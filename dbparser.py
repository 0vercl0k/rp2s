#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    dbparser.py - XXX: stuffz here
#    Copyright (C) 2013 Axel "0vercl0k" Souchet - http://www.twitter.com/0vercl0k
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import gadget
import traceback
import multiprocessing
import os
import transaction
from amoco.code import mapper, block
from amoco.cas.expressions import exp
from amoco.db import db_interface
from ZODB import DB, FileStorage
from persistent import Persistent

class ZODBGadgetDatabase(object):
    def __init__(self, filename):
        self.storage = FileStorage.FileStorage(filename)
        self.db = DB(self.storage)
        self.conn = self.db.open()
        self.root = self.conn.root()

    def add(self, key, obj):
        assert isinstance(obj, dict)
        x = obj
        for key, value in x.iteritems():
            if isinstance(value, (block, mapper, exp)):
                # replace it with its serializable version
                x[key] = db_interface(value)

        self.root[key] = x

    def commit(self):
        transaction.commit()

    def get(self, key):
        r = self.root[key]
        if isinstance(r, dict):
            r = gadget.Gadget(
                r['bytes'], r['mapper'].build(), r['is_strictly_clean']
            )
        return r

    def __len__(self):
        return len(self.root.keys())

    def __iter__(self):
        for k, _ in self.root.iteritems():
            yield self.get(k)
        raise StopIteration

    def close(self):
        self.conn.close()
        self.db.close()
        self.storage.close()

class GadgetDbParser(object):
    def __init__(self, filepath):
        self.filepath = filepath

    def __iter__(self):
        raise NotImplementedError('Inherit & implement it yourself')

def parse_one_line_rp(line):
    if ' ;  ' not in line:
        return None
    _, second_part = line.split(' ;  ')
    bytes, _ = second_part.split(' (')
    return gadget.Gadget(bytes.decode('string_escape'))

def get_gadgets_from_file_rp(filepath):
    with open(filepath, 'r') as f:
        for line in f.readlines():
            try:
                l = parse_one_line_rp(line)
                if l:
                    yield l 
            except Exception, e:
                print '<get_gadgets_from_file_rp>'.center(60, '-')
                traceback.print_exc(file = sys.stdout)
                print '</get_gadgets_from_file_rp>'.center(60, '-')

    raise StopIteration()

class Rp(GadgetDbParser):
    def __init__(self, filepath):
        GadgetDbParser.__init__(self, filepath)
        self.it = get_gadgets_from_file_rp(self.filepath)

    def __iter__(self):
        return self

    def next(self):
        return self.it.next()

def consumer_worker_rp(q_work, q_res, filepath):
    head, tail = os.path.split(filepath)
    dbname = '%s-%s.temp.zodb' % (tail, multiprocessing.current_process().name)
    dbfilepath = os.path.join(head, dbname)
    s = ZODBGadgetDatabase(dbfilepath)

    while True:
        line = q_work.get()
        if line is None:
            break
        try:
            gadget = parse_one_line_rp(line)
            s.add(
                gadget._bytes, 
                {
                    'bytes' : gadget._bytes,
                    'mapper' : gadget._mapper,
                    'is_strictly_clean' : gadget._is_strictly_clean
                }
            )
        except Exception, e:
            print '<consumer_worker_rp>'.center(60, '-')
            traceback.print_exc(file = sys.stdout)
            print '</consumer_worker_rp>'.center(60, '-')
    s.commit()
    s.close()
    q_res.put(dbfilepath)

def get_zodb_session_from_rp_database_with_workers(filepath, nworkers):
    head, tail = os.path.split(filepath)
    zodb_final_path = os.path.join(head, '%s.zodb' % tail)
    final_s = None
    if os.path.isfile(zodb_final_path) == False:
        # We need to create everything, let's go!
        q_work = multiprocessing.Queue()
        q_res = multiprocessing.Queue()
        workers = [
            multiprocessing.Process(
                target = consumer_worker_rp,
                args = (q_work, q_res, filepath))
            for _ in range(nworkers)
        ]

        for worker in workers:
            worker.start()

        with open(filepath, 'r') as f:
            for line in f.readlines():
                q_work.put(line)

        for _ in workers:
            q_work.put(None)

        q_work.close()
        q_work.join_thread()

        for worker in workers:
            worker.join()

        # Now we need to merge them
        final_s = ZODBGadgetDatabase(zodb_final_path)
        while q_res.empty() == False:
            dbfilepath = q_res.get()
            s = ZODBGadgetDatabase(dbfilepath)
            for bytes, gadget in s:
                print type(gadget)
                final_s.add(bytes, gadget)
            final_s.commit()
            s.close()
            for suffix in ('', 'index', 'lock', 'tmp'):
                try:
                    os.remove('%s.%s' % (dbfilepath, suffix))
                except:
                    pass
    
    if final_s is None:
        final_s = ZODBGadgetDatabase(zodb_final_path)

    return final_s

def main(argc, argv):
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))