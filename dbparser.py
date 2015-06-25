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
from amoco.db import Session

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
    s = Session(dbfilepath)

    while True:
        line = q_work.get()
        if line is None:
            break
        try:
            gadget = parse_one_line_rp(line)
            s.add(gadget._bytes, gadget)
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
        final_s = Session(zodb_final_path)
        while q_res.empty() == False:
            dbfilepath = q_res.get()
            s = Session(dbfilepath)
            for bytes, gadget in s.root.iteritems():
                final_s.add(bytes, gadget)
            s.commit()
            s.close()
            for suffix in ('', 'index', 'lock', 'tmp'):
                try:
                    os.remove('%s.%s' % (dbfilepath, suffix))
                except:
                    pass
    
    if final_s is None:
        final_s = Session(zodb_final_path)

    return final_s

def main(argc, argv):
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))