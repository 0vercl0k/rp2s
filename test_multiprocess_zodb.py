#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    script_title.py - script_title script abstract
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
import ZODB
import gadget
import dbparser
import multiprocessing
import time
import traceback
import os
from amoco.db import Session

def consumer_worker(q_work, q_res, filepath):
    head, tail = os.path.split(filepath)
    dbname = '%s-%s.temp.zodb' % (tail, multiprocessing.current_process().name)
    dbfilepath = os.path.join(head, dbname)
    s = Session(dbfilepath)

    while True:
        line = q_work.get()
        if line is None:
            break
        try:
            gadget = dbparser.parse_one_line_rp(line)
            s.add(gadget._bytes, gadget)
            s.commit()
        except Exception, e:
            print '<consumer_worker>'.center(60, '-')
            traceback.print_exc(file = sys.stdout)
            print '</consumer_worker>'.center(60, '-')

    q_res.put(dbfilepath)

def create_zodb_database_with_workers(filepath):
    t1 = time.time()
    q_work = multiprocessing.Queue()
    q_res = multiprocessing.Queue()
    workers = [ multiprocessing.Process(target = consumer_worker, args = (q_work, q_res, filepath)) for _ in range(multiprocessing.cpu_count()) ]
    for worker in workers:
        worker.start()

    with open(filepath, 'r') as f:
        for line in f.readlines():
            q_work.put(line)

    q_work.close()
    q_work.join_thread()

    for worker in workers:
        worker.join()

    t2 = time.time()
    print 'First step done in', t2 - t1
    while q_res.empty() == False:
        dbfilepath = q_res.get()
        print '> Opening', dbfilepath
        print '> Done with', dbfilepath

def main(argc, argv):
    create_zodb_database_with_workers(r'D:\Codes\rp2s\libc_gadgets.txt')
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
