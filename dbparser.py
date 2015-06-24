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
                traceback.print_exc(file=sys.stdout)
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

def main(argc, argv):
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))