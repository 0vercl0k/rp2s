#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    gadget.py - XXX: stuffz
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
import unittest
import gadget

class TestGadget(unittest.TestCase):
    def test_strict_cleaness(self):
        # negative test: obvious memory read
        gadget_code, gadget_disass = '\xa1\xef\xbe\xea\x0d\x50\xc3', 'mov eax, [0xdeabeef] ; push eax ; ret'
        self.assertFalse(gadget.Gadget(gadget_code)._is_stricly_clean)
        print '>', gadget_disass, 'is not stricly clean'

        # positive test: obvious esp memory read
        gadget_code, gadget_disass = '\x54\xc3', 'push esp ; ret'
        self.assertTrue(gadget.Gadget(gadget_code)._is_stricly_clean)
        print '>', gadget_disass, 'is stricly clean'

        # obvious memory write
        # ovious memory read write
        # obvious memory write read
        # 'hidden' memory read
        # 'hidden' memory read write

        # tests with strict sequences

def main(argc, argv):
    unittest.main(verbosity = 2)
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))