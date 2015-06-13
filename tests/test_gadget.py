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
        self.assertFalse(gadget.Gadget(gadget_code)._is_strictly_clean)
        print '>', gadget_disass, 'is not stricly clean'

        # positive test: obvious esp memory write
        gadget_code, gadget_disass = '\x54\xc3', 'push esp ; ret'
        self.assertTrue(gadget.Gadget(gadget_code)._is_strictly_clean)
        print '>', gadget_disass, 'is stricly clean'

        # obvious memory write
        gadget_code, gadget_disass = '\xa3\xef\xbe\xad\xde\xc3', 'mov [0xdeadbeef], eax ; ret'
        self.assertFalse(gadget.Gadget(gadget_code)._is_strictly_clean)
        print '>', gadget_disass, 'is not stricly clean'
        gadget_code, gadget_disass = '\xa3\xef\xbe\xad\xde\xc3', 'mov eax, 0x31337 ; mov [eax], ebx ; ret'
        self.assertFalse(gadget.Gadget(gadget_code)._is_strictly_clean)
        print '>', gadget_disass, 'is not stricly clean'


        gadget_code, gadget_disass = '\x8d\x44\x24\x0a\x89\xc3\x89\x0b\xc3', 'lea eax, [esp + 10] ; mov ebx, eax ; mov [ebx], ecx ; ret'
        self.assertTrue(gadget.Gadget(gadget_code)._is_strictly_clean)
        print '>', gadget_disass, 'is strictly clean'
        gadget_code, gadget_disass = '\x8d\x44\x24\x0a\x89\xc3\x8b\x0b\x8b\x09\xc3', 'lea eax, [esp + 10] ; mov ebx, eax ; mov ecx, [ebx] ; mov ecx, [ecx] ; ret'
        self.assertTrue(gadget.Gadget(gadget_code)._is_strictly_clean)
        print '>', gadget_disass, 'is strictly clean'


        # obvious memory read write

        # obvious memory write read
        # 'hidden' memory read
        gadget_code, gadget_disass = '\x8b\x18\xbb\x01\x00\x00\x00\xc3', 'mov ebx, [eax] ; mov ebx, 1 ; ret'
        self.assertFalse(gadget.Gadget(gadget_code)._is_strictly_clean)
        print '>', gadget_disass, 'is not strictly clean'

        # 'hidden' memory read write

        # tests with strict sequences

def main(argc, argv):
    unittest.main(verbosity = 2)
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))