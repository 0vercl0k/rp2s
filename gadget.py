#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    gadget.py - XXX: put stuff here
#    Copyright (C) 2015 Axel "0vercl0k" Souchet - http://www.twitter.com/0vercl0k
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
import symexec
import utils
import operator

class Constraint(object):
    '''A constraint is basically a `src` that can be a register or a memory location,
    an operator & an equation.
    Note that you can also supply your own comparaison operator as soon as it takes two things in input & return a boolean.

    Here is an example:
        * src = esp, operator = '=', constraint = eax + 100
          - It basically means that you want that ESP = EAX + 100 at the end of the execution of the gadget

        * src = esp, operator = '<', constraint = esp + 100
          - It basically means that you want that ESP < ESP + 100 at the end of the execution of the gadget
    '''
    def __init__(self, src, constraint, op = operator.eq):
        self.src = src
        self.constraint = constraint
        self.operator = op

    def __eq__(self, b):
        if isinstance(b, Gadget):
            return utils.are_cpu_states_equivalent(
                [self], b._mapper
            )

        raise NotImplemented('Constraint.__eq__')

#XXX: ConstraintList

class Gadget(object):
    '''
    A gadget is a sequence of instructions that ends with a branch instruction.
    Every time you create a `Gadget`, it will be symbolically executed by Amoco's engine
    & the resulting symbolic CPU state will be stored for further analysis.

    Actually, we make more strong assumptions about a `Gadget` in order to have more accurate results:
        
        * In order to be able to chain `Gadget`s we need them to be chainable -- basically we need that EIP = [ESP + X] at
        the end of its execution with 0 <= X < cst.

    Also, a `Gadget` can have a set of `Primitive` associated; it describes which useful things a `Gadget` can do, in a more higher
    view than assembly.

    Each `Gadget` is also associated with a set of "classic" information:
        * `return_stackoffset`: it is basically at which offset you are supposed to place the next `Gadget` if you want to chain them
        * `preserved_registers`: the set of registers that is preserved after execution
    '''
    def __init__(self, bytes):
        self._bytes = bytes
        self._disassembly = utils.disassemble(self._bytes)
        self._mapper = symexec.sym_exec_gadget_and_get_mapper(self._bytes)
        self._primitives = []
        self._return_stackoffset = None

    def to_smtlib(self):
        return self._mapper.to_smtlib()

    def __getitem__(self, items):
        if isinstance(items, (list, tuple)):
            return [Constraint(item, self._mapper[item]) for item in items]

        return Constraint(items, self._mapper[items])

def main(argc, argv):
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))