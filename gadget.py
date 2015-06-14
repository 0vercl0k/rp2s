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
# XXX: this is ugly -- ideally we shouldn't need to import any amoco stuff in here
import amoco.arch.x86.cpu_x86 as cpu
from amoco.cas.expressions import *

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

#XXX: ConstraintList?? rly?

class Gadget(object):
    '''
    A gadget is a sequence of instructions that ends with a branch instruction.
    Every time you create a `Gadget`, it will be symbolically executed by Amoco's engine
    & the resulting symbolic CPU state will be stored for further analysis.

    Actually, we make more strong assumptions about a `Gadget` in order to have more accurate results:
        
        * In order to be able to chain `Gadget`s we need them to be chainable -- basically we need that EIP = [ESP + X] at
        the end of its execution with 0 <= X < cst. You can query the `_is_chainable` variable to have this info.

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
        self.preserved_registers = utils.get_preserved_gpr_from_mapper(self._mapper)
        self._primitives = []

        self._is_chainable, self._stackoffset_for_chaining = self._is_chainable_gadget()
        self._is_stackpivot, self._stackpivot_offset = self._is_stackpivot_gadget()
        self._is_strictly_clean = self._is_strictly_clean()

    def _is_chainable_gadget(self):
        '''Checking if EIP = [ESP + X]'''
        eip = self._mapper[cpu.eip]
        if eip._is_mem and eip.a.base._is_reg and eip.a.base.ref == 'esp' and 0 <= eip.a.disp < 0x100:
            return True, eip.a.disp
        return False, None

    def _is_stackpivot_gadget(self):
        '''We assume the gadget pivots the stack enough when ESP is ESP + X at the end with 0x100 <= X'''
        esp = self._mapper[cpu.esp]
        if isinstance(esp, op):
            if esp.l._is_reg and esp.l.ref == 'esp' and esp.r._is_cst and 0x100 <= esp.r.v:
                return True, esp.r.v

            if esp.r._is_reg and esp.r.ref == 'esp' and esp.l._is_cst and 0x100 <= esp.l.v:
                return True, esp.l.v

        return False, None

    def _is_strictly_clean(self):
        '''A clean gadget is a gadget that won't try to read/write to memory we can't control;
        I assume the memory controllable is [ESP + X] basically.

        The idea behind this function is to provide a reliable way to not have gadgets segfaulting in the middle
        of their executions while doing random memory access. Keeping them clean is another set of hard constraints for sure,
        but it should improve the accuracy of the information we give back to the user.'''
        # So, to do that properly we actually need both the symbolic state after every instructions & the one after the entire block
        # If we focus only the state after the block, we could have 'mov ebx, eax ; mov eax, [0xdeadbeef] ; mov eax, ebx' & we wouldn't
        # see the memory read happening just by looking at the state at the end of the block.
        
        # Thus the idea is to kind of mix both idea; let's focus on this example:
        #   'mov ebx, eax ; lea ecx, [esp + 10] ; mov eax, [ecx] ; mov eax, ebx'
        # If we have the mapper for every instruction, we are fine, we'll see the [ecx] dereference -- but now we have another problem;
        # How do I know if ECX is derived from ESP (& thus assumed controllable?)?
        # Soo, to get around this we won't generate a mapper for every instruction, but we will generate a mapper for 'mov ebx, eax', 'mov ebx, eax ; lea ecx, [esp + 10]',
        # 'mov ebx, eax ; lea ecx, [esp + 10] ; mov eax, [ecx]' & so on. This is exactly what symexec.sym_exec_gadget_and_get_mappers_incremental will do.
        for mapper in symexec.sym_exec_gadget_and_get_mappers_incremental(self._bytes):
            # In [6]: print m
            # ebx <- { | [0:32]->eax | }
            # ecx <- { | [0:32]->(esp+10) | }
            # eip <- { | [0:32]->(eip+0xa) | }
            # eax <- { | [0:32]->eax | }
            # In [7]: print m.outputs() <- this is the left part of the previous output (memory write)
            # [<amoco.cas.expressions.reg object at 0x03116AB0>, <amoco.cas.expressions.reg object at 0x03116AE0>,
            # <amoco.cas.expressions.reg object at 0x03116C00>, <amoco.cas.expressions.reg object at 0x03116A80>]
            # In [8]: print m.inputs() <- this is the right part (memory read)
            # [<amoco.cas.expressions.reg object at 0x03116A80>, <amoco.cas.expressions.ptr object at 0x0337D3F0>, <amoco.cas.expressi
            # ons.reg object at 0x03116C00>, <amoco.cas.expressions.reg object at 0x03116A80>]
            symbols = mapper.outputs() + mapper.inputs()
            
            # first step is to keep only memory operations
            memory_operations = filter(
                lambda x:x._is_mem,
                symbols
            )

            if len(memory_operations) == 0:
                # we are fine, we can continue
                continue

            # second step is to identify the controllable memory locations from the one you don't
            # we don't handle conditional jumps in gadget that could make a memory location conditional as:
            #    mov eax, [esp] ; test eax, eax ; jz foo; mov eax, [esp + 4] ; foo: mov eax, [0xdeadbeef]
            # According to the value pointed by ESP, we can either read again from a derived location from ESP, or from 0xdeadbeef
            # In [24]: m = symexec.sym_exec_gadget_and_get_mapper('\x8b\x04\x24\x85\xc0\x74\x04\x8b\x44\x24\x04')
            # In [25]: print m
            # eip <- { | [0:32]->(((M32(esp)==0x0) ? (eip+0xb) : (eip+0x7))+0x4) | }
            # XXX: May investigate why that is -> eax <- { | [0:32]->M32(esp+4) | }
            for memory_operation in memory_operations:
                inner_expr = memory_operation.a
                while True:
                    if isinstance(inner_expr, ptr):
                        # We need to go deeper to do the check
                        inner_expr = inner_expr.base
                    elif isinstance(inner_expr, mem):
                        inner_expr = inner_expr.a
                    else:
                        if not (isinstance(inner_expr, reg) and inner_expr.ref == 'esp'):
                            return False
                        # We're done!
                        break

        return True

    def to_smtlib(self):
        return self._mapper.to_smtlib()

    def __getitem__(self, items):
        if isinstance(items, (list, tuple)):
            return [Constraint(item, self._mapper[item]) for item in items]

        return Constraint(items, self._mapper[items])

    def __str__(self):
        s = []
        s.append('Gadget: %s; %s' % (self._disassembly, repr(self._bytes)[ : 40]))
        s.append('  -> Preserved registers: %s' % ', '.join(map(str, self.preserved_registers)))
        s.append('  -> Strictly clean: %s' % self._is_strictly_clean)
        s.append('  -> Chainable from stack? %s' % self._is_chainable)
        if self._is_chainable:
            s.append('    -> Stack-offset to chain: %s' % self._stackoffset_for_chaining)
        s.append('  -> Enough to pivot the stack? %s' % self._is_stackpivot)
        if self._is_stackpivot:
            s.append('    -> %s bytes pivot' % self._stackpivot_offset)
        return '\n'.join(s)

    def __key(self):
        return self._bytes

    def __eq__(self, y):
        return self.__key() == y.__key()

    def __hash__(self):
        return hash(self.__key())

def main(argc, argv):
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
