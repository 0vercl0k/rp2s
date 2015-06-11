#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    symexec.py - Those are regression tests for Amoco's x86 symbolic-execution engine
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
import gadget
import utils
import unittest
import amoco
import amoco.arch.x86.cpu_x86 as cpu
from amoco.cas.expressions import *

class TestSymbolicExecutionEngine(unittest.TestCase):
    '''Those tests aim at both testing the symbolic execution engine & the rp2s proving capabilities.

        Basically, the idea is to take a sequence of instructions as reference & prove that others will
        end up in the same CPU state.

        The idea is to try every different "kind" of assembly operations: arithmetic, assignation, memory read,
        memory write, etc.'''

    def test_arith_assignation(self):
        '''This one focuses arithmetic assembly operations & what I call "assignations" (moving registers from one to another, etc.).\n'''
        disass_target, gadget_target = 'mov eax, ebx ; ret 4', '\x89\xd8\xc2\x04\x00'
        # We generate the mapper for the final state we want to reach
        # In that state we may be interested in only one or two registers ; whatever, you extract what you want from it
        target_gadget = gadget.Gadget(gadget_target)
        
        # We pick the registers (& their amoco expressions) we are interested in inside the final ``mapper``
        cpu_state_end_target_eax = target_gadget[cpu.eax]

        # Thanks Dad`! -- http://aurelien.wail.ly/nrop/demos/
        candidates = {
            'add byte ptr [eax], al ; add byte ptr [edi], cl ; add eax, 0xc3d88948 ; xchg ebx, eax ; ret' : '\x00\x00\x00\x0f\x05\x48\x89\xd8\xc3\x87\xd8\xc3',
            'add byte ptr [edi], cl ; add eax, 0xc3d88948 ; xchg ebx, eax ; ret' : '\x00\x0f\x05\x48\x89\xd8\xc3\x87\xd8\xc3',
            'xchg ebx, eax ; pop edi ; pop edi ; ret' : '\x87\xd8\x5f\x5f\xc3',
            'mov eax, ebx ; shl eax, 32 ; ret' : '\x89\xd8\xc1\xe0\x20\xc3',
            'mov eax, ebx ; rol eax, 32 ; ret' : '\x89\xd8\xc1\xc0\x20\xc3',
        }

        for disass, code in candidates.iteritems():
            cpu_state_end_candidate = gadget.Gadget(code)
            self.assertEqual(
                cpu_state_end_target_eax,
                cpu_state_end_candidate
            )
            print ' > "%s" == "%s"' % (disass_target, disass)

        cpu_state_end_target_eax_esp = target_gadget[cpu.eax, cpu.esp]

        # Conservation of ESP (or not in this case)
        disass_gadget = 'xchg ebx, eax ; pop edi ; pop edi ; ret'
        gadget_code = candidates[disass_gadget]
        self.assertFalse(
            utils.are_cpu_states_equivalent(
                cpu_state_end_target_eax_esp,
                gadget.Gadget(gadget_code)
            )
        )

        print ' > "%s" != "%s"' % (disass_target, disass_gadget)
        csts_eax, csts_esp = cpu_state_end_target_eax_esp
        print '  > %r VS %r' % (
            csts_esp.constraint.to_smtlib(),
            gadget.Gadget(gadget_code)._mapper[cpu.esp].to_smtlib()
        )

        disass_target, gadget_target = 'mov eax, 0x1234 ; ret', '\xb8\x34\x12\x00\x00\xc3'
        disass, gadget_code = 'mov edx, 0xffffedcc ; xor eax, eax ; sub eax, edx ; ret', '\xba\xcc\xed\xff\xff\x31\xc0\x29\xd0\xc3'
        target_gadget = gadget.Gadget(gadget_target)

        cpu_state_end_target_eax = target_gadget[cpu.eax]
        self.assertTrue(
            utils.are_cpu_states_equivalent(
                cpu_state_end_target_eax,
                gadget.Gadget(gadget_code)
            )
        )
        print ' > "%s" == "%s"' % (disass_target, disass)

    def test_memory_read_write(self):
        '''This one is going to focus more on memory read/write operations
        '''
        disass_target, gadget_target = 'mov eax, 0x1234 ; ret', '\xb8\x34\x12\x00\x00\xc3'
        target_gadget = gadget.Gadget(gadget_target)._mapper
        cpu_state_end_target_eax = utils.extract_things_from_mapper_eq(target_gadget, cpu.eax)

        candidates = {
            'push 0xffffedcc ; pop edx ; xor eax, eax ; sub eax, edx ; ret' : '\x68\xcc\xed\xff\xff\x5a\x31\xc0\x29\xd0\xc3',
            'mov [eax], 0x1234 ; mov ebx, [eax] ; xchg eax, ebx ; ret' : '\xc7\x00\x34\x12\x00\x00\x8b\x18\x93\xc3'
        }

        for disass, code in candidates.iteritems():
            cpu_state_end_candidate = gadget.Gadget(code)
            self.assertTrue(
                utils.are_cpu_states_equivalent(
                    cpu_state_end_target_eax,
                    cpu_state_end_candidate
                )
            )
            print ' > "%s" == "%s"' % (disass_target, disass)

        cpu_state_end_target_esp = gadget.Constraint(cpu.esp, mem(cpu.ebp, 32) + 8)
        candidates = {
            # https://twitter.com/NicoEconomou/status/527555631017107456 -- thanks @NicoEconomou! 
            'leave ; setl cl ; mov eax, ecx ; pop edi ; pop ebx ; pop esi ; leave ; ret' : '\xc9\x0f\x9c\xc1\x89\xc8\x5f\x5b\x5e\xc9\xc3',
        }
        for disass, code in candidates.iteritems():
            cpu_state_end_candidate = gadget.Gadget(code)
            self.assertTrue(
                utils.are_cpu_states_equivalent(
                    cpu_state_end_target_esp,
                    cpu_state_end_candidate
                )
            )
            print ' > "%s" == "%s"' % (disass_target, disass)

        disass_target, gadget_target = 'add [eax], 4 ; ret', '\x83\x00\x04\xc3'
        target_gadget = gadget.Gadget(gadget_target)._mapper
        cpu_state_end_target_mem_eax = utils.extract_things_from_mapper_eq(target_gadget, mem(cpu.eax, 32))
        candidates = {
            'inc [eax] ; mov ebx, eax ; push ebx ; mov esi, [esp] ; add [esi], 3 ; mov ebx, [esi] ; mov [eax], ebx ; ret' : '\xff\x00\x89\xc3\x53\x8b\x34\x24\x83\x06\x03\x8b\x1e\x89\x18\xc3',
            'inc [eax] ; push eax ; mov esi, [esp] ; add [esi], 3 ; mov ebx, [esi] ; mov [eax], ebx ; ret' : '\xff\x00\x50\x8b\x34\x24\x83\x06\x03\x8b\x1e\x89\x18\xc3',
        }

        for disass, code in candidates.iteritems():
            cpu_state_end_candidate = gadget.Gadget(code)
            self.assertTrue(
                utils.are_cpu_states_equivalent(
                    cpu_state_end_target_mem_eax,
                    cpu_state_end_candidate
                )
            )
            print ' > "%s" == "%s"' % (disass_target, disass)

        disass_target = 'EIP = [ESP + 0x24]'
        cpu_state_end_target_eip = gadget.Constraint(cpu.eip, mem(cpu.esp + 0x24, 32))
        candidates = {
            'add esp, 0x24 ; ret' : '\x83\xc4\x24\xc3'
        }

        for disass, code in candidates.iteritems():
            cpu_state_end_candidate = gadget.Gadget(code)
            self.assertTrue(
                utils.are_cpu_states_equivalent(
                    cpu_state_end_target_eip,
                    cpu_state_end_candidate
                )
            )
            print ' > "%s" == "%s"' % (disass_target, disass)

        disass_target = 'ESP = [ESP + 0x24]'
        cpu_state_end_target_esp = gadget.Constraint(cpu.esp, mem(cpu.esp + 0x24, 32))
        candidates = {
            'add esp, 0x24 ; mov esp, [esp]' : '\x83\xc4\x24\x8b\x24\x24'
        }

        for disass, code in candidates.iteritems():
            cpu_state_end_candidate = gadget.Gadget(code)
            print '  >', cpu_state_end_candidate[cpu.esp], 'VS', cpu_state_end_target_esp.constraint
            self.assertTrue(
                utils.are_cpu_states_equivalent(
                    cpu_state_end_target_esp,
                    cpu_state_end_candidate
                )
            )
            print ' > "%s" == "%s"' % (disass_target, disass)

    def test_inequation(self):
        pass

    def test_preserved_registers(self):
        pass

    def test_is_gadget_PN1_valid(self):
        pass
        # assembly_store = {
        #     'mov ecx, eax ; pop eax; rdtsc ; ret' : '\x89\xc1\x58\x0f\x31\xc3',
        # }

        # # simple PN1
        # r = is_gadget_PN1_valid(Gadget(assembly_store['mov ecx, eax ; pop eax; rdtsc ; ret']))
        # assert len(r) == 1
        # r = r[0]
        # assert r.src == 'eax' and r.dst == 'ecx' and [cpu.ecx]

    def test_is_gadget_PN2_valid(self):
        pass

def main(argc, argv):
    unittest.main(verbosity = 2)
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))