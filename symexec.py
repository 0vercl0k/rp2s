#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    symexec.py - XXX: put stuff here plz
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

import amoco
import amoco.system.raw
import amoco.system.core
import amoco.cas.smt
import amoco.arch.x86.cpu_x86 as cpu

GPRs = [ cpu.eax, cpu.ebx, cpu.ecx, cpu.edx, cpu.esi, cpu.edi ]
GPRsEFL = GPRs + [ cpu.eflags ]

amoco.set_quiet()
# Disable aliasing -- mov [eax], ebx ; mov [ebx], 10; jmp [eax]
# Here we assume that eax & ebx are different. Without assume_no_aliasing, we would have eip <- M32$2(eax)
amoco.cas.mapper.mapper.assume_no_aliasing = True

def sym_exec_gadget_and_get_mapper(code, address_code = 0xdeadbeef):
    '''This function gives you a ``mapper`` object from assembled `code`. `code` will basically be
    our assembled gadgets.

    Note that `call`s will be neutralized in order to not mess-up the symbolic execution (otherwise the instruction just
    after the `call is considered as the instruction being jumped to).
    
    From this ``mapper`` object you can reconstruct the symbolic CPU state after the execution of your gadget.

    The CPU used is x86, but that may be changed really easily, so no biggie.'''
    p = amoco.system.raw.RawExec(
        amoco.system.core.DataIO(code), cpu
    )
    blocks = list(amoco.lsweep(p).iterblocks())
    assert(len(blocks) > 0)
    mp = amoco.cas.mapper.mapper()
    for block in blocks:
        # If the last instruction is a call, we need to "neutralize" its effect
        # in the final mapper, otherwise the mapper thinks the block after that one
        # is actually 'the inside' of the call, which is not the case with ROP gadgets
        if block.instr[-1].mnemonic.lower() == 'call':
            p.cpu.i_RET(None, block.map)
        mp >>= block.map
    return mp

def sym_exec_gadget_and_get_mappers_incremental(code, address_code = 0xdeadbeef):
    '''This function gives you a ``mapper`` object from assembled `code`. `code` will basically be
    our assembled gadgets.

    Note that `call`s will be neutralized in order to not mess-up the symbolic execution (otherwise the instruction just
    after the `call is considered as the instruction being jumped to).
    
    From this ``mapper`` object you can reconstruct the symbolic CPU state after the execution of your gadget.

    The CPU used is x86, but that may be changed really easily, so no biggie.'''
    p = amoco.system.raw.RawExec(
        amoco.system.core.DataIO(code), cpu
    )
    instrs = []
    bytes = code
    loc = cpu.cst(address_code, 32)
    while len(bytes) > 0:
        i = cpu.disassemble(bytes, address = loc)
        l = i.length
        instrs.append(i)
        bytes = bytes[l : ]
        loc += l

    mappers = [amoco.code.block(instrs[0 : i]).map for i in range(1, len(instrs))]
    # XXX: We need to do something about the potential calls in the chain as above
    return mappers

def main(argc, argv):
    
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))