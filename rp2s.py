#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    rp2s.py - 
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

'''Show case
# Example with several constraints: "I want EAX = EBX = 0 at the end of the gadget execution":
# xor eax, eax ; push eax ; mov ebx, eax ; ret
# xor eax, eax ; xor ebx, ebx ; ret
# xor ebx, ebx ; mov eax, ebx ; push esi ; call  [0x10A1587C]
# [...]
# push 0x00000000 ; call  [0x10A15B98] ; pop edi ; pop ebx ; xor eax, eax ; retn 0x0008 # TODO: Check what's going on here

# Find a way to pivot code execution to the stack: "I want EIP = ESP at the end of the gadget execution":
# add dword ptr [ebx], 2 ; push esp ; ret 
# jmp esp
# pushad ; mov eax, 0xffffffff ; pop ebx ; pop esi ; pop edi ; ret
# [...]

# Find a way to move the stack by at least 1000 bytes: "I want ((ESP >= ESP + 1000) && (ESP < ESP + 2000))"
# add esp, 0x47c ; fldz ; pop ebx ; fchs ; pop esi ; pop edi ; pop ebp ; ret
# ret 0x3ff
# ret 0x78b
# ret 0x789
# xor eax, eax ; add esp, 0x45c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret

# Find a way to move the stack by at least 1000 bytes & set EAX to 0: "I want ((ESP >= ESP + 1000) && (ESP < ESP + 2000)) && (EAX == 0)"
# xor eax, eax ; add esp, 0x45c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
'''

import sys
import operator
import amoco
import amoco.system.raw
import amoco.system.core
import amoco.cas.smt
import amoco.arch.x86.cpu_x86 as cpu
import amoco.db
import argparse
import multiprocessing
import time
import traceback
import cPickle

from collections import namedtuple
from z3 import *
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

def prove_(f):
    '''Taken from http://rise4fun.com/Z3Py/tutorialcontent/guide#h26'''
    s = Solver()
    s.add(Not(f))
    if s.check() == unsat:
        return True
    return False

def get_preserved_gpr_from_mapper(mapper):
    '''Returns a list with the preserved registers in `mapper`'''
    # XXX: Is there a way to get that directly from `cpu` without knowing the architecture?
    gpr = [ cpu.eax, cpu.ebx, cpu.ecx, cpu.edx, cpu.esi, cpu.edi, cpu.ebp, cpu.esp, cpu.eip, cpu.eflags ]
    return filter(lambda reg: prove_(mapper[reg].to_smtlib() == reg.to_smtlib()), gpr)

def get_preserved_gpr_from_mapper_str(mapper):
    '''Returns a clean string instead of a list of expressions'''
    preserved_gprs = get_preserved_gpr_from_mapper(mapper)
    return ', '.join(r.ref for r in preserved_gprs)

def are_cpu_states_equivalent(target, candidate):
    '''This function tries to compare a set of constraints & a symbolic CPU state. The idea
    is simple:
        * `target` is basically a list of `constraints`
        * `candidate` is a `mapper` instance

    Every constraints inside target are going to be checked against the mapper `candidate`,
    if they are all satisfied, it returns True, else False.'''
    valid = True
    for constraint in target:
        reg, exp, op = constraint.src, constraint.constraint, constraint.operator
        if op in (operator.gt, operator.ge, operator.lt, operator.le):
            # little trick here
            #   In [42]: from z3 import *
            #   In [43]: a, b = BitVecs('a b', 32)
            #   In [44]: prove(UGT((a + 10), (a+3)))
            #    counterexample
            #    [a = 4294967287] :((((
            #   In [65]: prove(((a+10)-(a+3)) > 0)
            #    proved - yay!
            valid = prove_(op(0, exp.to_smtlib() - candidate[reg].to_smtlib()))
        else:
            valid = prove_(op(exp.to_smtlib(), candidate[reg].to_smtlib()))

        if valid == False:
            break

    return valid

def extract_things_from_mapper(mapper, op, *things):
    '''Extracts whatever you want from a mapper & build a Constraint instance so that you can directly feed
    those ones in `are_cpu_states_equivalent`.'''
    return [ Constraint(thing, mapper[thing], op) for thing in things ]

def extract_things_from_mapper_eq(mapper, *things):
    return extract_things_from_mapper(mapper, operator.eq, *things)

def extract_mems_from_mapper(mapper):
    '''Extract every ``mem`` state available in a ``mapper``. It is particularly
    useful if you want to analyze what kind of operation against memory a ``mapper``
    does'''
    mem = []
    for location, content in mapper:
        if isinstance(location, (amoco.cas.expressions.ptr, amoco.cas.expressions.mem)):
            mem.append((location, content))
    return mem

# def extract_write4_what_where_from_mapper(mapper):
#     '''The idea here is to find in a ``mapper`` if you can write 4 arbitrary bytes at an
#     arbitrary location. If it is possible, it tells you where you have to stick the ``where`` pointer and
#     the ``what`` value. We assume you have control over the stack, but we will discard hardcoded location
#     because you most likely want to write wherever you want.'''
#     mem = extract_mems_from_mapper(mapper)
#     for location, content in mem:
#         where = None
#         # First we check where the write is happening
#         if isinstance(location, amoco.cas.expressions.ptr):
#             if isinstance(location.base


def test_arith_assignation():
    print 'Arithmetic/Assignation tests'.center(100, '=')
    disass_target, gadget_target = 'mov eax, ebx ; ret 4', '\x89\xd8\xc2\x04\x00'
    
    # We generate the mapper for the final state we want to reach
    # In that state we may be interested in only one or two registers ; whatever, you extract what you want from it
    target_mapper = sym_exec_gadget_and_get_mapper(gadget_target)
    
    # We pick the registers (& their amoco expressions) we are interested in inside the final ``mapper``
    cpu_state_end_target_eax = extract_things_from_mapper_eq(target_mapper, cpu.eax)

    # Thanks Dad`! -- http://aurelien.wail.ly/nrop/demos/
    candidates = {
        'add byte ptr [eax], al ; add byte ptr [edi], cl ; add eax, 0xc3d88948 ; xchg ebx, eax ; ret' : '\x00\x00\x00\x0f\x05\x48\x89\xd8\xc3\x87\xd8\xc3',
        'add byte ptr [edi], cl ; add eax, 0xc3d88948 ; xchg ebx, eax ; ret' : '\x00\x0f\x05\x48\x89\xd8\xc3\x87\xd8\xc3',
        # TODO: Implement fadd
        'fadd st0, st3 ; xchg ebx, eax ; pop edi ; pop edi ; ret' : '\xd8\xc3\x87\xd8\x5f\x5f\xc3',
        'mov eax, ebx ; shl eax, 32 ; ret' : '\x89\xd8\xc1\xe0\x20\xc3',
        'mov eax, ebx ; rol eax, 32 ; ret' : '\x89\xd8\xc1\xc0\x20\xc3',
    }

    for disass, code in candidates.iteritems():
        cpu_state_end_candidate = sym_exec_gadget_and_get_mapper(code)
        assert(are_cpu_states_equivalent(cpu_state_end_target_eax, cpu_state_end_candidate) == True)
        print ' > "%s" == "%s"' % (disass_target, disass)

    cpu_state_end_target_eax_esp = extract_things_from_mapper_eq(target_mapper, cpu.eax, cpu.esp)

    # Conservation of ESP (or not in this case)
    gadget = 'fadd st0, st3 ; xchg ebx, eax ; pop edi ; pop edi ; ret'
    gadget_code = candidates[gadget]
    assert(
        are_cpu_states_equivalent(
            cpu_state_end_target_eax_esp,
            sym_exec_gadget_and_get_mapper(gadget_code)
        ) == False
    )

    print ' > "%s" != "%s"' % (disass_target, gadget)
    csts_eax, csts_esp = cpu_state_end_target_eax_esp
    print '  > %r VS %r' % (
        csts_esp.constraint.to_smtlib(),
        sym_exec_gadget_and_get_mapper(gadget_code)[cpu.esp].to_smtlib()
    )

    disass_target, gadget_target = 'mov eax, 0x1234 ; ret', '\xb8\x34\x12\x00\x00\xc3'
    disass, gadget = 'mov edx, 0xffffedcc ; xor eax, eax ; sub eax, edx ; ret', '\xba\xcc\xed\xff\xff\x31\xc0\x29\xd0\xc3'
    target_mapper = sym_exec_gadget_and_get_mapper(gadget_target)

    cpu_state_end_target_eax = extract_things_from_mapper_eq(target_mapper, mem(cpu.eax))
    assert(are_cpu_states_equivalent(cpu_state_end_target_eax, sym_exec_gadget_and_get_mapper(gadget)) == True)
    print ' > "%s" == "%s"' % (disass_target, disass)

def test_memory_stuff():
    print 'Memory store / read tests:'.center(100, '=')
    disass_target, gadget_target = 'mov eax, 0x1234 ; ret', '\xb8\x34\x12\x00\x00\xc3'
    target_mapper = sym_exec_gadget_and_get_mapper(gadget_target)
    cpu_state_end_target_eax = extract_things_from_mapper_eq(target_mapper, cpu.eax)

    candidates = {
        'push 0xffffedcc ; pop edx ; xor eax, eax ; sub eax, edx ; ret' : '\x68\xcc\xed\xff\xff\x5a\x31\xc0\x29\xd0\xc3',
        'mov [eax], 0x1234 ; mov ebx, [eax] ; xchg eax, ebx ; ret' : '\xc7\x00\x34\x12\x00\x00\x8b\x18\x93\xc3'
    }

    for disass, code in candidates.iteritems():
        cpu_state_end_candidate = sym_exec_gadget_and_get_mapper(code)
        assert(are_cpu_states_equivalent(cpu_state_end_target_eax, cpu_state_end_candidate) == True)
        print ' > "%s" == "%s"' % (disass_target, disass)

    cpu_state_end_target_esp = [ Constraint(cpu.esp, mem(cpu.ebp, 32) + 8) ]
    candidates = {
        # https://twitter.com/NicoEconomou/status/527555631017107456 -- thanks @NicoEconomou! 
        'leave ; setl cl ; mov eax, ecx ; pop edi ; pop ebx ; pop esi ; leave ; ret' : '\xc9\x0f\x9c\xc1\x89\xc8\x5f\x5b\x5e\xc9\xc3',
    }
    for disass, code in candidates.iteritems():
        cpu_state_end_candidate = sym_exec_gadget_and_get_mapper(code)
        assert(are_cpu_states_equivalent(cpu_state_end_target_esp, cpu_state_end_candidate) == True)
        print ' > "%s" == "%s"' % (disass_target, disass)

    disass_target, gadget_target = 'add [eax], 4 ; ret', '\x83\x00\x04\xc3'
    target_mapper = sym_exec_gadget_and_get_mapper(gadget_target)
    cpu_state_end_target_mem_eax = extract_things_from_mapper_eq(target_mapper, mem(cpu.eax, 32))
    candidates = {
        'inc [eax] ; mov ebx, eax ; push ebx ; mov esi, [esp] ; add [esi], 3 ; mov ebx, [esi] ; mov [eax], ebx ; ret' : '\xff\x00\x89\xc3\x53\x8b\x34\x24\x83\x06\x03\x8b\x1e\x89\x18\xc3',
        'inc [eax] ; push eax ; mov esi, [esp] ; add [esi], 3 ; mov ebx, [esi] ; mov [eax], ebx ; ret' : '\xff\x00\x50\x8b\x34\x24\x83\x06\x03\x8b\x1e\x89\x18\xc3',
    }

    for disass, code in candidates.iteritems():
        cpu_state_end_candidate = sym_exec_gadget_and_get_mapper(code)
        assert(are_cpu_states_equivalent(cpu_state_end_target_mem_eax, cpu_state_end_candidate) == True)
        print ' > "%s" == "%s"' % (disass_target, disass)

    disass_target = 'EIP = [ESP + 0x24]'
    cpu_state_end_target_eip = [ Constraint(cpu.eip, mem(cpu.esp + 0x24, 32)) ]
    candidates = {
        'add esp, 0x24 ; ret' : '\x83\xc4\x24\xc3'
    }

    for disass, code in candidates.iteritems():
        cpu_state_end_candidate = sym_exec_gadget_and_get_mapper(code)
        assert(are_cpu_states_equivalent(cpu_state_end_target_eip, cpu_state_end_candidate) == True)
        print ' > "%s" == "%s"' % (disass_target, disass)

    disass_target = 'ESP = [ESP + 0x24]'
    cpu_state_end_target_esp = [ Constraint(cpu.esp, mem(cpu.esp + 0x24, 32)) ]
    candidates = {
        'add esp, 0x24 ; mov esp, [esp]' : '\x83\xc4\x24\x8b\x24\x24'
    }

    for disass, code in candidates.iteritems():
        cpu_state_end_candidate = sym_exec_gadget_and_get_mapper(code)
        print '  >', cpu_state_end_candidate[cpu.esp], 'VS', cpu_state_end_target_esp[0].constraint
        assert(are_cpu_states_equivalent(cpu_state_end_target_esp, cpu_state_end_candidate) == True)
        print ' > "%s" == "%s"' % (disass_target, disass)

def test_inequation():
    pass

def test_preserved_registers():
    pass

def testing():
    test_arith_assignation()
    test_memory_stuff()
    test_inequation()
    test_preserved_registers()

def disassemble(bytes):
    p = amoco.system.raw.RawExec(
        amoco.system.core.DataIO(bytes), cpu
    )
    blocks = list(amoco.lsweep(p).iterblocks())
    s = []
    for block in blocks:
        for i in block.instr:
            s.append(' '.join(i.formatter(i).split()))

    return ' ; '.join(s).lower()

class Gadget(object):
    def __init__(self, bytes, mapper = None):
        self.bytes = bytes
        self._mapper = mapper
        self.state = 'npickable'
        if self._mapper is None:
            self.state = 'pickable'
            self._mapper = amoco.db.db_mapper(sym_exec_gadget_and_get_mapper(self.bytes))

    @property
    def mapper(self):
        if self._mapper is None:
            self._mapper = sym_exec_gadget_and_get_mapper(self.bytes)
            if self.state == 'npickable':
                self.state = 'pickable'
                self._mapper = amoco.db.db_mapper(self._mapper)
        return self._mapper

    @property
    def disassembly(self):
        disassembly(self.bytes)

    def serialize(self, f):
        cPickle.dump(self.bytes, f)
        cPickle.dump(self.mapper, f)

    @staticmethod
    def unserialize(f):
        bytes = cPickle.load(f)
        mapper = cPickle.load(f).build()
        return Gadget(bytes, mapper)

class HandleLineFromFile(object):
    def __init__(self, g_dict, maxtuples):
        self.g_dict = g_dict
        self.maxtuples = maxtuples

    def __call__(self, line):
        if (self.maxtuples != 0 and len(self.g_dict) == self.maxtuples) or ' ;  ' not in line:
            print 'wat', line
            return

        first_part, second_part = line.split(' ;  ')
        _, disass = first_part.split(':', 1)
        bytes, _ = second_part.split(' (')
        
        if bytes in self.g_dict:
            return

        try:
            self.g_dict[bytes] = Gadget(bytes.decode('string_escape'))
        except Exception, e:
            print '>>> Skipped: %r %r' % (bytes, str(e))

def build_candidates(manager, f, nprocesses, maxtuples = 0):
    '''Gets all the gadgets (both assembly & disassembly) from `f` & return them'''
    # XXX: Do not store both disassembly AND bytes; amoco is able to disassemble, so let's keep the bytes
    candidates = manager.dict()
    lines = open(f, 'r').readlines()
    if maxtuples != 0:
        lines = lines[: maxtuples]

    p = multiprocessing.Pool(processes = nprocesses)
    job = p.map_async(
        HandleLineFromFile(candidates, maxtuples),
        lines
    )

    last_idx = 0
    while job.ready() == False:
        job.wait(120)
        print '>> Analyzed %d unique gadgets so far...' % len(candidates)

    print '>> Analyzed a total of %d gadgets...' % len(candidates)
    p.terminate()
    p.join()
    return candidates

class HandleCandidate(object):
    '''This class is here because partial functions are not pickable ;
    so you can't use them with multiprocessing.Pool in Py27.
    This functor kind of workaround that nicely!'''
    def __init__(self, targeted_state, g_list):
        self.targeted_state = targeted_state
        self.g_list = g_list

    def __call__(self, candidate):
        try:
            if are_cpu_states_equivalent(self.targeted_state, candidate.mapper) == True:
                self.g_list.append((disass, get_preserved_gpr_from_mapper_str(candidate.mapper)))
        except AssertionError, e:
            pass
        except RuntimeError, e:
            pass
        except Exception, e:
            if str(e) != 'size mismatch':
                print '?? %s with %s:%r' % (str(e), candidate.disassembly, candidate.bytes)
                traceback.print_exc()
            # pass

class HandleCandidateAnalysis(object):
    '''This class is here because partial functions are not pickable ;
    so you can't use them with multiprocessing.Pool in Py27.
    This functor kind of workaround that nicely!'''
    def __init__(self, g_dict):
        self.g_dict = g_dict

    def __call__(self, candidate):
        disass, bytes = candidate
        if disass in self.g_dict:
            return

        try:
            self.g_dict[disass] = sym_exec_gadget_and_get_mapper(bytes)
        except AssertionError, e:
            pass
        except RuntimeError, e:
            pass
        except Exception, e:
            if str(e) != 'size mismatch':
                print '?? %s with %s:%r' % (str(e), disass, bytes)
                traceback.print_exc()
            # pass

def are_cpu_states_equivalent_or(target, candidate):
    '''This function tries to compare a set of constraints & a symbolic CPU state. The idea
    is simple:
        * `target` is basically a list of `constraints`
        * `candidate` is a `mapper` instance

    Every constraints inside target are going to be checked against the mapper `candidate`,
    if one of them is satisfied, it returns True, else False.'''
    valid = False
    for constraint in target:
        reg, exp, op = constraint.src, constraint.constraint, constraint.operator
        if op in (operator.gt, operator.ge, operator.lt, operator.le):
            # little trick here
            #   In [42]: from z3 import *
            #   In [43]: a, b = BitVecs('a b', 32)
            #   In [44]: prove(UGT((a + 10), (a+3)))
            #    counterexample
            #    [a = 4294967287] :((((
            #   In [65]: prove(((a+10)-(a+3)) > 0)
            #    proved - yay!
            valid |= prove_(op(0, exp.to_smtlib() - candidate[reg].to_smtlib()))
        else:
            valid |= prove_(op(exp.to_smtlib(), candidate[reg].to_smtlib()))

        if valid == True:
            break

    return valid

# def primitive_write4(candidates, where, what, preserved_registers = None):
#     gpr = [ cpu.eax, cpu.ebx, cpu.ecx, cpu.edx, cpu.esi, cpu.edi ]
#     preserved_registers = [] if preserved_registers is None else preserved_registers
#     # ESP & EBP & EFLAGS conservation; makes things easier but I guess it's not really needed
#     preserved_registers.append(cpu.esp, cpu.ebp)

#     prerequired_state = [
#         Constraint(cpu.esp, cpu.esp),
#         Constraint(cpu.ebp, cpu.ebp),
#         # Constraint(cpu.eflags, cpu.eflags),
#         # Obviously you don't want to loose control over your chain -- it could be ptr(esp+Y) too...;
#         # again the constraint is a bit restrictive
#         Constraint(cpu.eip, mem(cpu.esp))
#     ]

#     # Now we want to be able to write somewhere b
#     or_targeted_state = []
#     for dst in gpr:
#         for src in gpr:
#             # mov [x], x isn't what we need
#             if dst == src:
#                 continue
#             # XXX: Again, theoritically, we could have a more large equation -- we don't really
#             # need ptr(dst) to be equal to src, it could be src *operator* value
#             or_targeted_state.append(Constraint(mem(dst), src))

#     for candidate_disass, candidate_mapper in candidates.iteritems():
#         try:
#             if are_cpu_states_equivalent(prerequired_state, candidate_mapper) == True and are_cpu_states_equivalent_or(or_targeted_state, candidate_mapper):
#                 return candidate_disass
#         except AssertionError, e:
#             pass
#         except RuntimeError, e:
#             pass
#         except Exception, e:
#             if str(e) != 'size mismatch':
#                 print '?? %s with %s' % (str(e), candidate_disass)
#                 traceback.print_exc()

# def try_autorop_linux_execve_x86(gadgets, args):
#     '''sys_execve(char __user *, char __user *__user *, char __user *__user *, struct pt_regs *) - EAX=0x0b, EBX=char __user *, ECX=char __user *__user *, EDX=char __user *__user *, ESI=struct pt_regs *'''
#     gadgets = dict(gadgets)
#     print primitive_write4(gadgets, 0xdeadbeef, 0xbaadc0de)

def is_clean_gadget(gadget):
    gpr = [ cpu.eax, cpu.ebx, cpu.ecx, cpu.edx, cpu.esi, cpu.edi ]
    is_clean = True
    # we want a clean gadget that don't try to write.read everywhere
    is_clean &= len(filter(lambda x:x._is_mem, gadget.mapper.outputs())) == 0
    # same for reads
    is_clean &= len(filter(lambda x:x._is_mem, [gadget.mapper[reg] for reg in gpr])) == 0
    return is_clean

def test_is_gadget_PN1_valid():
    assembly_store = {
        'mov ecx, eax ; pop eax; rdtsc ; ret' : '\x89\xc1\x58\x0f\x31\xc3',
    }

    # simple PN1
    r = is_gadget_PN1_valid(sym_exec_gadget_and_get_mapper(assembly_store['mov ecx, eax ; pop eax; rdtsc ; ret']))
    assert len(r) == 1
    r = r[0]
    assert r.src == 'eax' and r.dst == 'ecx' and [cpu.ecx]
def is_gadget_PN1_valid(gadget):
    gpr = [ cpu.eax, cpu.ebx, cpu.ecx, cpu.edx, cpu.esi, cpu.edi ]
    Result = namedtuple('PN1Result', ('src', 'dst', 'preserved_registers', 'bytes'))
    # XXX: In [116]: print sym_exec_gadget_and_get_mapper('\x3a\x17')
    # eip <- { | [0:32]->(eip+0x2) | }
    # eflags <- { | [0:1]->(((dl-M8(edi))[7:8]&(M8(edi)[7:8]|(~edx[7:8])))|(M8(edi)[7:8]&(~edx[7:8]))) | [1:2]->eflags[1:2] |
    # [2:3]->(0x6996>>((dl-M8(edi))^((dl-M8(edi))>>0x4))[0:4])[0:1] | [3:4]->eflags[3:4] | [4:5]->((((-M8(edi)[0:4])+edx[0:4])
    # [3:4]&(M8(edi)[3:4]|(~edx[3:4])))|(M8(edi)[3:4]&(~edx[3:4]))) | [5:6]->eflags[5:6] | [6:7]->((dl-M8(edi))==0x0) | [7:8]-
    # >((dl-M8(edi))<0x0) | [8:11]->eflags[8:11] | [11:12]->(((dl-M8(edi))[7:8]^edx[7:8])&(M8(edi)[7:8]^edx[7:8])) | [12:32]->
    # eflags[12:32] | }
    # XXX: What about expressions? that are not directly memory r/w?
    
    results = []

    # XXX: Limitation -> symbolicly execute the whole block; if we have mov eax, [0] ; mov eax, ebx, it will be seen
    # as a valid PN1, even if the first instruction will prevent the rest from being executed

    # we want a clean gadget that don't try to write everywhere
    if is_clean_gadget(gadget):
        for src in gpr:
            for dst in gpr:
                if src == dst:
                    continue

                state = gadget.mapper[dst]
                if state._is_reg and state.ref == src.ref:
                    results.append(
                        Result(bytes = gadget.bytes, src = src, dst = dst, preserved_registers = get_preserved_gpr_from_mapper(gadget.mapper))
                    )

    return results

def is_gadget_PN2_valid(gadget):
    gpr = [ cpu.eax, cpu.ebx, cpu.ecx, cpu.edx, cpu.esi, cpu.edi ]
    Result = namedtuple('PN2Result', ('reg', 'stackoffset', 'bytes', 'preserved_registers', 'ret_stackoffset'))
    results = []
    if is_clean_gadget(gadget):
        for src in gadget.mapper.outputs():
            # src must be a gpr
            # it have to be a mem one, so that we know it is something like [something]
            # it must have `esp` as base so that we know it is something like [esp something]
            # it must have have a maximum offset of 0x100 let's say
            state = gadget.mapper[src]
            if src in gpr and state._is_mem and state.a.base._is_reg and state.a.base.ref == 'esp' and 0 <= state.a.disp < 0x100:
                # XXX: Remove this when rdtsc serialization bug gone
                try:
                    results.append(
                        Result(bytes = gadget.bytes, reg = src, stackoffset = state.a.disp, preserved_registers = get_preserved_gpr_from_mapper(gadget.mapper))
                    )
                except:
                    pass
    return results

class Primitive(object):
    def __init__(self, s):
        self.s = s
        self.gadgets = list()
        self.best_preserved = 0

    def append(self, gadget):
        if len(gadget.preserved_registers) > self.best_preserved:
            self.best_preserved = len(gadget.preserved_registers)

        self.gadgets.append(gadget)
        self.gadgets.sort(key = lambda x: len(x.preserved_registers), reverse = True)
    
    def __str__(self):
        return self.s

def display_dict_primitives(title, d):
    print title.center(80, '=')
    for desc, primitive in d.iteritems():
        print '> Achieved', desc, 'with %d gadgets (best:%d)' % (len(primitive.gadgets), primitive.best_preserved) 
        for i in range(min(len(primitive.gadgets), 3)):
            print '>> %s, preserved_registers: %s' % (disassemble(primitive.gadgets[i].bytes), ', '.join(str(e) for e in primitive.gadgets[i].preserved_registers))

def find_natural_primitive_gadgets(gadgets):
    '''Try to find PN1/PN2 gadgets as definied by `https://media.blackhat.com/us-13/US-13-Quynh-OptiROP-Hunting-for-ROP-Gadgets-in-Style-Slides.pdf`
    PN1: Set register to another
    PN2: Control a register via a value on the stack (which is assumed fully controlled)'''
    PN1 = {}
    PN2 = {}
    for gadget in gadgets:
        # XXX: Also filter gadgets where we won't be able to control the flow after execution (we want at the end that EIP = [ESP+X] )
        eip_end = gadget.mapper[cpu.eip]
        if eip_end._is_mem == False or eip_end.a.base is not cpu.esp or (0 >= eip_end.a.disp >= 0x100):
            continue

        res = is_gadget_PN1_valid(gadget)
        if len(res) > 0:
            for primitive in res:
                k = '%s = %s' % (primitive.dst, primitive.src)
                PN1.setdefault(k, Primitive(k)).append(primitive)

        res = is_gadget_PN2_valid(gadget)
        if len(res) > 0:
            for primitive in res:
                k = '%s = [esp + %d]' % (primitive.reg, primitive.stackoffset)
                PN2.setdefault(k, Primitive(k)).append(primitive)

    display_dict_primitives('PN1', PN1)
    display_dict_primitives('PN2', PN2)

def main():
    parser = argparse.ArgumentParser(description = 'Find a suitable ROP gadget via custom constraints.')
    parser.add_argument('--run-tests', action = 'store_true', help = 'Run the unit tests')
    parser.add_argument('--file', type = str, help = 'The files with every available gadgets you have')
    parser.add_argument('--nprocesses', type = int, default = 0, help = 'The default value will be the number of CPUs you have')
    
    amoco.set_quiet()
    # Disable aliasing -- mov [eax], ebx ; mov [ebx], 10; jmp [eax]
    # Here we assume that eax & ebx are different. Without assume_no_aliasing, we would have eip <- M32$2(eax)
    amoco.cas.mapper.mapper.assume_no_aliasing = True

    args = parser.parse_args()
    if args.run_tests:
        testing()

    if args.nprocesses == 0:
        args.nprocesses = multiprocessing.cpu_count()

    if args.file is None:
        if args.run_tests is None:
            parser.print_help()
        return 0

    db_path = os.path.join(os.path.dirname(args.file), '%s.db' % os.path.basename(args.file))
    t1 = None
    candidates = []
    if os.path.isfile(db_path) == False:
        print '> Building the list of gadgets since you do not have an existing database (may take time)..'
        t1 = time.time()
        m = multiprocessing.Manager()
        candidates = dict(build_candidates(m, args.file, args.nprocesses, maxtuples = 0))
        m.shutdown()
        t2 = time.time()
        print '> Serializing the candidates into %s' % db_path
        with open(db_path, 'wb') as f:
            for candidate in candidates.itervalues():
                candidate.serialize(f)
    else:
        print '> Loading the candidates from the db..'
        t1 = time.time()
        with open(db_path, 'rb') as f:
            while len(candidates) < 100000:
                try:
                    candidates.append(Gadget.unserialize(f))
                except EOFError:
                    break
        t2 = time.time()

    print '> Loaded %d unique candidates in %d s' % (len(candidates), t2 - t1)
    find_natural_primitive_gadgets(candidates)
    # try_autorop_linux_execve_x86(candidates, args)
    return 0
    # TODO:
    #  Inequations: why do they actually work?:D
    # Add preserved registers

    # Show case: Pivot ; EIP = ESP
    # cpu_state_end_target = SymbolicCpuX86TargetedState()
    # cpu_state_end_target.wants_register_equal('eip', 'esp')

    # cpu_state_end_target = { cpu.esp : mem(cpu.esp + 0x24, 32) }
    
    # Show case: [EAX] = EAX+1
    # targeted_state = [
    #     Constraint(mem(cpu.eax, 32), cpu.eax + 1)
    # ]

    # Show case: EAX = EBX = 0
    # XXX: Try if (EAX = 0, EBX = 0) == (EAX = EBX, EBX = 0)
    # targeted_state = [
    #     Constraint(cpu.eax, cst(0, 32)),
    #     Constraint(cpu.ebx, cst(0, 32))
    # ]

    # Show case: EDI = ESI
    # targeted_state = [
    #     Constraint(cpu.edi, cpu.esi),
    # ]

    # Show case: ((ESP >= ESP + 1000) && (ESP < ESP + 2000)) && (EAX == 0)
    targeted_state = [
        Constraint(cpu.esp, cpu.esp + cst(1000, 32), operator.ge),
        Constraint(cpu.esp, cpu.esp + cst(2000, 32), operator.lt),
        # Constraint(cpu.eax, cst(0, 32))
    ]

    manager = multiprocessing.Manager()
    matches = manager.list()

    print '> Trying to find what you want..'
    t1 = time.time()
    p = multiprocessing.Pool(processes = args.nprocesses)
    job = p.map_async(
        HandleCandidate(targeted_state, matches),
        candidates
    )

    last_idx = 0
    while job.ready() == False:
        job.wait(20)
        len_matches = len(matches)
        print '>> Found %d gadgets so far...' % len_matches
        if last_idx < len_matches:
            for i in range(last_idx, len_matches):
                disass, preserved_gprs = matches[i]
                print '>>>', matches[i], '; Preserved GPRs:', preserved_gprs
                last_idx = len_matches

    print '> Done, found %d matches in %ds!' % (len(matches), time.time() - t1)
    print 'Your constraints'.center(50, '=')
    for constraint in targeted_state:
        print ' >', constraint.src, '->', constraint.constraint

    print 'Successful matches'.center(50, '=')
    for disass, preserved_gprs in matches:
        print ' >', disass, '; Preserved GPRs:', preserved_gprs

    return 1

if __name__ == '__main__':
    sys.exit(main())