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
import argparse
import multiprocessing
import time
import traceback
import cPickle

import symexec
import dbparser
import utils

from collections import namedtuple
# XXX: no amoco here
import amoco.arch.x86.cpu_x86 as cpu

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
    is_clean = True
    # we want a clean gadget that don't try to write.read everywhere
    is_clean &= len(filter(lambda x:x._is_mem, gadget._mapper.outputs())) == 0
    # same for reads
    is_clean &= len(filter(lambda x:x._is_mem, [gadget._mapper[reg] for reg in symexec.GPRs])) == 0
    return is_clean

def is_gadget_PN1_valid(gadget):
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
        for src in symexec.GPRs:
            for dst in symexec.GPRs:
                if src == dst:
                    continue

                state = gadget._mapper[dst]
                if state._is_reg and state.ref == src.ref:
                    results.append(
                        Result(bytes = gadget._bytes, src = src, dst = dst, preserved_registers = utils.get_preserved_gpr_from_mapper(gadget._mapper))
                    )

    return results

def is_gadget_PN2_valid(gadget):
    Result = namedtuple('PN2Result', ('reg', 'stackoffset', 'bytes', 'preserved_registers', 'ret_stackoffset'))
    results = []
    if is_clean_gadget(gadget):
        for src in gadget._mapper.outputs():
            # src must be a gpr
            # it have to be a mem one, so that we know it is something like [something]
            # it must have `esp` as base so that we know it is something like [esp something]
            # it must have have a maximum offset of 0x100 let's say
            state = gadget.mapper[src]
            if src in symexec.GPRs and state._is_mem and state.a.base._is_reg and state.a.base.ref == 'esp' and 0 <= state.a.disp < 0x100:
                # XXX: Remove this when rdtsc serialization bug gone
                try:
                    results.append(
                        Result(bytes = gadget._bytes, reg = src, stackoffset = state.a.disp, preserved_registers = utils.get_preserved_gpr_from_mapper(gadget._mapper))
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
        eip_end = gadget._mapper[cpu.eip]
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
    arg_parser = argparse.ArgumentParser(description = 'XXX: not sure what it is going to do exactly so waiting for that.')
    arg_parser.add_argument('--run-tests', action = 'store_true', help = 'Run the unit tests')
    arg_parser.add_argument('--file', type = str, help = 'The files with every available gadgets you have')
    # arg_parser.add_argument('--nprocesses', type = int, default = 0, help = 'The default value will be the number of CPUs you have')
    arg_parser.add_argument('--parser-template', type = str, default = 'rp', help = 'The parser template you want to use; default value is "rp"')
    arg_parser.add_argument('--max-gadgets', type = int, default = -1, help = 'The maximum amount of gadgets you want to extract from `file`')
    args = arg_parser.parse_args()
    
    db_parser = None

    if args.run_tests:
        # https://stackoverflow.com/questions/1732438/how-to-run-all-python-unit-tests-in-a-directory
        suite = unittest.TestSuite()
        for all_test_suite in unittest.defaultTestLoader.discover('tests', pattern = '*.py'):
            for test_suite in all_test_suite:
                suite.addTests(test_suite)

        unittest.main(verbosity = 2)

    # if args.nprocesses == 0:
    #     args.nprocesses = multiprocessing.cpu_count()

    if args.file is None and args.run_tests is None:
        arg_parser.print_help()
        return 0

    if args.parser_template.lower().startswith('rp'):
        db_parser = dbparser.Rp(args.file)

    if db_parser is None or args.max_gadgets < -1:
        arg_parser.print_help()
        return 0

    if args.max_gadgets == -1:
        args.max_gadgets = None

    t1 = time.time()
    candidates = list()
    for gadget in db_parser:
        candidates.append(gadget)
        if (len(candidates) % 2000) == 0 and len(candidates) != 0:
            print '>> Analyzed %d gadgets so far...' % len(candidates)
        if args.max_gadgets is not None and min(len(candidates), args.max_gadgets) == args.max_gadgets:
            break
    t2 = time.time()
    # db_path = os.path.join(os.path.dirname(args.file), '%s.db' % os.path.basename(args.file))
    # t1 = None
    # candidates = []
    # if os.path.isfile(db_path) == False:
    #     print '> Building the list of gadgets since you do not have an existing database (may take time)..'
    #     t1 = time.time()
    #     m = multiprocessing.Manager()
    #     candidates = dict(build_candidates(m, args.file, args.nprocesses, maxtuples = 0))
    #     m.shutdown()
    #     t2 = time.time()
    #     print '> Serializing the candidates into %s' % db_path
    #     with open(db_path, 'wb') as f:
    #         for candidate in candidates.itervalues():
    #             candidate.serialize(f)
    # else:
    #     print '> Loading the candidates from the db..'
    #     t1 = time.time()
    #     with open(db_path, 'rb') as f:
    #         while len(candidates) < 100000:
    #             try:
    #                 candidates.append(Gadget.unserialize(f))
    #             except EOFError:
    #                 break
    #     t2 = time.time()

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