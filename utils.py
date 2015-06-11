#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    utils.py - XXX: plz
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
import operator
import symexec
import gadget
import amoco
import amoco.system.raw
import amoco.system.core
import amoco.arch.x86.cpu_x86 as cpu

from z3 import *

def disassemble(bytes):
    '''This function disassembles some assembly'''
    p = amoco.system.raw.RawExec(
        amoco.system.core.DataIO(bytes), cpu
    )
    blocks = list(amoco.lsweep(p).iterblocks())
    s = []
    for block in blocks:
        for i in block.instr:
            s.append(' '.join(i.formatter(i).split()))

    return ' ; '.join(s).lower()

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
    return filter(
        lambda reg: prove_(mapper[reg].to_smtlib() == reg.to_smtlib()),
        symexec.GPRsEFL
    )

def get_preserved_gpr_from_mapper_str(mapper):
    '''Returns a clean string instead of a list of expressions'''
    preserved_gprs = get_preserved_gpr_from_mapper(mapper)
    return ', '.join(r.ref for r in preserved_gprs)

def are_cpu_states_equivalent(target, candidate):
    '''This function tries to compare a set of constraints & a symbolic CPU state. The idea
    is simple:
        * `target` is basically a list of `constraints`, or a `Constraint`
        * `candidate` is a `mapper` instance, or a `Gadget` instance

    Every constraints inside target are going to be checked against the mapper `candidate`,
    if they are all satisfied, it returns True, else False.'''
    if isinstance(candidate, gadget.Gadget):
        candidate = candidate._mapper

    if isinstance(target, gadget.Constraint):
        target = [ target ]

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

# XXX: Do something better than the two methods with and / or; ideally we would be able to express both and & or in an expression
# XXX: if we want
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

def extract_things_from_mapper(mapper, op, *things):
    '''Extracts whatever you want from a mapper & build a Constraint instance so that you can directly feed
    those ones in `are_cpu_states_equivalent`.'''
    return [ gadget.Constraint(thing, mapper[thing], op) for thing in things ]

def extract_things_from_mapper_eq(mapper, *things):
    return extract_things_from_mapper(mapper, operator.eq, *things)

def main(argc, argv):
    
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))