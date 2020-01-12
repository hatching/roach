# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import disasm
from roach.disasm import Operand, Instruction
from unittest.mock import Mock, patch, PropertyMock, MagicMock

def test_instruction():
    assert (Instruction() == 3) is False
    assert (Instruction(mnem=2) == Instruction(mnem=3)) is False
    assert (Instruction(addr=2, op1=1, op2=2, op3=3) == Instruction(addr=2, op1=1, op2=2, op3=4)) is False
    # @todo check if str method is implemented right
    assert str(Instruction(mnem=0, op1=1, op2=2, op3=3)) == "0 1, 2, 3"
    assert str(Instruction(mnem="21")) == "21"

def test_disamsm_mem():
    with patch.object(Operand, 'is_mem') as t:
        t.__get__ = Mock(return_value=True)
        p = PropertyMock()
        m = Mock()
        m.value.mem.disp = p

        obj = Operand(m)
        assert obj.value is p

def test_disamsm_reg():
    with patch.object(Operand, 'is_reg') as t:
        t.__get__ = Mock(return_value=True)
        m = Mock()
        m.reg = 1

        obj = Operand(m)
        obj.regs = {1: "89"}
        assert obj.value == "89"

class TestDisasm(object):
    streams = b"".join((
        # mov esi, [edi+4]
        b"\x8b\x77\x04",
        # mov eax, [ebx+4*ecx+4242]
        b"\x8b\x84\x8b\x92\x10\x00\x00",
        # mov al, byte [1333337]
        b"\xa0\x59\x58\x14\x00",
        # mov eax, byte [1333337]
        b"\xa1\x59\x58\x14\x00",
        # push 0x41414141
        b"\x68\x41\x41\x41\x41",
        # call $+0
        b"\xe8\x00\x00\x00\x00",
        # movxz eax, byte [0x400000]
        b"\x0f\xb6\x05\x00\x00\x04\x00",
    ))

    def setup(self):
        self.insns = list(disasm(self.streams, 0x1000))

    def test_insns(self):
        insn1 = self.insns[0]
        assert insn1.mnem == "mov"
        assert insn1.op1 == "esi"
        assert insn1.op1 != "ebp"
        # One of the listed registers.
        assert insn1.op1 in ("ebp", "esi")
        assert insn1.op2 == ("dword", "edi", None, None, 4)
        assert str(insn1) == "mov esi, dword [edi+0x00000004]"

        insn2 = self.insns[1]
        assert insn2.op2.mem == ("dword", "ebx", 4, "ecx", 4242)
        assert str(insn2) == "mov eax, dword [ebx+4*ecx+0x00001092]"

        # This is a bug, "mov al, byte [addr]" should have "al" as
        # first operand.
        insn3 = self.insns[2]
        assert insn3.op1.mem == ("byte", None, None, None, 1333337)

        insn4 = self.insns[3]
        assert insn4.op1 == "eax"
        assert insn4.op2.mem == ("dword", None, None, None, 1333337)
        assert str(insn4) == "mov eax, dword [0x00145859]"

        insn5 = self.insns[4]
        assert insn5.op1 == 0x41414141
        assert str(insn5) == "push 0x41414141"

        insn6 = self.insns[5]
        assert insn6.op1.value == insn6.addr + 5

        insn7 = self.insns[6]
        assert insn7.op2.reg is None
        assert insn7.op2 == (None, None, None, 0x400000)

    def test_equal(self):
        assert disasm(b"hAAAA", 0)[0].mnem == "push"
        assert disasm(b"hAAAA", 0)[0].op1.value == 0x41414141
        assert disasm(b"hAAAA", 0) == disasm(b"hAAAA", 0)
