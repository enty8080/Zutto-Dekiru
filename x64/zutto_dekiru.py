#!/usr/bin/env python3

#
# This payload requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

import random

from hatsploit.lib.encoder import Encoder

from pex.string import String
from pex.poly import LogicalBlock
from pex.nop import Opty2
from pex.arch import X86


class HatSploitEncoder(Encoder, String, Opty2, X86):
    details = {
        'Name': "Zutto Dekiru XOR Encoder",
        'Encoder': "x64/zutto_dekiru",
        'Authors': [
            'Ivan Nikolsky (enty8080) - encoder developer'
        ],
        'Description': "Zutto Dekiru encoder for x64.",
        'Architecture': "x64"
    }

    options = {
        'KEY': {
            'Description': "8-byte key to encode.",
            'Value': "P@ssW0rd",
            'Type': None,
            'Required': True
        }
    }

    def asm(self, code):
        return self.assemble('x64', code)

    @staticmethod
    def fxsave64(reg):
        regs = {
            'rax': b"\x48\x0f\xae\x00",
            'rbx': b"\x48\x0f\xae\x03",
            'rcx': b"\x48\x0f\xae\x01",
            'rdx': b"\x48\x0f\xae\x02",
            'rsi': b"\x48\x0f\xae\x06",
            'rdi': b"\x48\x0f\xae\x07",
            'rbp': b"\x48\x0f\xae\x45\x00",
            'r8': b"\x49\x0f\xae\x00",
            'r9': b"\x49\x0f\xae\x01",
            'r10': b"\x49\x0f\xae\x02",
            'r11': b"\x49\x0f\xae\x03",
            'r12': b"\x49\x0f\xae\x04\x24",
            'r13': b"\x49\x0f\xae\x45\x00",
            'r14': b"\x49\x0f\xae\x06",
            'r15': b"\x49\x0f\xae\x07"
        }

        if reg in regs:
            return regs[reg]

    def nop(self, length, save_registers=[]):
        return self.generate_sled(length, save_registers)

    @staticmethod
    def ordered_random_merge(a, b):
        a, b = a.copy(), b.copy()
        filled = sorted([random.randint(0, len(b)) for _ in a])

        for i in reversed(filled):
            b.insert(i, a.pop())

        return a

    def encode_block(self, key, block):
        allowed_reg = [
            ["rax",  "eax",  "ax",   "al"  ],
            ["rbx",  "ebx",  "bx",   "bl"  ],
            ["rcx",  "ecx",  "cx",   "cl"  ],
            ["rdx",  "edx",  "dx",   "dl"  ],
            ["rsi",  "esi",  "si",   "sil" ],
            ["rdi",  "edi",  "di",   "dil" ],
            ["rbp",  "ebp",  "bp",   "bpl" ],
            ["r8",   "r8d",  "r8w",  "r8b" ],
            ["r9",   "r9d",  "r9w",  "r9b" ],
            ["r10",  "r10d", "r10w", "r10b"],
            ["r11",  "r11d", "r11w", "r11b"],
            ["r12",  "r12d", "r12w", "r12b"],
            ["r13",  "r13d", "r13w", "r13b"],
            ["r14",  "r14d", "r14w", "r14b"],
            ["r15",  "r15d", "r15w", "r15b"],
        ]

        random.shuffle(allowed_reg)

        if len(block) % 8 != 0:
            block += self.nop(8 - (len(block) % 8))

        reg_type = 3

        if len(block) / 8 > 0xff:
            reg_type = 2

        if len(block) / 8 > 0xffff:
            reg_type = 1

        if len(block) / 8 > 0xffffffff:
            reg_type = 0

        reg_key = allowed_reg[0][0]
        reg_size = allowed_reg[3]
        reg_rip = allowed_reg[1][0]
        reg_env = allowed_reg[2]

        flip_coin = random.randint(0, 1)
        fpu_opcode = LogicalBlock('fpu', *self.fpu_instructions())

        fpu = []
        fpu.append(["fpu", fpu_opcode.generate()])

        sub = (random.randint(0, 0xcff) & 0xfff0) + 0xf000
        lea = []

        if not flip_coin:
            lea.append(["lea", self.asm(f"mov {reg_env[0]}, rsp")])
            lea.append(["lea1", self.asm(f"and {reg_env[2]}, {hex(sub)}")])
        else:
            lea.append(["lea", self.asm("push rsp")])
            lea.append(["lea1", self.asm(f"pop {reg_env[0]}")])
            lea.append(["lea2", self.asm(f"and {reg_env[2]}, {hex(sub)}")])

        fpu_lea = self.ordered_random_merge(fpu, lea)
        fpu_lea.append(["fpu1", self.fxsave(reg_env[0])])

        key_ins = [["key", self.asm(f"mov {reg_key}, {hex(key)}")]]

        size = []
        size.append(["size", self.asm(f"xor {reg_size[0]}, {reg_size[0]}")])
        size.append(["size", self.asm(f"mov {reg_size[reg_type]}, {hex(len(block) / 8)}")])

        getrip = 0

        a = self.ordered_random_merge(size, key_ins)
        decode_head_tab = self.ordered_random_merge(a, fpu_lea)

        for i in range(len(decode_head_tab)):
            if decode_head_tab[i][0] == "fpu":
                getrip = i

        decode_head = b''.join([str(i) for _, i in decode_head_tab])
        flip_coin = random.randint(0, 1)

        if not flip_coin:
            decode_head += self.asm(f"mov {reg_rip}, [{reg_env[0]} + 0x8]")
        else:
            decode_head += self.asm(f"add {reg_env[0]}, 0x8")
            decode_head += self.asm(f"mov {reg_rip}, [{reg_env[0]}]")

        decode_head_size = len(decode_head)
        for i in range(0, getrip):
            decode_head_size -= len(decode_head_tab[i][1])

        loop_code = self.asm(f"dec {reg_size[0]}")
        loop_code += self.asm(f"xor [{reg_rip} + ({reg_size[0]} * 8) + 0x7f], {reg_key}")
        loop_code += self.asm(f"test {reg_size[0]}, {reg_size[0]}")

        jnz = b"\x75" + bytes([0x100 - (len(loop_code) + 2)])
        decode = decode_head + loop_code + jnz

        return decode + self.xor_key_bytes(block, key.encode())

    def run(self):
        key = self.parse_options(self.options)
        return self.encode_block(self.payload, key)
