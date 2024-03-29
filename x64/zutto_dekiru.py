"""
This encoder requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import random

from hatsploit.lib.encoder.basic import *

from pex.assembler import Assembler
from pex.string import String
from pex.nop import Opty2
from pex.arch import X86


class HatSploitEncoder(Encoder, Assembler, String, Opty2, X86):
    def __init__(self):
        super().__init__()

        self.details.update({
            'Name': "Zutto Dekiru XOR Encoder",
            'Encoder': "x64/zutto_dekiru",
            'Authors': [
                'Ivan Nikolsky (enty8080) - encoder developer'
            ],
            'Description': "Zutto Dekiru encoder for x64.",
            'Architecture': ARCH_X64,
        })

        self.key = Option("hatspl64", "8-byte key to encode.", True)

    def asm(self, code):
        return self.assemble(self.details['Arch'], code)

    def nop(self, length, save_registers=[]):
        return self.generate_sled(length, save_registers)

    @staticmethod
    def ordered_random_merge(a, b):
        a, b = a.copy(), b.copy()
        filled = sorted([random.randint(0, len(b)) for _ in a])

        for i in reversed(filled):
            b.insert(i, a.pop())

        return b

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

        fpu = []
        fpus = self.fpu_instructions()
        fpu.append(["fpu", fpus[random.randint(0, len(fpus)-1)]])

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
        fpu_lea.append(["fpu1", self.asm(f"fxsave64 [{reg_env[0]}]")])

        key_ins = [["key", self.asm(f"mov {reg_key}, {key[::-1].encode().hex()}")]]

        size = []
        size.append(["size", self.asm(f"xor {reg_size[0]}, {reg_size[0]}")])
        size.append(["size", self.asm(f"mov {reg_size[reg_type]}, {hex(len(block) / 8)}")])

        getrip = 0

        a = self.ordered_random_merge(size, key_ins)
        decode_head_tab = self.ordered_random_merge(a, fpu_lea)

        for i in range(len(decode_head_tab)):
            if decode_head_tab[i][0] == "fpu":
                getrip = i

        decode_head = b''.join(i for _, i in decode_head_tab])
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

        payload_offset = hex(len(decode_head_size) + 2)

        loop_code = self.asm(f"dec {reg_size[0]}")
        loop_code += self.asm(f"xor [{reg_rip} + ({reg_size[0]} * 8) + {payload_offset}], {reg_key}")
        loop_code += self.asm(f"test {reg_size[0]}, {reg_size[0]}")

        jnz = b"\x75" + bytes([0x100 - (len(loop_code) + 2)])
        decode = decode_head + loop_code + jnz

        return decode + self.xor_key_bytes(block, key.encode())

    def run(self):
        key = self.parse_options(self.options)
        return self.encode_block(key, self.payload)
