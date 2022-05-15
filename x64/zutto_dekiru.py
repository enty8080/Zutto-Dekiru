#!/usr/bin/env python3

#
# This payload requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

from hatsploit.lib.encoder import Encoder

from pex.string import String
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

    def nop(length, save_registers=[]):
        return self.generate_sled(length, save_registers)

    
    def run(self):
        
