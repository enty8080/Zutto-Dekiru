#!/usr/bin/env python3

#
# This payload requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

from hatsploit.lib.encoder import Encoder

from pex.string import String
from pex.arch import X86


class HatSploitEncoder(Encoder, String, X86):
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
        
    def run(self):
        
