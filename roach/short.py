# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach.crypto.aes import AES
from roach.crypto.rc import RC4
from roach.pe import PE

class aes(object):
    def __init__(self, mode):
        self.mode = mode

    def decrypt(self, key=None, iv=None, data=None):
        return AES(key, iv, self.mode).decrypt(data)

    class cbc(object):
        @staticmethod
        def decrypt(key=None, iv=None, data=None):
            return aes("cbc").decrypt(key, iv, data)

    class ecb(object):
        @staticmethod
        def decrypt(key=None, iv=None, data=None):
            return aes("ecb").decrypt(key, iv, data)

class rc4_(object):
    @staticmethod
    def rc4(key, data):
        return RC4(key).encrypt(data)

    __call__ = decrypt = encrypt = rc4

rc4 = rc4_()
pe = PE
