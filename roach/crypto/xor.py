# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from builtins import int
from past.builtins import basestring
from Crypto.Cipher import XOR

def xor(key, data):
    if not isinstance(data, basestring):
        raise RuntimeError("data value must be a string!")

    if isinstance(key, int):
        key = bytes([key])
    elif isinstance(key, str):
        key = key.encode("utf-8")

    return XOR.new(key).decrypt(data)
