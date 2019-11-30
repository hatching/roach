# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from builtins import int, bytes
from Crypto.Cipher import XOR

def xor(key, data):
    if not isinstance(data, str):
        raise RuntimeError("data value must be a string!")

    # Retro compatiblity with Python2 (key is used as it is)
    if isinstance(key, int) and isinstance(data, bytes):
        key = bytes([key])
    elif isinstance(key, str):
        try:
            key = key.encode("utf-8")
        except UnicodeDecodeError as e:
            print("Warning, a string can't be decoded as UTF-8 using xor() function")


    if isinstance(data, str):
        data = bytes(data)

    return XOR.new(key).decrypt(data)
