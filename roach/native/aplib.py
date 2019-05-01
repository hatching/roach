# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import ctypes

from roach.native.common import load_library

try:
    aplib = load_library("aplib")
except ImportError as e:
    aplib = None

def unpack(buf, length=None, maxsz=4*1024*1024):
    """ Note : buf can be a str or a bytes-like object"""

    # Use only bytes elements
    if isinstance(buf, str):
        try:
            buf = buf.encode("utf-8")
        except UnicodeDecodeError as e:
            print("Warning, %s can't be decoded as utf-8" % buf)

    if not aplib:
        raise RuntimeError("aplib can't be used on your platform!")

    if not length:
        length = len(buf) * 2

    if buf.startswith(b"AP32"):
        fn = aplib.aPsafe_depack
    else:
        fn = aplib.aP_depack_asm_safe

    while length < maxsz:
        out = ctypes.create_string_buffer(length)
        ret = fn(buf, len(buf), out, length)
        if ret > 0:
            break
        length *= 2
    if ret < 0:
        return

    return out.raw[:ret]

