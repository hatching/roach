# Copyright (C) 2020 Hatching International B.V..
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pytest
import unittest
import os
import roach.native.aplib

from pathlib import Path
from roach import aplib, gzip, base64
from unittest.mock import patch
from roach.native.common import load_library

@patch("os.path.exists", return_value=False)
def test_common_not_exists(r):
    with pytest.raises(ImportError):
        load_library("test")

@patch("sys.platform", return_value="win32")
@patch("os.path.exists", return_value=True)
@patch("roach.native.common.ctypes.LibraryLoader.LoadLibrary")
def test_common(a, f, r):
    load_library("test")
    p = Path(os.path.dirname(__file__)).parents[0]
    o = os.path.join(p, "roach", "native", "components", "test-64.so")
    a.assert_called_once_with(o)

class TestMeme(unittest.TestCase):
    def setUp(self):
        self.aplib = roach.native.aplib.aplib
        roach.native.aplib.aplib = None

    def test_import(self):
        with pytest.raises(RuntimeError):
            roach.native.aplib.unpack(b"t")

    def tearDown(self):
        roach.native.aplib.aplib = self.aplib

@pytest.mark.skipif("sys.platform == 'darwin'")
def test_aplib():
    assert aplib(
        base64("QVAzMhgAAAANAAAAvJpimwsAAACFEUoNaDhlbI5vIHducuxkAA==")
    ) == b"hello world"
    assert aplib(base64("aDhlbI5vIHducuxkAA==")) == b"hello world"

    assert aplib(base64("""
QVAzMhgAAABGAAAAf+p8HwEAEAA5iu7QQacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3/
/IcB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBXXf/2QqAAA==
""")) == b"A"*1024*1024 + b"\n"
    assert aplib(base64("""
QacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3//IcB19//yAF9ff/
8hwHX3//IAX19//yH\nAdff/8gBXXf/2QqAAA==
""")) == b"A"*1024*1024 + b"\n"

    assert aplib("helloworld") is None

@pytest.mark.skipif("sys.platform != 'darwin'")
def test_aplib_macos():
    with pytest.raises(RuntimeError):
        assert aplib("hello world")

def test_gzip():
    assert gzip(base64("eJzLSM3JyVcozy/KSQEAGgsEXQ==")) == b"hello world"
    assert gzip(
        base64("H4sICCGZt1oEAzEtMQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=")
    ) == b"hello world"
    assert gzip(
        base64("H4sICCOZt1oCAzEtOQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=")
    ) == b"hello world"
