# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pytest

from roach import aes, blowfish, des3, rc4, rsa, xor, base64, unhex, rabbit
from roach.crypto.aes import PlaintextKeyBlob
from roach.crypto.rsa import PublicKeyBlob, PrivateKeyBlob
from unittest.mock import Mock, patch

def test_aes():
    mock = Mock()
    mock.read.return_value = "test"
    assert PlaintextKeyBlob().parse(mock) is None

    assert aes.ecb.decrypt(b"A"*16, b"C"*32) == (
        b"I\x96Z\xe4\xb5\xffX\xbdT]\x93\x03\x96\xfcw\xd9"
        b"I\x96Z\xe4\xb5\xffX\xbdT]\x93\x03\x96\xfcw\xd9"
    )
    assert aes.ecb.decrypt(b"A"*16, data=b"C"*32) == (
        b"I\x96Z\xe4\xb5\xffX\xbdT]\x93\x03\x96\xfcw\xd9"
        b"I\x96Z\xe4\xb5\xffX\xbdT]\x93\x03\x96\xfcw\xd9"
    )

    assert aes.cbc.decrypt(b"A"*16, b"B"*16, b"C"*32) == (
        b"\x0b\xd4\x18\xa6\xf7\xbd\x1a\xff\x16\x1f\xd1A\xd4\xbe5\x9b"
        b"\n\xd5\x19\xa7\xf6\xbc\x1b\xfe\x17\x1e\xd0@\xd5\xbf4\x9a"
    )

    assert aes.ctr(
        b"hello world12345", b"A"*16,
        b"\x803\xe3J#\xf4;\x13\x11+h\xf5\xba-\x9b\x05"
    ) == b"B"*16

    assert aes.import_key(
        b"\x08\x02\x00\x00\x0ef\x00\x00\x10\x00\x00\x00" + b"A"*16
    ) == ("AES-128", b"A"*16)

    assert aes.import_key(
        b"\x08\x02\x00\x00\x0ef"
    ) is None

    assert aes.import_key(
        b't\xfb\x88\xcf' + b"A"*16
    ) is None

    assert aes.import_key(
        b'\x08\x02\x00\x00\x0ef' + b"A" * 16
    ) is None

def test_blowfish():
    assert blowfish(
        b"blowfish", b"\x91;\x92\xa9\x85\x83\xb36\xbb\xac\xa8r0\xf1$\x19"
    ) == b"_hello world01!?"

def test_des():
    assert des3.cbc.decrypt(
        b"A"*8, b"B"*8, b"\x1d\xed\xc37pV\x89S\xac\xaeT\xaf\xa1\xcfW\xa3"
    ) == b"C"*16

def test_rc4():
    assert rc4.encrypt("Key", "Plaintext") == unhex("bbf316e8d940af0ad3")
    assert rc4.decrypt("Wiki", "pedia") == unhex("1021bf0420")
    assert rc4.decrypt("Secret", "Attack at dawn") == (
        unhex("45a01f645fc35b383552544b9bf5")
    )
    assert rc4("hello", "world") == unhex("783ecd96cf")

def test_xor():
    assert xor(
        0xff, b"\x97\x9a\x93\x93\x90\xdf\x88\x90\x8d\x93\x9b"
    ) == b"hello world"
    assert xor(
        "hi!", b"\x00\x0cM\x04\x06\x01\x1f\x06S\x04\r"
    ) == b"hello world"
    with pytest.raises(RuntimeError):
        assert xor(
            "hi!", "test"
        ) == b"hello world"

@patch("roach.crypto.rsa.PublicKeyBlob")
@patch("roach.crypto.rsa.bigint", side_effect=lambda a, b: None)
def test_rsa_p1(big, pk):
    pk.parse.return_value = 3
    mock = Mock()
    mock.read.return_value = b"test"
    p = PrivateKeyBlob()
    p.bitsize = 16
    assert p.parse(mock) == "a"
    assert len(big.mock_calls) == 1

@patch("roach.crypto.rsa.PublicKeyBlob")
@patch("roach.crypto.rsa.bigint", side_effect=[3, None])
def test_rsa_p2(big, pk):
    pk.parse.return_value = 3
    mock = Mock()
    mock.read.return_value = b"test"
    p = PrivateKeyBlob()
    p.bitsize = 16
    assert p.parse(mock) == "b"
    assert len(big.mock_calls) == 2

@patch("roach.crypto.rsa.PublicKeyBlob")
@patch("roach.crypto.rsa.bigint", side_effect=[3, 3, None])
def test_rsa_p3(big, pk):
    pk.parse.return_value = 3
    mock = Mock()
    mock.read.return_value = b"test"
    p = PrivateKeyBlob()
    p.bitsize = 16
    assert p.parse(mock) == "c"
    assert len(big.mock_calls) == 3

@patch("roach.crypto.rsa.PublicKeyBlob")
@patch("roach.crypto.rsa.bigint", side_effect=[3, 3, 3, None])
def test_rsa_p4(big, pk):
    pk.parse.return_value = 3
    mock = Mock()
    mock.read.return_value = b"test"
    p = PrivateKeyBlob()
    p.bitsize = 16
    assert p.parse(mock) == "d"
    assert len(big.mock_calls) == 4

@patch("roach.crypto.rsa.PublicKeyBlob")
@patch("roach.crypto.rsa.bigint", side_effect=[3, 3, 3, 3, None])
def test_rsa_p5(big, pk):
    pk.parse.return_value = 3
    mock = Mock()
    mock.read.return_value = b"test"
    p = PrivateKeyBlob()
    p.bitsize = 16
    assert p.parse(mock) == "e"
    assert len(big.mock_calls) == 5

@patch("roach.crypto.rsa.PublicKeyBlob")
@patch("roach.crypto.rsa.bigint", side_effect=[3, 3, 3, 3, 3, None])
def test_rsa_p6(big, pk):
    pk.parse.return_value = 3
    mock = Mock()
    mock.read.return_value = b"test"
    p = PrivateKeyBlob()
    p.bitsize = 16
    assert p.parse(mock) == "f"
    assert len(big.mock_calls) == 6

@patch("roach.crypto.rsa.RSA.export_key")
def test_rsa_export(exp):
    p = PrivateKeyBlob()
    p.n = 1
    p.e = 8
    p.d = 12
    p.export_key()
    exp.assert_called_once_with(1, 8, 12)

@patch("roach.crypto.rsa.RSA")
def test_rsa_import(rsaa):

    rsaa.algorithms = {}
    assert rsa.import_key(base64("""
    BgIAAACkAABSU0ExAAQAAAEAAQChEcfAbVoL/jUnFMxI+xsR0zZUvMZ+9pgkLGpaxTiLRP6PZqx8
    lDdwqdb7gC+m5aOz+Uwms6RHrY/xRMYEXopj877qLancMtsiqcpASOYJWxWSgW+gQMJGldwn2H97
    AaHoqFlbn7NW6oNtpz4C7NotiggtVnqLdE8YyNfO6/gEpQ==
    """)) == "b"

def test_rsa():
    mock = Mock()
    mock.read.return_value = b"test"
    assert PublicKeyBlob().parse(mock) is None

    mock.read.return_value = b"RSA1" + b"a" * 8
    assert PublicKeyBlob().parse(mock) is None
    assert PrivateKeyBlob().parse(mock) is None

    assert rsa.import_key(base64("""
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5cagCPVB7LiX3UI5N3WRQJqTLe5RPrhFj79/U
7AY+ziYQrKhSaIQG7KWuLAZj4sKRyRyZK1te0Ekb1UGkYn3b1YTQtXojaakq5p4WyHFvhfNPjSlJ
ClIt4QC/NZ9uS2FRee8ONEKODrcgevzcd+lbNy/mGAB7yW9XgP06YzfOyQIDAQAB
    """)) == b"""
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5cagCPVB7LiX3UI5N3WRQJqTL
e5RPrhFj79/U7AY+ziYQrKhSaIQG7KWuLAZj4sKRyRyZK1te0Ekb1UGkYn3b1YTQ
tXojaakq5p4WyHFvhfNPjSlJClIt4QC/NZ9uS2FRee8ONEKODrcgevzcd+lbNy/m
GAB7yW9XgP06YzfOyQIDAQAB
-----END PUBLIC KEY-----
""".strip()

    assert rsa.import_key(base64("""
BgIAAACkAABSU0ExAAQAAAEAAQChEcfAbVoL/jUnFMxI+xsR0zZUvMZ+9pgkLGpaxTiLRP6PZqx8
lDdwqdb7gC+m5aOz+Uwms6RHrY/xRMYEXopj877qLancMtsiqcpASOYJWxWSgW+gQMJGldwn2H97
AaHoqFlbn7NW6oNtpz4C7NotiggtVnqLdE8YyNfO6/gEpQ==
""")) == b"""
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClBPjrztfIGE90i3pWLQiKLdrs
Aj6nbYPqVrOfW1mo6KEBe3/YJ9yVRsJAoG+BkhVbCeZIQMqpItsy3Kkt6r7zY4pe
BMZE8Y+tR6SzJkz5s6Plpi+A+9apcDeUfKxmj/5EizjFWmosJJj2fsa8VDbTERv7
SMwUJzX+C1ptwMcRoQIDAQAB
-----END PUBLIC KEY-----
""".strip()

    assert rsa.import_key(base64("""
bgIAAACkAABSU0ExAAQAAAEAAQChEcfAbVoL/jUnFMxI+xsR0zZUvMZ+9pgkLGpaxTiLRP6PZqx8
lDdwqdb7gC+m5aOz+Uwms6RHrY/xRMYEXopj877qLancMtsiqcpASOYJWxWSgW+gQMJGldwn2H97
AaHoqFlbn7NW6oNtpz4C7NotiggtVnqLdE8YyNfO6/gEpQ1==
""")) is None

    assert rsa.import_key("") is None

    # This obviously doesn't make any sense, but it's to ensure that the
    # None or long wrapping is working, avoiding PyCrypto complains.
    assert rsa.export_key(0x10001, 0x10001) == b"""
-----BEGIN PUBLIC KEY-----
MB4wDQYJKoZIhvcNAQEBBQADDQAwCgIDAQABAgMBAAE=
-----END PUBLIC KEY-----
""".strip()

def test_rabbit():
    key1 = b"".join([
        b"\x00", b"\x00", b"\x00", b"\x00", b"\x00", b"\x00", b"\x00", b"\x00",
        b"\x00", b"\x00", b"\x00", b"\x00", b"\x00", b"\x00", b"\x00", b"\x00",
    ])

    key2 = b"".join([
        b"\xAC", b"\xC3", b"\x51", b"\xDC", b"\xF1", b"\x62", b"\xFC", b"\x3B",
        b"\xFE", b"\x36", b"\x3D", b"\x2E", b"\x29", b"\x13", b"\x28", b"\x91",
    ])

    key3 = b"".join([
        b"\x43", b"\x00", b"\x9B", b"\xC0", b"\x01", b"\xAB", b"\xE9", b"\xE9",
        b"\x33", b"\xC7", b"\xE0", b"\x87", b"\x15", b"\x74", b"\x95", b"\x83",
    ])

    iv1 = b"".join([
        b"\x00", b"\x00", b"\x00", b"\x00", b"\x00", b"\x00", b"\x00", b"\x00"
    ])

    iv2 = b"".join([
        b"\x59", b"\x7E", b"\x26", b"\xC1", b"\x75", b"\xF5", b"\x73", b"\xC3",
    ])

    iv3 = b"".join([
        b"\x27", b"\x17", b"\xF4", b"\xD2", b"\x1A", b"\x56", b"\xEB", b"\xA6",
    ])

    out1 = b"".join([
        b"\x02", b"\xF7", b"\x4A", b"\x1C", b"\x26", b"\x45", b"\x6B", b"\xF5",
        b"\xEC", b"\xD6", b"\xA5", b"\x36", b"\xF0", b"\x54", b"\x57", b"\xB1",
        b"\xA7", b"\x8A", b"\xC6", b"\x89", b"\x47", b"\x6C", b"\x69", b"\x7B",
        b"\x39", b"\x0C", b"\x9C", b"\xC5", b"\x15", b"\xD8", b"\xE8", b"\x88",
        b"\x96", b"\xD6", b"\x73", b"\x16", b"\x88", b"\xD1", b"\x68", b"\xDA",
        b"\x51", b"\xD4", b"\x0C", b"\x70", b"\xC3", b"\xA1", b"\x16", b"\xF4",
    ])

    out2 = b"".join([
        b"\x9C", b"\x51", b"\xE2", b"\x87", b"\x84", b"\xC3", b"\x7F", b"\xE9",
        b"\xA1", b"\x27", b"\xF6", b"\x3E", b"\xC8", b"\xF3", b"\x2D", b"\x3D",
        b"\x19", b"\xFC", b"\x54", b"\x85", b"\xAA", b"\x53", b"\xBF", b"\x96",
        b"\x88", b"\x5B", b"\x40", b"\xF4", b"\x61", b"\xCD", b"\x76", b"\xF5",
        b"\x5E", b"\x4C", b"\x4D", b"\x20", b"\x20", b"\x3B", b"\xE5", b"\x8A",
        b"\x50", b"\x43", b"\xDB", b"\xFB", b"\x73", b"\x74", b"\x54", b"\xE5",
    ])

    out3 = b"".join([
        b"\x9B", b"\x60", b"\xD0", b"\x02", b"\xFD", b"\x5C", b"\xEB", b"\x32",
        b"\xAC", b"\xCD", b"\x41", b"\xA0", b"\xCD", b"\x0D", b"\xB1", b"\x0C",
        b"\xAD", b"\x3E", b"\xFF", b"\x4C", b"\x11", b"\x92", b"\x70", b"\x7B",
        b"\x5A", b"\x01", b"\x17", b"\x0F", b"\xCA", b"\x9F", b"\xFC", b"\x95",
        b"\x28", b"\x74", b"\x94", b"\x3A", b"\xAD", b"\x47", b"\x41", b"\x92",
        b"\x3F", b"\x7F", b"\xFC", b"\x8B", b"\xDE", b"\xE5", b"\x49", b"\x96",
    ])

    out4 = b"".join([
        b"\xED", b"\xB7", b"\x05", b"\x67", b"\x37", b"\x5D", b"\xCD", b"\x7C",
        b"\xD8", b"\x95", b"\x54", b"\xF8", b"\x5E", b"\x27", b"\xA7", b"\xC6",
        b"\x8D", b"\x4A", b"\xDC", b"\x70", b"\x32", b"\x29", b"\x8F", b"\x7B",
        b"\xD4", b"\xEF", b"\xF5", b"\x04", b"\xAC", b"\xA6", b"\x29", b"\x5F",
        b"\x66", b"\x8F", b"\xBF", b"\x47", b"\x8A", b"\xDB", b"\x2B", b"\xE5",
        b"\x1E", b"\x6C", b"\xDE", b"\x29", b"\x2B", b"\x82", b"\xDE", b"\x2A",
    ])

    out5 = b"".join([
        b"\x6D", b"\x7D", b"\x01", b"\x22", b"\x92", b"\xCC", b"\xDC", b"\xE0",
        b"\xE2", b"\x12", b"\x00", b"\x58", b"\xB9", b"\x4E", b"\xCD", b"\x1F",
        b"\x2E", b"\x6F", b"\x93", b"\xED", b"\xFF", b"\x99", b"\x24", b"\x7B",
        b"\x01", b"\x25", b"\x21", b"\xD1", b"\x10", b"\x4E", b"\x5F", b"\xA7",
        b"\xA7", b"\x9B", b"\x02", b"\x12", b"\xD0", b"\xBD", b"\x56", b"\x23",
        b"\x39", b"\x38", b"\xE7", b"\x93", b"\xC3", b"\x12", b"\xC1", b"\xEB",
    ])

    out6 = b"".join([
        b"\x4D", b"\x10", b"\x51", b"\xA1", b"\x23", b"\xAF", b"\xB6", b"\x70",
        b"\xBF", b"\x8D", b"\x85", b"\x05", b"\xC8", b"\xD8", b"\x5A", b"\x44",
        b"\x03", b"\x5B", b"\xC3", b"\xAC", b"\xC6", b"\x67", b"\xAE", b"\xAE",
        b"\x5B", b"\x2C", b"\xF4", b"\x47", b"\x79", b"\xF2", b"\xC8", b"\x96",
        b"\xCB", b"\x51", b"\x15", b"\xF0", b"\x34", b"\xF0", b"\x3D", b"\x31",
        b"\x17", b"\x1C", b"\xA7", b"\x5F", b"\x89", b"\xFC", b"\xCB", b"\x9F",
    ])

    assert rabbit(key1, None, b"\x00"*48) == out1
    assert rabbit(key2, None, b"\x00"*48) == out2
    assert rabbit(key3, None, b"\x00"*48) == out3

    assert rabbit(key1, iv1, b"\x00"*48) == out4
    assert rabbit(key1, iv2, b"\x00"*48) == out5
    assert rabbit(key1, iv3, b"\x00"*48) == out6
