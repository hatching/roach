# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from click.testing import CliRunner

from roach.main import procmem_list

def test_procmem_list():
    result = CliRunner().invoke(procmem_list, ["tests/files/dummy.dmp"])
    assert not result.exit_code
    assert result.output == (
        "0x41410000 .. 0x41411000 b'AAAAAAAAAAAAAAAA'\n"
        "0x41411000 .. 0x41413000 b'BBBBBBBBBBBBBBBB'\n"
        "0x42420000 .. 0x42421000 b'CCCCCCCCCCCCCCCC'\n"
    )
