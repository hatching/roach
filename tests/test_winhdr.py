from roach.crypto.winhdr import BaseBlob
from unittest.mock import Mock, patch
import pytest

def test_baseblock():
    with pytest.raises(NotImplementedError):
        b = BaseBlob()
        b.parse(2)

    with pytest.raises(NotImplementedError):
        b = BaseBlob()
        b.export_key()