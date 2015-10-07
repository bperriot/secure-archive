#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import base64

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from encryption import EncryptionLayerWriter, EncryptionLayerReader


class TestEncryptionLayerWriter(object):

    def test_encryption_empty(self):
        ecw = EncryptionLayerWriter()
        data = ecw.get_data()

        header = data[:9]
        data = data[9:]

        assert header == b'\x09\x00\x02\x00\x00\x00\x00\x00\x00'
        assert data == ''


    def test_encryption_none(self):
        ecw = EncryptionLayerWriter(encoding='none', data='foobarbaz')
        data = ecw.get_data()

        header = data[:9]
        data = data[9:]

        assert header == b'\x09\x00\x02\x00\x00\x09\x00\x00\x00'
        assert data == 'foobarbaz'


    # @pytest.mark.skipif("True")
    def test_encryption_fernet(self):
        ecw = EncryptionLayerWriter(encoding='fernet',
                                    encoding_param={'secret': 'password',
                                                    'key_turns': 100000},
                                    data='foobarbaz')
        data = ecw.get_data()

        generic_header = data[:5]

        key_format, key_algo, key_turns = struct.unpack('<BBI', data[5:11])
        key_salt = data[11:27]

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=key_salt,
                         iterations=key_turns,
                         backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive('password'))

        fernet_params = data[27:52]

        data_len = struct.unpack('<I', data[52:56])[0]
        data = data[56:]

        fernet_token = base64.urlsafe_b64encode(fernet_params+data)

        f = Fernet(key)
        payload = f.decrypt(fernet_token)

        assert generic_header == b'\x38\x00\x02\x01\x00'
        assert data_len == len(data)

        assert key_format == 1
        assert key_algo == 1
        assert key_turns == 100000

        assert payload == 'foobarbaz'


class TestEncryptionLayerReader(object):

    def test_encryption_empty(self):
        ecr = EncryptionLayerReader(b'\x09\x00\x02\x00\x00\x00\x00\x00\x00')
        data = ecr.get_data()

        assert data == ''


    def test_encryption_none(self):
        ecr = EncryptionLayerReader(
            b'\x09\x00\x02\x00\x00\x09\x00\x00\x00'
            'foobarbaz')

        data = ecr.get_data()

        assert data == 'foobarbaz'


    # @pytest.mark.skipif("True")
    def test_encryption_fernet(self):

        ecw = EncryptionLayerWriter(encoding='fernet',
                                    encoding_param={'secret': 'U78TPVa',
                                                    'key_turns': 100000},
                                    data='foobarbaz')
        data = ecw.get_data()

        elr = EncryptionLayerReader(data, 'U78TPVa')

        assert elr.get_data() == 'foobarbaz'


