#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from layer import GenericLayerWriter
from layer import GenericLayerReader

encoding_dict = {
    'none': 0,
    'fernet': 1,
    }

class EncryptionLayerWriter(GenericLayerWriter):
    def __init__(self, encoding=0, encoding_param=None, data=''):

        if encoding in encoding_dict:
            encoding = encoding_dict[encoding]

        super(EncryptionLayerWriter, self).__init__(
            encoding, encoding_param, data)
        self.layer_id = 2

    def _encode_data(self):
        if self.encoding == encoding_dict['none']:
            self.payload = self.data
        elif self.encoding == encoding_dict['fernet']:
            salt = self.encoding_param.get('salt', os.urandom(16))
            turns = self.encoding_param.get('key_turns', 100000)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                             length=32,
                             salt=salt,
                             iterations=turns,
                             backend=default_backend())

            key = base64.urlsafe_b64encode(
                kdf.derive(self.encoding_param['secret']))

            f = Fernet(key)
            token = base64.urlsafe_b64decode(f.encrypt(self.data))

            self.encoding_param_header = '\x01\x01'
            self.encoding_param_header += struct.pack('<I', turns)
            self.encoding_param_header += salt
            self.encoding_param_header += token[:25]
            self.payload = token[25:]



class EncryptionLayerReader(GenericLayerReader):
    def __init__(self, data, secret=''):
        self.secret = secret
        super(EncryptionLayerReader, self).__init__(data)

    def _decode_data(self):

        if self.encoding == encoding_dict['none']:
            self.decoded_data = self.data[self.header_length:]

        elif self.encoding == encoding_dict['fernet']:
            key_format, key_derivation_algo, turns = \
                struct.unpack('<BBI', self.encoding_parameters[:6])
            key_salt = self.encoding_parameters[6:22]
            fernet_header = self.encoding_parameters[22:47]

            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                             length=32,
                             salt=key_salt,
                             iterations=turns,
                             backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(self.secret))

            token = base64.urlsafe_b64encode(
                fernet_header + self.data[self.header_length:])

            f = Fernet(key)
            self.decoded_data = f.decrypt(token)



    # - key format (pbkdf2, 0x01) - 1 bytes
    # - key derivation algorithm - 1 bytes (0x01 sha256)
    # - key number of turn - 4 bytes
    # - key derivation salt - 16 bytes
    # - fernet version 1 byte
    # - fernet timestamp 8 bytes
    # - fernet IV 16 bytes
