#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct


class GenericLayerWriter(object):

    def __init__(self, encoding=0, encoding_param=None, data=''):
        self.layer_id = 0
        self.encoding = encoding
        self.encoding_version = 0
        self.encoding_param = encoding_param if encoding_param else {}
        self.data = data

        self._encode_data()

    def _encode_data(self):
        self.payload = self.data

    def get_header(self):
        return struct.pack('<HBBBI',
                           9,
                           self.layer_id,
                           self.encoding,
                           self.encoding_version,
                           len(self.payload))

    def get_data(self):
        return self.get_header() + self.payload


class GenericLayerReader(object):

    def __init__(self, data=''):
        self.data = data

        self.header_length = struct.unpack('H', self.data[:2])[0]
        self.header = self.data[:self.header_length]

        self.layer_id, self.encoding, self.encoding_version = \
            struct.unpack('<BBB', self.header[2:5])
        self.data_len = struct.unpack('<I', self.header[-4:])[0]
        self.encoding_parameters = self.header[5:-4]

        self._decode_data()

    def _decode_data(self):
        self.decoded_data = self.data[self.header_length:]

    def get_data(self):
        return self.decoded_data

