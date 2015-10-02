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
                           8,
                           self.layer_id,
                           self.encoding,
                           self.encoding_version,
                           len(self.payload))

    def get_data(self):
        return self.get_header() + self.payload

