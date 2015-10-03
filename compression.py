#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zlib

from layer import GenericLayerWriter
from layer import GenericLayerReader


encoding_dict = {
    'none': 0,
    'gzip': 1,
    }


class CompressionLayerWriter(GenericLayerWriter):
    def __init__(self, encoding=0, encoding_param=None, data=''):

        if encoding in encoding_dict:
            encoding = encoding_dict[encoding]

        super(CompressionLayerWriter, self).__init__(
            encoding, encoding_param, data)
        self.layer_id = 3

    def _encode_data(self):
        if self.encoding == encoding_dict['none']:
            self.payload = self.data
        elif self.encoding == encoding_dict['gzip']:
            self.payload = zlib.compress(self.data, 9)


class CompressionLayerReader(GenericLayerReader):

    def __init__(self, data=''):

        super(CompressionLayerReader, self).__init__(data)


    def _decode_data(self):
        payload = self.data[self.header_length:]
        if self.encoding == encoding_dict['none']:
            self.decoded_data = payload
        elif self.encoding == encoding_dict['gzip']:
            self.decoded_data = zlib.decompress(payload)



