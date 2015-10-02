#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zlib

from layer import GenericLayerWriter


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



