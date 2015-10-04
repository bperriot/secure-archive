#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Possible reed-solomon library

# reedsolo: public, pure-python

# PyECLib: C backend, MIT -> schéma vand, tout pourri
#                           -> cauchy  / pareil
# reedsolomon 0.1: C backend, GPL (phil karn backend)
    # http://www.ka9q.net/code/fec/
    # multiple algorithms, fast, libC, LGPL

# https://github.com/dchokola/reed-solomon/blob/master/reed-solomon.c
    # MIT, semble ok
    # peu de doc
    # non finie ; broken

# https://github.com/s29zhu/Reed-Solomon; C, LGPL; complet ?
# https://github.com/f33losopher/ReedSolomon/tree/master/PhilKarn/src
    # update of phil karn

# https://github.com/nimrody/rs/blob/master/rs.c, pas de licence, pas de doc

from reedsolo import RSCodec

from layer import GenericLayerWriter
from layer import GenericLayerReader

encoding_dict = {
    'none': 0,
    'reedsolo': 1
    }


class ErrorCorrectingLayerWriter(GenericLayerWriter):
    def __init__(self, encoding=0, encoding_param=None, data=''):

        self.correction_bytes = 10

        if encoding in encoding_dict:
            encoding = encoding_dict[encoding]

        super(ErrorCorrectingLayerWriter, self).__init__(
            encoding, encoding_param, data)

        self.layer_id = 1

    def _encode_data(self):
        if self.encoding == encoding_dict['none']:
            self.payload = self.data
        elif self.encoding == encoding_dict['reedsolo']:
            rs = RSCodec(self.correction_bytes)

            if len(self.data) % 245:
                self.data += '\x00' * (245 - (len(self.data) % 245))

            payload = bytes(rs.encode(bytearray(self.data)))

            self.payload = ''.join([payload[i::255] for i in xrange(255)])

            self.encoding_param_header = b'\x0A'


class ErrorCorrectingLayerReader(GenericLayerReader):
    def __init__(self, data=''):
        super(ErrorCorrectingLayerReader, self).__init__(data)

    def _decode_data(self):
        payload = self.data[self.header_length:]
        if self.encoding == encoding_dict['none']:
            self.decoded_data = payload
        elif self.encoding == encoding_dict['reedsolo']:

            packet_size = len(payload) / 255
            uninterleaved = ''.join([payload[i::packet_size]
                                     for i in xrange(packet_size)])

            self.decoded_data = str(RSCodec(10).decode(
                bytearray(uninterleaved)))


