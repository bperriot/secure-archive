#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import json
from collections import OrderedDict

from compression import CompressionLayerWriter, CompressionLayerReader
from encryption import EncryptionLayerWriter, EncryptionLayerReader
from errorcorrecting import ErrorCorrectingLayerWriter
from errorcorrecting import ErrorCorrectingLayerReader



block_magic_value = '1234567\x00'


class BlockWriter(object):

    def __init__(self, id, compression=None, encryption=None,
                 errorcorrecting=None):
        self.id = id
        self.entries = []

        self.compression = {"encoding": "gzip"}
        if compression:
            self.compression.update(compression)

        self.encryption = {"encoding": "fernet", "param": {}}
        if encryption:
            self.encryption.update(encryption)

        self.errorcorrecting = {"encoding": "reedsolo"}
        if errorcorrecting:
            self.errorcorrecting.update(errorcorrecting)

    def flush(self, outfile):
        blockdata = ''

        block_metadata = OrderedDict()
        for key, metadata, data in self.entries:
            block_metadata[key] = OrderedDict([
                ('size', len(data)),
                ('offset', len(blockdata)),
                ('metadata', metadata)
                ])

            blockdata += data

        metadatastring = json.dumps(block_metadata, separators=(',', ':'))

        compression_layer = CompressionLayerWriter(
            encoding=self.compression["encoding"],
            data=struct.pack(
                '<I', len(metadatastring)) + metadatastring + blockdata)

        encryption_layer = EncryptionLayerWriter(
            encoding=self.encryption["encoding"],
            encoding_param=self.encryption["param"],
            data=compression_layer.get_data())

        errorcorrection_layer = ErrorCorrectingLayerWriter(
            encoding=self.errorcorrecting['encoding'],
            data=encryption_layer.get_data())

        # block header
        outfile.write(b'1234567\x00')
        outfile.write(struct.pack('I', self.id))

        outfile.write(errorcorrection_layer.get_data())


    def add_entry(self, key, metadata, data):
        self.entries.append((key, metadata, data))



class BlockReader(object):

    def __init__(self, infile, secret=''):
        self.infile = infile

        self.block_header = infile.read(12)

        ecr = ErrorCorrectingLayerReader(infile.read())
        enr = EncryptionLayerReader(ecr.get_data(), secret=secret)
        cpr = CompressionLayerReader(enr.get_data())

        self.raw_data = cpr.get_data()

        self.metadata_len = struct.unpack('<I', self.raw_data[:4])[0]

        self.metadata = json.loads(self.raw_data[4:4+self.metadata_len],
                                   object_pairs_hook=OrderedDict)
        self.bin_offset = 4 + self.metadata_len

    def get_keys(self):
        return self.metadata.keys()

    def get_metadata(self, key):
        return {}

    def get_data(self, key):
        offset = self.metadata[key]['offset']
        size = self.metadata[key]['size']

        return self.raw_data[self.bin_offset + offset:
                             self.bin_offset + offset + size]


