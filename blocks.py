#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import json
from collections import OrderedDict

from compression import CompressionLayerWriter
from encryption import EncryptionLayerWriter
from errorcorrecting import ErrorCorrectingLayerWriter



block_magic_value = '1234567\x00'


class BlockWriter(object):

    def __init__(self, id):
        self.id = id
        self.entries = []

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

        datalen = len(metadatastring) + len(blockdata)

        compression_layer = CompressionLayerWriter(
            data=struct.pack(
                '<I', len(metadatastring)) + metadatastring + blockdata)

        encryption_layer = EncryptionLayerWriter(
            data=compression_layer.get_data())

        errorcorrection_layer = ErrorCorrectingLayerWriter(
            data=encryption_layer.get_data())

        # block header
        outfile.write(b'1234567\x00')
        outfile.write(struct.pack('I', self.id))

        outfile.write(errorcorrection_layer.get_data())

        # error-correcting header
        # outfile.write(b'\x08\x00\x01\x00\x00')
        # outfile.write(struct.pack('I', datalen + 22))

        # encryption header
        # outfile.write(b'\x08\x00\x02\x00\x00')
        # outfile.write(struct.pack('I', datalen + 13))

        # compression header
        # outfile.write(b'\x08\x00\x03\x00\x00')
        # outfile.write(struct.pack('I', datalen + 4))

        # metadata
        # outfile.write(struct.pack('I', len(metadatastring)))
        # outfile.write(metadatastring)

        # for key, metadata, data in self.entries:
            # outfile.write(data)

    def add_entry(self, key, metadata, data):
        self.entries.append((key, metadata, data))



class BlockReader(object):

    def __init__(self, infile):
        self.infile = infile

        self.infile.seek(39)
        self.metadata_len = struct.unpack('<I', self.infile.read(4))[0]
        self.metadata = json.loads(self.infile.read(self.metadata_len),
                                   object_pairs_hook=OrderedDict)
        self.bin_offset = self.infile.tell()

    def get_keys(self):
        return self.metadata.keys()

    def get_metadata(self, key):
        return {}

    def get_data(self, key):
        offset = self.metadata[key]['offset']
        size = self.metadata[key]['size']

        self.infile.seek(self.bin_offset + offset)

        return self.infile.read(size)





