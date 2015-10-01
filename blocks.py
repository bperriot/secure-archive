#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import json
from copy import copy
from collections import OrderedDict

block_magic_value = '1234567\x00'


class BlockWriter(object):

    def __init__(self, id):
        self.id = id
        self.entries = []

    def flush(self, outfile):
        offset = 0

        block_metadata = OrderedDict()
        for key, metadata, data in self.entries:
            block_metadata[key] = OrderedDict([
                ('size', len(data)),
                ('offset', offset),
                ('metadata', metadata)
                ])

            offset += len(data)

        metadatastring = json.dumps(block_metadata, separators=(',', ':'))

        datalen = len(metadatastring) + offset

        # block header
        outfile.write(b'1234567\x00')
        outfile.write(struct.pack('I', self.id))

        # error-correcting header
        outfile.write(b'\x00\x08\x01\x00\x00')
        outfile.write(struct.pack('I', datalen + 22))

        # encryption header
        outfile.write(b'\x00\x08\x02\x00\x00')
        outfile.write(struct.pack('I', datalen + 13))

        # compression header
        outfile.write(b'\x00\x08\x03\x00\x00')
        outfile.write(struct.pack('I', datalen + 4))

        # metadata
        outfile.write(struct.pack('I', len(metadatastring)))
        outfile.write(metadatastring)

        for key, metadata, data in self.entries:
            outfile.write(data)

    def add_entry(self, key, metadata, data):
        self.entries.append((key, metadata, data))



class BlockReader(object):

    def __init__(self, infile):
        self.infile = infile

        self.infile.seek(39)
        self.metadata_len = struct.unpack('I', self.infile.read(4))[0]
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





