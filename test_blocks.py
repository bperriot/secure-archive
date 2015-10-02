#!/usr/bin/env python
# -*- coding: utf-8 -*-

from StringIO import StringIO
import struct
import json
from collections import OrderedDict

import pytest


from blocks import BlockWriter, BlockReader

# - Magic value (7 bytes)
# - Block format version (1 byte)
# - Bloc id (4 bytes, used for indexing)
# - Decoded info hash (if not problematic for confidentiality)

# #### Layer structure (generic)

# - Header lenght (2 bytes)
# - Layer id (1 byte)
# - Method used (1 byte)
#     eg aes for encryption, bzip or lzma for compression...
# - Layer format version (1 byte)
# - Layer parameters (variable)
#     aes key, aes hmac, compression parameter, ...
# - Data lenght (4 bytes)
# - Data of next layer or raw


class TestBlockWriterRawString(object):
    def test_empty_block(self):
        outfile = StringIO()
        bl = BlockWriter(0)
        bl.flush(outfile)

        data = outfile.getvalue()
        block_header = data[0:12]
        errorcorrecting_header = data[12:21]
        encryption_header = data[21:30]
        compression_header = data[30:39]
        data = data[39:]

        assert block_header == b'1234567\x00\x00\x00\x00\x00'
        assert data == b'\x02\x00\x00\x00{}'
        assert compression_header == b'\x08\x00\x03\x00\x00\x06\x00\x00\x00'
        assert encryption_header == b'\x08\x00\x02\x00\x00\x0F\x00\x00\x00'
        assert errorcorrecting_header == \
            b'\x08\x00\x01\x00\x00\x18\x00\x00\x00'


    def test_id(self):
        outfile = StringIO()
        bl = BlockWriter(515)
        bl.flush(outfile)

        data = outfile.getvalue()
        block_header = data[0:12]
        errorcorrecting_header = data[12:21]
        encryption_header = data[21:30]
        compression_header = data[30:39]
        data = data[39:]

        assert data == b'\x02\x00\x00\x00{}'
        assert compression_header == b'\x08\x00\x03\x00\x00\x06\x00\x00\x00'
        assert encryption_header == b'\x08\x00\x02\x00\x00\x0F\x00\x00\x00'
        assert errorcorrecting_header == \
            b'\x08\x00\x01\x00\x00\x18\x00\x00\x00'
        assert block_header == b'1234567\x00\x03\x02\x00\x00'


    def test_empty_entry(self):
        outfile = StringIO()
        bl = BlockWriter(0)
        bl.add_entry('0', {}, '')
        bl.flush(outfile)

        data = outfile.getvalue()
        block_header = data[0:12]
        errorcorrecting_header = data[12:21]
        encryption_header = data[21:30]
        compression_header = data[30:39]
        datalen = struct.unpack('<I', data[39:43])[0]
        metadata = data[43:90]
        bin = data[90:]

        print metadata

        assert datalen == 41
        assert bin == ''
        assert json.loads(metadata) == {"0": {"size": 0,
                                              "offset": 0,
                                              "metadata": {}}}
        assert compression_header == b'\x08\x00\x03\x00\x00\x2D\x00\x00\x00'
        assert encryption_header == b'\x08\x00\x02\x00\x00\x36\x00\x00\x00'
        assert errorcorrecting_header == \
            b'\x08\x00\x01\x00\x00\x3F\x00\x00\x00'
        assert block_header == b'1234567\x00\x00\x00\x00\x00'


    def test_simple_entry(self):
        outfile = StringIO()
        bl = BlockWriter(0)
        bl.add_entry('0', {}, 'foo')
        bl.flush(outfile)

        data = outfile.getvalue()
        block_header = data[0:12]
        errorcorrecting_header = data[12:21]
        encryption_header = data[21:30]
        compression_header = data[30:39]
        datalen = struct.unpack('<I', data[39:43])[0]
        metadata = data[43:84]
        bin = data[84:]

        assert datalen == 41
        assert bin == 'foo'
        assert json.loads(metadata) == {"0": {"size": 3,
                                        "offset": 0, "metadata": {}}}
        assert compression_header == b'\x08\x00\x03\x00\x00\x30\x00\x00\x00'
        assert encryption_header == b'\x08\x00\x02\x00\x00\x39\x00\x00\x00'
        assert errorcorrecting_header == \
            b'\x08\x00\x01\x00\x00\x42\x00\x00\x00'
        assert block_header == b'1234567\x00\x00\x00\x00\x00'


    def test_multiple_entry(self):
        outfile = StringIO()
        bl = BlockWriter(0)
        bl.add_entry('0', {}, 'foo')
        bl.add_entry('1', {}, 'secondentry')
        bl.flush(outfile)

        data = outfile.getvalue()
        block_header = data[0:12]
        errorcorrecting_header = data[12:21]
        encryption_header = data[21:30]
        compression_header = data[30:39]
        metadatalen = struct.unpack('<I', data[39:43])[0]
        metadata = data[43:125]
        bin = data[125:]


        metadata_ref = {
            "0": {"size": 3, "offset": 0, "metadata": {}},
            "1": {"size": 11, "offset": 3, "metadata": {}}}

        print metadata

        assert bin == 'foosecondentry'
        assert metadatalen == 82
        assert json.loads(metadata) == metadata_ref
        assert compression_header == b'\x08\x00\x03\x00\x00\x64\x00\x00\x00'
        assert encryption_header == b'\x08\x00\x02\x00\x00\x6D\x00\x00\x00'
        assert errorcorrecting_header == \
            b'\x08\x00\x01\x00\x00\x76\x00\x00\x00'
        assert block_header == b'1234567\x00\x00\x00\x00\x00'

# different id
# cas d'entrée pervers
# key non string utf8 valide; (string with special caracters, non-string)
# metadata is not a dict
# binary data is not a string of assimilated


class TestBlockReaderRawString(object):
    def test_empty_block(self):

        data = (
            b'1234567\x00\x00\x00\x00\x00'
            b'\x08\x00\x01\x00\x00\x18\x00\x00\x00'
            b'\x08\x00\x02\x00\x00\x0F\x00\x00\x00'
            b'\x08\x00\x03\x00\x00\x06\x00\x00\x00'
            b'\x02\x00\x00\x00{}'
            )

        infile = StringIO(data)
        bl = BlockReader(infile)

        assert bl.get_keys() == []

    # def test_id(self):
    #     outfile = StringIO()
    #     bl = BlockWriter(515)
    #     bl.flush(outfile)

    #     data = outfile.getvalue()
    #     block_header = data[0:12]
    #     errorcorrecting_header = data[12:21]
    #     encryption_header = data[21:30]
    #     compression_header = data[30:39]
    #     data = data[39:]

    #     assert data == b'\x02\x00\x00\x00[]'
    #     assert compression_header == b'\x08\x00\x03\x00\x00\x06\x00\x00\x00'
    #     assert encryption_header == b'\x08\x00\x02\x00\x00\x0F\x00\x00\x00'
    #     assert errorcorrecting_header == \
    #         b'\x08\x00\x01\x00\x00\x18\x00\x00\x00'
    #     assert block_header == b'1234567\x00\x03\x02\x00\x00'


    def test_empty_entry(self):

        metadata = json.dumps(OrderedDict((
            ("0", OrderedDict((("size", 0),
                               ("offset", 0),
                               ("metadata", {})
                               ))),)),
            separators=(',', ':'))

        data = (
            b'1234567\x00\x00\x00\x00\x00'
            b'\x08\x00\x01\x00\x00\x45\x00\x00\x00'
            b'\x08\x00\x02\x00\x00\x3C\x00\x00\x00'
            b'\x08\x00\x03\x00\x00\x33\x00\x00\x00' +
            struct.pack('<I', len(metadata)) + metadata
            )

        infile = StringIO(data)
        bl = BlockReader(infile)

        assert bl.get_keys() == ['0']
        assert bl.get_metadata('0') == {}
        assert bl.get_data('0') == ''


    def test_simple_entry(self):

        metadata = json.dumps(OrderedDict((
            ("0", OrderedDict((("size", 3),
                               ("offset", 0),
                               ("metadata", {})
                               ))),)),
            separators=(',', ':'))

        data = (
            b'1234567\x00\x00\x00\x00\x00'
            b'\x08\x00\x01\x00\x00\x42\x00\x00\x00'
            b'\x08\x00\x02\x00\x00\x39\x00\x00\x00'
            b'\x08\x00\x03\x00\x00\x30\x00\x00\x00' +
            struct.pack('<I', len(metadata)) + metadata + 'foo'
            )

        infile = StringIO(data)
        bl = BlockReader(infile)

        assert bl.get_keys() == ['0']
        assert bl.get_metadata('0') == {}
        assert bl.get_data('0') == 'foo'

    def test_multiple_entry(self):

        metadata = json.dumps(OrderedDict((
            ("0", OrderedDict((("size", 3),
                               ("offset", 0),
                               ("metadata", {})
                               ))),
            ("1", OrderedDict((("size", 11),
                               ("offset", 3),
                               ("metadata", {})))))),
            separators=(',', ':'))

        data = (
            b'1234567\x00\x00\x00\x00\x00'
            b'\x08\x00\x01\x00\x00\x72\x00\x00\x00'
            b'\x08\x00\x02\x00\x00\x69\x00\x00\x00'
            b'\x08\x00\x03\x00\x00\x60\x00\x00\x00' +
            struct.pack('<I', len(metadata)) + metadata + 'foosecondentry')

        infile = StringIO(data)
        bl = BlockReader(infile)

        assert bl.get_keys() == [u'0', u'1']
        assert bl.get_metadata('0') == {}
        assert bl.get_metadata('1') == {}
        assert bl.get_data('0') == 'foo'
        assert bl.get_data('1') == 'secondentry'


