#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zlib
import struct

from compression import CompressionLayerWriter, CompressionLayerReader


class TestCompressionLayerWriter(object):

    def test_compression_empty(self):
        clw = CompressionLayerWriter(encoding='none')
        data = clw.get_data()

        header = data[:9]
        data = data[9:]

        assert header == b'\x09\x00\x03\x00\x00\x00\x00\x00\x00'
        assert data == ''


    def test_compression_none(self):
        clw = CompressionLayerWriter(encoding='none', data='foobarbaz')
        data = clw.get_data()

        header = data[:9]
        data = data[9:]

        assert header == b'\x09\x00\x03\x00\x00\x09\x00\x00\x00'
        assert data == 'foobarbaz'


    def test_compression_gzip(self):
        clw = CompressionLayerWriter(encoding='gzip', data='foobarbaz')
        data = clw.get_data()

        header = data[:5]
        payload_len = struct.unpack('<I', data[5:9])[0]
        data = data[9:]

        data_gz = zlib.compress('foobarbaz', 9)

        assert header == b'\x09\x00\x03\x01\x00'
        assert payload_len == len(data_gz)
        assert data == data_gz

    def test_compression_gzip_size(self):
        clw = CompressionLayerWriter(encoding='gzip', data='0'*1024)
        data = clw.get_data()

        data_gz = zlib.compress('0'*1024, 9)

        assert len(data) == len(data_gz) + 9
        assert len(data) < 1024


class TestCompressionLayerReader(object):

    def test_compression_empty(self):
        clr = CompressionLayerReader(b'\x09\x00\x03\x00\x00\x00\x00\x00\x00')
        data = clr.get_data()

        assert clr.get_data() == ''


    def test_compression_none(self):
        clr = CompressionLayerReader(
            b'\x09\x00\x03\x00\x00\x09\x00\x00\x00'
            'foobarbaz')

        data = clr.get_data()

        assert data == 'foobarbaz'


    def test_compression_gzip(self):

        data_gz = zlib.compress('foobarbaz', 9)

        clr = CompressionLayerReader(
            b'\x09\x00\x03\x01\x00' +
            struct.pack('<I', len(data_gz)) +
            data_gz)
        data = clr.get_data()

        assert data == 'foobarbaz'


