#!/usr/bin/env python
# -*- coding: utf-8 -*-

from StringIO import StringIO
from array import array
import struct
from random import randint
from collections import Counter

import pytest

from archive import ArchiveWriter
from blocks import BlockReader



class TestArchiveWriter(object):

    @pytest.mark.skipif("True")
    def test_archive_empty(self):

        outfile = StringIO()

        ar = ArchiveWriter()

        ar.flush(outfile)

        outfile.seek(0)
        bl = BlockReader(outfile, secret='abc')

        assert bl.get_keys() == []


    @pytest.mark.skipif("True")
    def test_short_archive(self):

        outfile = StringIO()

        ar = ArchiveWriter()

        ar.add('0', {}, 'file1')
        ar.add('1', {}, 'file2')

        ar.flush(outfile)

        outfile.seek(0)
        bl = BlockReader(outfile, secret='abc')

        assert bl.get_keys() == ["0", "1"]
        assert bl.get_data("0") == 'file1'
        assert bl.get_data("1") == 'file2'
        assert bl.get_metadata("0") == {}
        assert bl.get_metadata("1") == {}


    def test_long_archive_small_file(self):

        outfile = StringIO()

        ar = ArchiveWriter()
        from time import time

        t0 = time()
        for i in xrange(1024):
            file_ = '0' * 50*1024
            ar.add('file%03d' % i, {}, file_)
        print time()-t0

        ar.flush(outfile)

        outfile.seek(0)
        data = outfile.read()
        offset = 0
        block_lenghts = []
        block_ids = []
        while offset < len(data):
            print "new block"
            offset += 8  # block header
            block_id = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            header_len = struct.unpack('<H', data[offset:offset+2])[0]
            offset += header_len - 4
            data_len = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4 + data_len

            print "block id = %d" % block_id
            print "block total size = %d" % (header_len + data_len)

            block_ids.append(block_id)
            block_lenghts.append(header_len + data_len)

        for block_len in block_lenghts:
            assert block_len < 12*1024*1024

        for c in Counter(block_ids).values():
            assert c == 1

    # def test_one_big_file(self):

    #     outfile = StringIO()

    #     ar = ArchiveWriter()

    #     ar.add('0', metadata, data)

