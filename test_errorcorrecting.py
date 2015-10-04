#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
from array import array

from reedsolo import RSCodec

from errorcorrecting import ErrorCorrectingLayerWriter
from errorcorrecting import ErrorCorrectingLayerReader


class TestErrorCorrectingLayerWriter(object):

    def test_errorcorrecting_empty(self):
        ecw = ErrorCorrectingLayerWriter()
        data = ecw.get_data()

        header = data[:9]
        data = data[9:]

        assert header == b'\x09\x00\x01\x00\x00\x00\x00\x00\x00'
        assert data == ''


    def test_errorcorrecting_none(self):
        ecw = ErrorCorrectingLayerWriter(encoding='none', data='foobarbaz')
        data = ecw.get_data()

        header = data[:9]
        data = data[9:]

        assert header == b'\x09\x00\x01\x00\x00\x09\x00\x00\x00'
        assert data == 'foobarbaz'


    def test_errorcorrecting_rs10(self):
        ecw = ErrorCorrectingLayerWriter(encoding='reedsolo',
                                         data='foobarbaz')
        data = ecw.get_data()

        header = data[:10]
        data = data[10:]

        encoded_data = str(RSCodec(10).encode(bytearray(
            'foobarbaz' + '\x00'*236)))

        assert header == b'\x0A\x00\x01\x01\x00\x0A\xFF\x00\x00\x00'
        assert data == encoded_data

    def test_errorcorrecting_rs10_long(self):
        indata = array('B', [i/10 for i in xrange(2000)]).tostring()

        ecw = ErrorCorrectingLayerWriter(encoding='reedsolo',
                                         data=indata)
        data = ecw.get_data()

        header = data[:6]
        data_len = struct.unpack('<I', data[6:10])[0]
        data = data[10:]

        packet_size = len(data) / 255
        extracted_data = ''.join([data[i::packet_size][:245]
                                  for i in xrange(packet_size)])[:2000]

        encoded_data = bytes(RSCodec(10).encode(bytearray(indata+'\x00'*205)))
        encoded_data = ''.join(encoded_data[i::255] for i in xrange(255))


        assert len(data) % 255 == 0
        assert header == b'\x0A\x00\x01\x01\x00\x0A'
        assert data_len == 9*255
        assert len(data) == 9*255
        assert data == encoded_data
        assert extracted_data == indata


    def test_errorcorrecting_rs10_2450B(self):
        indata = array('B', [i/10 for i in xrange(2450)]).tostring()

        ecw = ErrorCorrectingLayerWriter(encoding='reedsolo',
                                         data=indata)
        data = ecw.get_data()

        header = data[:6]
        data_len = struct.unpack('<I', data[6:10])[0]
        data = data[10:]

        packet_size = 10
        extracted_data = ''.join([data[i::packet_size][:245]
                                  for i in xrange(packet_size)])

        encoded_data = bytes(RSCodec(10).encode(bytearray(indata)))
        encoded_data = ''.join(encoded_data[i::255] for i in xrange(255))


        assert header == b'\x0A\x00\x01\x01\x00\x0A'
        assert data_len == 2550
        assert len(data) == len(encoded_data)
        assert data == encoded_data
        assert extracted_data == indata



class TestErrorCorrectingLayerReader(object):

    def test_errorcorrecting_empty(self):
        ecr = ErrorCorrectingLayerReader(
            b'\x09\x00\x01\x00\x00\x00\x00\x00\x00')
        data = ecr.get_data()

        assert data == ''


    def test_errorcorrecting_none(self):
        ecr = ErrorCorrectingLayerReader(
            b'\x09\x00\x01\x00\x00\x09\x00\x00\x00'
            'foobarbaz')

        data = ecr.get_data()

        assert data == 'foobarbaz'


    def test_errorcorrecting_rs10_245(self):

        header = b'\x0A\x00\x01\x01\x00\x0A\xFF\x00\x00\x00'
        payload = str(RSCodec(10).encode(bytearray('\x03'*245)))
        print len(payload)

        elr = ErrorCorrectingLayerReader(data=header+payload)
        data = elr.get_data()

        assert len(data) == 245
        assert data == '\x03' * 245


    def test_errorcorrecting_rs10_long(self):

        indata = array('B', [i/10 for i in xrange(2000)]).tostring()

        encoded_data = bytes(RSCodec(10).encode(bytearray(indata+'\x00'*205)))
        encoded_data = ''.join(encoded_data[i::255] for i in xrange(255))

        header = b'\x0A\x00\x01\x01\x00\x0A\xF7\x08\x00\x00'

        ecr = ErrorCorrectingLayerReader(data=header+encoded_data)
        data = ecr.get_data()

        assert len(data) == 2205
        assert data[:2000] == indata
        assert data[2000:] == '\x00' * 205

