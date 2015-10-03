#!/usr/bin/env python
# -*- coding: utf-8 -*-

from layer import GenericLayerWriter, GenericLayerReader


class TestGenericLayerWriter(object):

    def test_empty(self):
        layer = GenericLayerWriter()

        assert len(layer.get_data()) == 9
        assert layer.get_data() == b'\x09\x00\x00\x00\x00\x00\x00\x00\x00'


class TestGenericLayerReader(object):

    def test_empty(self):
        layer = GenericLayerReader(b'\x09\x00\x00\x00\x00\x00\x00\x00\x00')

        assert layer.header_length == 9
        assert layer.encoding == 0
        assert layer.encoding_version == 0
        assert layer.data_len == 0
        assert layer.get_data() == ''


    def test_dummy_layer(self):
        layer = GenericLayerReader(
            b'\x0B\x00\x07\x05\x0A\xFE\x01\x03\x00\x00\x00\x11\x22\x33')

        assert layer.header_length == 11
        assert layer.layer_id == 7
        assert layer.encoding == 5
        assert layer.encoding_version == 10
        assert layer.encoding_parameters == '\xFE\x01'
        assert layer.data_len == 3
        assert layer.get_data() == '\x11\x22\x33'






