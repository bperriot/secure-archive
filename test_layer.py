#!/usr/bin/env python
# -*- coding: utf-8 -*-

from layer import GenericLayerWriter

class TestGenericLayerWriter(object):

    def test_empty(self):
        layer = GenericLayerWriter()

        assert len(layer.get_data()) == 9
        assert layer.get_data() == b'\x08\x00\x00\x00\x00\x00\x00\x00\x00'



