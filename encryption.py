#!/usr/bin/env python
# -*- coding: utf-8 -*-

from layer import GenericLayerWriter
from layer import GenericLayerReader


class EncryptionLayerWriter(GenericLayerWriter):
    def __init__(self, encoding=0, encoding_param=None, data=''):
        super(EncryptionLayerWriter, self).__init__(
            encoding, encoding_param, data)
        self.layer_id = 2


class EncryptionLayerReader(GenericLayerReader):
    def __init__(self, data):
        super(EncryptionLayerReader, self).__init__(data)


