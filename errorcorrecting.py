#!/usr/bin/env python
# -*- coding: utf-8 -*-

from layer import GenericLayerWriter
from layer import GenericLayerReader


class ErrorCorrectingLayerWriter(GenericLayerWriter):
    def __init__(self, encoding=0, encoding_param=None, data=''):
        super(ErrorCorrectingLayerWriter, self).__init__(
            encoding, encoding_param, data)
        self.layer_id = 1


class ErrorCorrectingLayerReader(GenericLayerReader):
    def __init__(self, data=''):
        super(ErrorCorrectingLayerReader, self).__init__(data)


