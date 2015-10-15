#!/usr/bin/env python
# -*- coding: utf-8 -*-

from blocks import BlockWriter


class ArchiveWriter(object):

    def __init__(self, secret=''):
        self.blocks = [
            BlockWriter(0,
                        encryption={'encoding': 'none',
                                    'param': {'secret': 'abc'}},
                        errorcorrecting={'encoding': 'none'},
                        compression={'encoding': 'none'})]

    def add(self, key, metadata, data):

        last_block = self.blocks[-1]

        if last_block.size_estimate() > 10*1024*1024:
            self.blocks.append(BlockWriter(
                last_block.id + 1,
                encryption={'encoding': 'none', 'param': {'secret': 'abc'}},
                errorcorrecting={'encoding': 'none'},
                compression={'encoding': 'none'}))
            last_block = self.blocks[-1]

        last_block.add_entry(key, metadata, data)

    def flush(self, file_):
        for block in self.blocks:
            block.flush(file_)


