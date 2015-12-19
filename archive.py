#!/usr/bin/env python
# -*- coding: utf-8 -*-

from blocks import BlockWriter

max_block_size = 10*1024*1024


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

        if (last_block.size_estimate() + len(data) > max_block_size and
                not last_block.is_empty()):
            self.blocks.append(BlockWriter(
                last_block.id + 1,
                encryption={'encoding': 'none', 'param': {'secret': 'abc'}},
                errorcorrecting={'encoding': 'none'},
                compression={'encoding': 'none'}))
            last_block = self.blocks[-1]

        if len(data) <= max_block_size:
            last_block.add_entry(key, metadata, data)
        else:
            new_blocks = [
                BlockWriter(last_block.id + 1 + i,
                            encryption={'encoding': 'none',
                                        'param': {'secret': 'abc'}},
                            errorcorrecting={'encoding': 'none'},
                            compression={'encoding': 'none'})
                for i in xrange((len(data) - 1) / max_block_size)]
            self.blocks.extend(new_blocks)

            multiparts = [last_block.id]
            multiparts.extend([block.id for block in new_blocks])

            last_block.add_entry(key, metadata, data[:max_block_size],
                                 len(data), multiparts)

            new_blocks_iter = iter(new_blocks)

            offset = max_block_size
            while offset < len(data):
                current_block = new_blocks_iter.next()

                part = data[offset:offset+max_block_size]
                offset += len(part)

                current_block.add_entry(key, {}, part, len(data), multiparts)


    def flush(self, file_):
        for block in self.blocks:
            block.flush(file_)


