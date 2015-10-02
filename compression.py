
from layer import GenericLayerWriter



class CompressionLayerWriter(GenericLayerWriter):
    def __init__(self, encoding=0, encoding_param=None, data=''):
        super(CompressionLayerWriter, self).__init__(
            encoding, encoding_param, data)
        self.layer_id = 3


