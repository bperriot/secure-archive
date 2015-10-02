
from layer import GenericLayerWriter



class EncryptionLayerWriter(GenericLayerWriter):
    def __init__(self, encoding=0, encoding_param=None, data=''):
        super(EncryptionLayerWriter, self).__init__(
            encoding, encoding_param, data)
        self.layer_id = 2


