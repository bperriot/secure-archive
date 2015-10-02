
from layer import GenericLayerWriter



class ErrorCorrectingLayerWriter(GenericLayerWriter):
    def __init__(self, encoding=0, encoding_param=None, data=''):
        super(ErrorCorrectingLayerWriter, self).__init__(
            encoding, encoding_param, data)
        self.layer_id = 1


