class LayerNotDoneException(Exception):
    def __init__(self, layer, *args: object) -> None:
        super().__init__(*args)
        self.error_layer = layer

    def __str__(self):
        return "{} has not define,it has \n{}".format(self.error_layer.layer_name,
                                                      ','.join(self.error_layer.field_names))
