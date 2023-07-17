class DataResponse:
    def __init__(self, success, data):
        self.success = success
        self.data = data

    def to_dict(self):
        return {'success': self.success, 'data': self.data}