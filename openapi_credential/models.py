# coding=utf-8
# This file is auto-generated, don't edit it. Thanks.
from Tea.model import TeaModel


class Config(TeaModel):
    def __init__(
            self,
            type=None,
            access_key_id=None,
            private_key=None,
            client_key_file=None,
            client_key_content=None,
            password=None,
    ):
        self.type = type
        self.access_key_id = access_key_id
        self.private_key = private_key
        self.client_key_file = client_key_file
        self.client_key_content = client_key_content
        self.password = password

    def validate(self):
        self.validate_required(self.type, 'type')

    def to_map(self):
        _map = super(Config, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.type is not None:
            result['type'] = self.type
        if self.access_key_id is not None:
            result['accessKeyId'] = self.access_key_id
        if self.private_key is not None:
            result['privateKey'] = self.private_key
        if self.client_key_file is not None:
            result['clientKeyFile'] = self.client_key_file
        if self.client_key_content is not None:
            result['clientKeyContent'] = self.client_key_content
        if self.password is not None:
            result['password'] = self.password
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('type') is not None:
            self.type = m.get('type')
        if m.get('accessKeyId') is not None:
            self.access_key_id = m.get('accessKeyId')
        if m.get('privateKey') is not None:
            self.private_key = m.get('privateKey')
        if m.get('clientKeyFile') is not None:
            self.client_key_file = m.get('clientKeyFile')
        if m.get('clientKeyContent') is not None:
            self.client_key_content = m.get('clientKeyContent')
        if m.get('password') is not None:
            self.password = m.get('password')
        return self


class ClientKey(TeaModel):
    def __init__(
            self,
            key_id=None,
            private_key_data=None,
    ):
        self.key_id = key_id
        self.private_key_data = private_key_data

    def validate(self):
        pass

    def to_map(self):
        _map = super(ClientKey, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.private_key_data is not None:
            result['PrivateKeyData'] = self.private_key_data
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('PrivateKeyData') is not None:
            self.private_key_data = m.get('PrivateKeyData')
        return self
