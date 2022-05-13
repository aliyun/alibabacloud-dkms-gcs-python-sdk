# coding=utf-8
from Tea.model import TeaModel


class Config(TeaModel):
    def __init__(
            self,
            access_key_id=None,
            private_key=None,
            endpoint=None,
            protocol=None,
            region_id=None,
            read_timeout=None,
            connect_timeout=None,
            http_proxy=None,
            https_proxy=None,
            socks_5proxy=None,
            socks_5net_work=None,
            no_proxy=None,
            max_idle_conns=None,
            user_agent=None,
            type=None,
            credential=None,
            client_key_file=None,
            client_key_content=None,
            password=None,
    ):
        self.access_key_id = access_key_id
        # pkcs1 or pkcs8 PEM format private key
        self.private_key = private_key
        # crypto service address
        self.endpoint = endpoint
        self.protocol = protocol
        self.region_id = region_id
        self.read_timeout = read_timeout
        self.connect_timeout = connect_timeout
        self.http_proxy = http_proxy
        self.https_proxy = https_proxy
        self.socks_5proxy = socks_5proxy
        self.socks_5net_work = socks_5net_work
        self.no_proxy = no_proxy
        self.max_idle_conns = max_idle_conns
        self.user_agent = user_agent
        self.type = type
        self.credential = credential
        self.client_key_file = client_key_file
        # client key content
        self.client_key_content = client_key_content
        self.password = password

    def validate(self):
        if self.region_id is not None:
            self.validate_pattern(self.region_id, 'region_id', '[a-zA-Z0-9-_]+')

    def to_map(self):
        _map = super(Config, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.access_key_id is not None:
            result['accessKeyId'] = self.access_key_id
        if self.private_key is not None:
            result['privateKey'] = self.private_key
        if self.endpoint is not None:
            result['endpoint'] = self.endpoint
        if self.protocol is not None:
            result['protocol'] = self.protocol
        if self.region_id is not None:
            result['regionId'] = self.region_id
        if self.read_timeout is not None:
            result['readTimeout'] = self.read_timeout
        if self.connect_timeout is not None:
            result['connectTimeout'] = self.connect_timeout
        if self.http_proxy is not None:
            result['httpProxy'] = self.http_proxy
        if self.https_proxy is not None:
            result['httpsProxy'] = self.https_proxy
        if self.socks_5proxy is not None:
            result['socks5Proxy'] = self.socks_5proxy
        if self.socks_5net_work is not None:
            result['socks5NetWork'] = self.socks_5net_work
        if self.no_proxy is not None:
            result['noProxy'] = self.no_proxy
        if self.max_idle_conns is not None:
            result['maxIdleConns'] = self.max_idle_conns
        if self.user_agent is not None:
            result['userAgent'] = self.user_agent
        if self.type is not None:
            result['type'] = self.type
        if self.credential is not None:
            result['credential'] = self.credential
        if self.client_key_file is not None:
            result['clientKeyFile'] = self.client_key_file
        if self.client_key_content is not None:
            result['clientKeyContent'] = self.client_key_content
        if self.password is not None:
            result['password'] = self.password
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('accessKeyId') is not None:
            self.access_key_id = m.get('accessKeyId')
        if m.get('privateKey') is not None:
            self.private_key = m.get('privateKey')
        if m.get('endpoint') is not None:
            self.endpoint = m.get('endpoint')
        if m.get('protocol') is not None:
            self.protocol = m.get('protocol')
        if m.get('regionId') is not None:
            self.region_id = m.get('regionId')
        if m.get('readTimeout') is not None:
            self.read_timeout = m.get('readTimeout')
        if m.get('connectTimeout') is not None:
            self.connect_timeout = m.get('connectTimeout')
        if m.get('httpProxy') is not None:
            self.http_proxy = m.get('httpProxy')
        if m.get('httpsProxy') is not None:
            self.https_proxy = m.get('httpsProxy')
        if m.get('socks5Proxy') is not None:
            self.socks_5proxy = m.get('socks5Proxy')
        if m.get('socks5NetWork') is not None:
            self.socks_5net_work = m.get('socks5NetWork')
        if m.get('noProxy') is not None:
            self.no_proxy = m.get('noProxy')
        if m.get('maxIdleConns') is not None:
            self.max_idle_conns = m.get('maxIdleConns')
        if m.get('userAgent') is not None:
            self.user_agent = m.get('userAgent')
        if m.get('type') is not None:
            self.type = m.get('type')
        if m.get('credential') is not None:
            self.credential = m.get('credential')
        if m.get('clientKeyFile') is not None:
            self.client_key_file = m.get('clientKeyFile')
        if m.get('clientKeyContent') is not None:
            self.client_key_content = m.get('clientKeyContent')
        if m.get('password') is not None:
            self.password = m.get('password')
        return self


class ResponseEntity(object):

    def __init__(self, body_bytes, response_headers):
        self.body_bytes = body_bytes
        self.response_headers = response_headers
