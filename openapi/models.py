# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
from Tea.model import TeaModel

from openapi_credential.client import Client as DedicatedKmsOpenapiCredentialClient


class Config(TeaModel):
    def __init__(
            self,
            access_key_id: str = None,
            private_key: str = None,
            endpoint: str = None,
            protocol: str = None,
            region_id: str = None,
            read_timeout: int = None,
            connect_timeout: int = None,
            http_proxy: str = None,
            https_proxy: str = None,
            no_proxy: str = None,
            max_idle_conns: int = None,
            socks_5proxy: str = None,
            socks_5net_work: str = None,
            type: str = None,
            user_agent: str = None,
            credential: DedicatedKmsOpenapiCredentialClient = None,
            client_key_file: str = None,
            client_key_content: str = None,
            password: str = None,
            ca_file_path: str = None,
            ignore_ssl: bool = None,
    ):
        # 访问凭证ID
        self.access_key_id = access_key_id
        # pkcs1 或 pkcs8 PEM 格式私钥
        self.private_key = private_key
        # 实例地址
        self.endpoint = endpoint
        # 协议
        self.protocol = protocol
        # 区域标识
        self.region_id = region_id
        # 读取超时时间
        self.read_timeout = read_timeout
        # 连接超时时间
        self.connect_timeout = connect_timeout
        # http代理
        self.http_proxy = http_proxy
        # https代理
        self.https_proxy = https_proxy
        # 无代理
        self.no_proxy = no_proxy
        # 最大闲置连接数
        self.max_idle_conns = max_idle_conns
        # socks5代理
        self.socks_5proxy = socks_5proxy
        # socks5代理协议
        self.socks_5net_work = socks_5net_work
        # 访问凭证类型
        self.type = type
        # 用户代理
        self.user_agent = user_agent
        # 访问凭证
        self.credential = credential
        # ClientKey文件路径
        self.client_key_file = client_key_file
        # ClientKey文件内容
        self.client_key_content = client_key_content
        # ClientKey密码
        self.password = password
        # ca证书文件路径
        self.ca_file_path = ca_file_path
        # 是否忽略SSL认证
        self.ignore_ssl = ignore_ssl

    def validate(self):
        if self.region_id is not None:
            self.validate_pattern(self.region_id, 'region_id', '[a-zA-Z0-9-_]+')
        self.validate_required(self.type, 'type')

    def to_map(self):
        _map = super().to_map()
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
        if self.no_proxy is not None:
            result['noProxy'] = self.no_proxy
        if self.max_idle_conns is not None:
            result['maxIdleConns'] = self.max_idle_conns
        if self.socks_5proxy is not None:
            result['socks5Proxy'] = self.socks_5proxy
        if self.socks_5net_work is not None:
            result['socks5NetWork'] = self.socks_5net_work
        if self.type is not None:
            result['type'] = self.type
        if self.user_agent is not None:
            result['userAgent'] = self.user_agent
        if self.credential is not None:
            result['credential'] = self.credential
        if self.client_key_file is not None:
            result['clientKeyFile'] = self.client_key_file
        if self.client_key_content is not None:
            result['clientKeyContent'] = self.client_key_content
        if self.password is not None:
            result['password'] = self.password
        if self.ca_file_path is not None:
            result['caFilePath'] = self.ca_file_path
        if self.ignore_ssl is not None:
            result['ignoreSSL'] = self.ignore_ssl
        return result

    def from_map(self, m: dict = None):
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
        if m.get('noProxy') is not None:
            self.no_proxy = m.get('noProxy')
        if m.get('maxIdleConns') is not None:
            self.max_idle_conns = m.get('maxIdleConns')
        if m.get('socks5Proxy') is not None:
            self.socks_5proxy = m.get('socks5Proxy')
        if m.get('socks5NetWork') is not None:
            self.socks_5net_work = m.get('socks5NetWork')
        if m.get('type') is not None:
            self.type = m.get('type')
        if m.get('userAgent') is not None:
            self.user_agent = m.get('userAgent')
        if m.get('credential') is not None:
            self.credential = m.get('credential')
        if m.get('clientKeyFile') is not None:
            self.client_key_file = m.get('clientKeyFile')
        if m.get('clientKeyContent') is not None:
            self.client_key_content = m.get('clientKeyContent')
        if m.get('password') is not None:
            self.password = m.get('password')
        if m.get('caFilePath') is not None:
            self.ca_file_path = m.get('caFilePath')
        if m.get('ignoreSSL') is not None:
            self.ignore_ssl = m.get('ignoreSSL')
        return self
