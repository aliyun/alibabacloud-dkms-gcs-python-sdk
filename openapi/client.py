# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
import time

from Tea.exceptions import TeaException, UnretryableException
from Tea.request import TeaRequest
from Tea.core import TeaCore
from typing import Dict, Any

from openapi_credential.client import Client as DedicatedKmsOpenapiCredentialClient
from openapi import models as dedicated_kms_openapi_models
from alibabacloud_tea_util.client import Client as UtilClient
from openapi_credential import models as dedicated_kms_openapi_credential_models
from openapi_util import models as dedicated_kms_openapi_util_models
from openapi_util.client import Client as DedicatedKmsOpenapiUtilClient
from alibabacloud_darabonba_string.client import Client as StringClient
from alibabacloud_openapi_util.client import Client as OpenApiUtilClient
from alibabacloud_darabonba_map.client import Client as MapClient
from alibabacloud_darabonba_array.client import Client as ArrayClient


class Client:
    _endpoint: str = None
    _region_id: str = None
    _protocol: str = None
    _read_timeout: int = None
    _connect_timeout: int = None
    _http_proxy: str = None
    _https_proxy: str = None
    _no_proxy: str = None
    _user_agent: str = None
    _socks_5proxy: str = None
    _socks_5net_work: str = None
    _max_idle_conns: int = None
    _credential: DedicatedKmsOpenapiCredentialClient = None
    _ca_file_path: str = None
    _ignore_ssl: bool = None

    def __init__(
            self,
            config: dedicated_kms_openapi_models.Config,
    ):
        if UtilClient.is_unset(config):
            raise TeaException({
                'name': 'ParameterMissing',
                'message': "'config' can not be unset"
            })
        if UtilClient.empty(config.endpoint):
            raise TeaException({
                'code': 'ParameterMissing',
                'message': "'config.endpoint' can not be empty"
            })
        if not UtilClient.empty(config.client_key_content):
            config.type = 'rsa_key_pair'
            content_config = dedicated_kms_openapi_credential_models.Config(
                type=config.type,
                client_key_content=config.client_key_content,
                password=config.password
            )
            self._credential = DedicatedKmsOpenapiCredentialClient(content_config)
        elif not UtilClient.empty(config.client_key_file):
            config.type = 'rsa_key_pair'
            client_key_config = dedicated_kms_openapi_credential_models.Config(
                type=config.type,
                client_key_file=config.client_key_file,
                password=config.password
            )
            self._credential = DedicatedKmsOpenapiCredentialClient(client_key_config)
        elif not UtilClient.empty(config.access_key_id) and not UtilClient.empty(config.private_key):
            config.type = 'rsa_key_pair'
            credential_config = dedicated_kms_openapi_credential_models.Config(
                type=config.type,
                access_key_id=config.access_key_id,
                private_key=config.private_key
            )
            self._credential = DedicatedKmsOpenapiCredentialClient(credential_config)
        elif not UtilClient.is_unset(config.credential):
            self._credential = config.credential
        if not UtilClient.is_unset(config.ca_file_path):
            self._ca_file_path = config.ca_file_path
        self._endpoint = config.endpoint
        self._protocol = config.protocol
        self._region_id = config.region_id
        self._user_agent = config.user_agent
        self._read_timeout = config.read_timeout
        self._connect_timeout = config.connect_timeout
        self._http_proxy = config.http_proxy
        self._https_proxy = config.https_proxy
        self._no_proxy = config.no_proxy
        self._socks_5proxy = config.socks_5proxy
        self._socks_5net_work = config.socks_5net_work
        self._max_idle_conns = config.max_idle_conns
        self._ignore_ssl = config.ignore_ssl

    def do_request(
            self,
            api_name: str,
            api_version: str,
            protocol: str,
            method: str,
            signature_method: str,
            req_body_bytes: bytes,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
            request_headers: Dict[str, str],
    ) -> Dict[str, Any]:
        runtime.validate()
        _runtime = {
            'timeouted': 'retry',
            'readTimeout': UtilClient.default_number(runtime.read_timeout, self._read_timeout),
            'connectTimeout': UtilClient.default_number(runtime.connect_timeout, self._connect_timeout),
            'httpProxy': UtilClient.default_string(runtime.http_proxy, self._http_proxy),
            'httpsProxy': UtilClient.default_string(runtime.https_proxy, self._https_proxy),
            'noProxy': UtilClient.default_string(runtime.no_proxy, self._no_proxy),
            'socks5Proxy': UtilClient.default_string(runtime.socks_5proxy, self._socks_5proxy),
            'socks5NetWork': UtilClient.default_string(runtime.socks_5net_work, self._socks_5net_work),
            'maxIdleConns': UtilClient.default_number(runtime.max_idle_conns, self._max_idle_conns),
            'retry': {
                'retryable': DedicatedKmsOpenapiUtilClient.default_boolean(runtime.autoretry, True),
                'maxAttempts': UtilClient.default_number(runtime.max_attempts, 3)
            },
            'backoff': {
                'policy': UtilClient.default_string(runtime.backoff_policy, 'yes'),
                'period': UtilClient.default_number(runtime.backoff_period, 1)
            },
            'ignoreSSL': DedicatedKmsOpenapiUtilClient.default_boolean(self._ignore_ssl, runtime.ignore_ssl),
            'ca': UtilClient.default_string(self._ca_file_path, runtime.verify)
        }
        _last_request = None
        _last_exception = None
        _now = time.time()
        _retry_times = 0
        while TeaCore.allow_retry(_runtime.get('retry'), _retry_times, _now):
            if _retry_times > 0:
                _backoff_time = TeaCore.get_backoff_time(_runtime.get('backoff'), _retry_times)
                if _backoff_time > 0:
                    TeaCore.sleep(_backoff_time)
            _retry_times = _retry_times + 1
            try:
                _request = TeaRequest()
                _request.protocol = UtilClient.default_string(self._protocol, protocol)
                _request.method = method
                _request.pathname = '/'
                _request.headers = TeaCore.merge(request_headers)
                _request.headers['accept'] = 'application/x-protobuf'
                _request.headers['host'] = self._endpoint
                _request.headers['date'] = UtilClient.get_date_utcstring()
                _request.headers['user-agent'] = UtilClient.get_user_agent(self._user_agent)
                _request.headers['x-kms-apiversion'] = api_version
                _request.headers['x-kms-apiname'] = api_name
                _request.headers['x-kms-signaturemethod'] = signature_method
                _request.headers['x-kms-acccesskeyid'] = self._credential.get_access_key_id()
                _request.headers['content-type'] = 'application/x-protobuf'
                _request.headers['content-length'] = DedicatedKmsOpenapiUtilClient.get_content_length(req_body_bytes)
                _request.headers['content-sha256'] = StringClient.to_upper(
                    OpenApiUtilClient.hex_encode(OpenApiUtilClient.hash(req_body_bytes, 'ACS3-RSA-SHA256')))
                _request.body = req_body_bytes
                str_to_sign = DedicatedKmsOpenapiUtilClient.get_string_to_sign(method, _request.pathname,
                                                                               _request.headers, _request.query)
                _request.headers['authorization'] = self._credential.get_signature(str_to_sign)
                _last_request = _request
                _response = TeaCore.do_action(_request, _runtime)
                body_bytes = None
                if UtilClient.is_4xx(_response.status_code) or UtilClient.is_5xx(_response.status_code):
                    body_bytes = UtilClient.read_as_bytes(_response.body)
                    resp_map = UtilClient.assert_as_map(DedicatedKmsOpenapiUtilClient.get_err_message(body_bytes))
                    raise TeaException({
                        'code': resp_map.get('Code'),
                        'message': resp_map.get('Message'),
                        'data': {
                            'httpCode': _response.status_code,
                            'requestId': resp_map.get('RequestId'),
                            'hostId': resp_map.get('HostId')
                        }
                    })
                body_bytes = UtilClient.read_as_bytes(_response.body)
                response_headers = {}
                headers = _response.headers
                if not UtilClient.is_unset(runtime.response_headers):
                    for key in MapClient.key_set(headers):
                        if ArrayClient.contains(runtime.response_headers, key):
                            response_headers[key] = headers.get(key)
                return {
                    'bodyBytes': body_bytes,
                    'responseHeaders': response_headers
                }
            except Exception as e:
                if TeaCore.is_retryable(e) or (
                        isinstance(e, TeaException) and DedicatedKmsOpenapiUtilClient.is_retry_err(e)):
                    _last_exception = e
                    continue
                raise e
        raise UnretryableException(_last_request, _last_exception)

    async def do_request_async(
            self,
            api_name: str,
            api_version: str,
            protocol: str,
            method: str,
            signature_method: str,
            req_body_bytes: bytes,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
            request_headers: Dict[str, str],
    ) -> Dict[str, Any]:
        runtime.validate()
        _runtime = {
            'timeouted': 'retry',
            'readTimeout': UtilClient.default_number(runtime.read_timeout, self._read_timeout),
            'connectTimeout': UtilClient.default_number(runtime.connect_timeout, self._connect_timeout),
            'httpProxy': UtilClient.default_string(runtime.http_proxy, self._http_proxy),
            'httpsProxy': UtilClient.default_string(runtime.https_proxy, self._https_proxy),
            'noProxy': UtilClient.default_string(runtime.no_proxy, self._no_proxy),
            'socks5Proxy': UtilClient.default_string(runtime.socks_5proxy, self._socks_5proxy),
            'socks5NetWork': UtilClient.default_string(runtime.socks_5net_work, self._socks_5net_work),
            'maxIdleConns': UtilClient.default_number(runtime.max_idle_conns, self._max_idle_conns),
            'retry': {
                'retryable': DedicatedKmsOpenapiUtilClient.default_boolean(runtime.autoretry, True),
                'maxAttempts': UtilClient.default_number(runtime.max_attempts, 3)
            },
            'backoff': {
                'policy': UtilClient.default_string(runtime.backoff_policy, 'yes'),
                'period': UtilClient.default_number(runtime.backoff_period, 1)
            },
            'ignoreSSL': DedicatedKmsOpenapiUtilClient.default_boolean(self._ignore_ssl, runtime.ignore_ssl),
            'ca': UtilClient.default_string(self._ca_file_path, runtime.verify)
        }
        _last_request = None
        _last_exception = None
        _now = time.time()
        _retry_times = 0
        while TeaCore.allow_retry(_runtime.get('retry'), _retry_times, _now):
            if _retry_times > 0:
                _backoff_time = TeaCore.get_backoff_time(_runtime.get('backoff'), _retry_times)
                if _backoff_time > 0:
                    TeaCore.sleep(_backoff_time)
            _retry_times = _retry_times + 1
            try:
                _request = TeaRequest()
                _request.protocol = UtilClient.default_string(self._protocol, protocol)
                _request.method = method
                _request.pathname = '/'
                _request.headers = TeaCore.merge(request_headers)
                _request.headers['accept'] = 'application/x-protobuf'
                _request.headers['host'] = self._endpoint
                _request.headers['date'] = UtilClient.get_date_utcstring()
                _request.headers['user-agent'] = UtilClient.get_user_agent(self._user_agent)
                _request.headers['x-kms-apiversion'] = api_version
                _request.headers['x-kms-apiname'] = api_name
                _request.headers['x-kms-signaturemethod'] = signature_method
                _request.headers['x-kms-acccesskeyid'] = self._credential.get_access_key_id()
                _request.headers['content-type'] = 'application/x-protobuf'
                _request.headers['content-length'] = DedicatedKmsOpenapiUtilClient.get_content_length(req_body_bytes)
                _request.headers['content-sha256'] = StringClient.to_upper(
                    OpenApiUtilClient.hex_encode(OpenApiUtilClient.hash(req_body_bytes, 'ACS3-RSA-SHA256')))
                _request.body = req_body_bytes
                str_to_sign = DedicatedKmsOpenapiUtilClient.get_string_to_sign(method, _request.pathname,
                                                                               _request.headers, _request.query)
                _request.headers['authorization'] = self._credential.get_signature(str_to_sign)
                _last_request = _request
                _response = await TeaCore.async_do_action(_request, _runtime)
                body_bytes = None
                if UtilClient.is_4xx(_response.status_code) or UtilClient.is_5xx(_response.status_code):
                    body_bytes = await UtilClient.read_as_bytes_async(_response.body)
                    resp_map = UtilClient.assert_as_map(DedicatedKmsOpenapiUtilClient.get_err_message(body_bytes))
                    raise TeaException({
                        'code': resp_map.get('Code'),
                        'message': resp_map.get('Message'),
                        'data': {
                            'httpCode': _response.status_code,
                            'requestId': resp_map.get('RequestId'),
                            'hostId': resp_map.get('HostId')
                        }
                    })
                body_bytes = await UtilClient.read_as_bytes_async(_response.body)
                response_headers = {}
                headers = _response.headers
                if not UtilClient.is_unset(runtime.response_headers):
                    for key in MapClient.key_set(headers):
                        if ArrayClient.contains(runtime.response_headers, key):
                            response_headers[key] = headers.get(key)
                return {
                    'bodyBytes': body_bytes,
                    'responseHeaders': response_headers
                }
            except Exception as e:
                if TeaCore.is_retryable(e) or (
                        isinstance(e, TeaException) and DedicatedKmsOpenapiUtilClient.is_retry_err(e)):
                    _last_exception = e
                    continue
                raise e
        raise UnretryableException(_last_request, _last_exception)
