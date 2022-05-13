# coding=utf-8
# This file is auto-generated, don't edit it. Thanks.
import time

from Tea.exceptions import TeaException, UnretryableException
from Tea.request import TeaRequest
from Tea.core import TeaCore

from openapi_credential.client import Client as DedicatedKmsOpenapiCredentialClient
from alibabacloud_tea_util.client import Client as UtilClient
from openapi_credential import models as dedicated_kms_openapi_credential_models
from openapi.models import ResponseEntity
from openapi_util.client import Client as DedicatedKmsOpenapiUtilClient


class Client(object):
    _endpoint = None
    _region_id = None
    _protocol = None
    _read_timeout = None
    _connect_timeout = None
    _http_proxy = None
    _https_proxy = None
    _no_proxy = None
    _user_agent = None
    _socks_5proxy = None
    _socks_5net_work = None
    _max_idle_conns = None
    _credential = None

    def __init__(
            self,
            config,
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

    def do_request(
            self,
            api_name,
            api_version,
            protocol,
            method,
            signature_method,
            req_body_bytes,
            runtime,
            request_headers,
    ):
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
                'retryable': runtime.autoretry,
                'maxAttempts': UtilClient.default_number(runtime.max_attempts, 3)
            },
            'backoff': {
                'policy': UtilClient.default_string(runtime.backoff_policy, 'no'),
                'period': UtilClient.default_number(runtime.backoff_period, 1)
            },
            'ignoreSSL': runtime.ignore_ssl,
            'ca': runtime.verify
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
                _request.headers = {
                    'accept': 'application/x-protobuf',
                    'host': DedicatedKmsOpenapiUtilClient.get_host(self._region_id, self._endpoint),
                    'date': UtilClient.get_date_utcstring(),
                    'user-agent': UtilClient.get_user_agent(self._user_agent),
                    'x-kms-apiversion': api_version,
                    'x-kms-apiname': api_name,
                    'x-kms-signaturemethod': signature_method,
                    'x-kms-acccesskeyid': self._credential.get_access_key_id()
                }
                if not request_headers:
                    request_headers = {}
                request_headers.update(_request.headers)
                _request.headers = request_headers
                _request.headers['content-type'] = 'application/x-protobuf'
                _request.headers['content-length'] = DedicatedKmsOpenapiUtilClient.get_content_length(req_body_bytes)
                _request.headers['content-sha256'] = DedicatedKmsOpenapiUtilClient.get_content_sha256(req_body_bytes)
                _request.body = req_body_bytes
                str_to_sign = DedicatedKmsOpenapiUtilClient.get_string_to_sign(_request)
                _request.headers['authorization'] = self._credential.get_signature(str_to_sign)
                _last_request = _request
                _response = TeaCore.do_action(_request, _runtime)
                body_bytes = None
                if UtilClient.is_4xx(_response.status_code) or UtilClient.is_5xx(_response.status_code):
                    body_bytes = UtilClient.read_as_bytes(_response.body)
                    resp_map = DedicatedKmsOpenapiUtilClient.get_err_message(body_bytes)
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
                response_headers = None
                if runtime.response_headers:
                    response_headers = {}
                    for response_header in runtime.response_headers:
                        response_headers[response_header] = _response.headers.get(response_header)
                resp_entity = ResponseEntity(body_bytes, response_headers)
                return resp_entity
            except Exception as e:
                if TeaCore.is_retryable(e):
                    _last_exception = e
                    continue
                raise e
        raise UnretryableException(_last_request, _last_exception)
