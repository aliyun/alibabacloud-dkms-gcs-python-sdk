# -*- coding: utf-8 -*-
import base64

from openapi.models import Config
from openapi_util.models import RuntimeOptions
from sdk.client import Client
from sdk.models import SignRequest, VerifyRequest

config = Config()
config.protocol = "https"
config.client_key_file = "<your-client-key-file>"
config.password = "<your-password>"
config.endpoint = "<your-endpoint>"
client = Client(config)


class SignContext(object):
    """The sign context may be stored."""

    def __init__(self, key_id, message_type, signature, algorithm):
        self.key_id = key_id
        self.message_type = message_type
        self.signature = signature
        # Use default algorithm value,if the value is not set.
        self.algorithm = algorithm


def sign(key_id, message, message_type, algorithm):
    request = SignRequest()
    request.key_id = key_id
    request.message = message
    request.message_type = message_type
    request.algorithm = algorithm
    runtime_options = RuntimeOptions()
    # ignore ssl
    # runtime_options.ignore_ssl = True
    # the param verify is ca certificate file path
    runtime_options.verify = "<your-ca-certificate-file-path>"
    resp = client.sign_with_options(request, runtime_options)
    print(resp)
    return SignContext(resp.key_id, resp.message_type, resp.signature, resp.algorithm)


def verify(context, message):
    request = VerifyRequest()
    request.key_id = context.key_id
    request.message_type = context.message_type
    request.signature = context.signature
    request.algorithm = context.algorithm
    request.message = message
    runtime_options = RuntimeOptions()
    # ignore ssl
    # runtime_options.ignore_ssl = True
    # the param verify is ca certificate file path
    runtime_options.verify = "<your-ca-certificate-file-path>"
    resp = client.verify_with_options(request, runtime_options)
    print(resp)


key_id = "<your-key-id>"
algorithm = "<your-algorithm>"
message = "<your-message>".encode("utf-8")
# RAW-原始消息，DIGEST-摘要
message_type = "RAW"
context = sign(key_id, message, message_type, algorithm)
verify(context, message)
