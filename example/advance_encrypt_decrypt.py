# -*- coding: utf-8 -*-
import os

from openapi.models import Config
from openapi_util.models import RuntimeOptions
from sdk.client import Client
from sdk.models import AdvanceEncryptRequest, AdvanceDecryptRequest

config = Config()
config.protocol = "https"
config.client_key_file = "<your-client-key-file>"
config.password = os.getenv('CLIENT_KEY_PASSWORD')
config.endpoint = "<your-endpoint>"
client = Client(config)


class AdvanceEncryptContext(object):
    """The advance encrypt context may be stored."""

    def __init__(self, key_id, ciphertext_blob, iv, algorithm):
        self.key_id = key_id
        self.ciphertext_blob = ciphertext_blob
        self.iv = iv
        # Use default algorithm value,if the value is not set.
        self.algorithm = algorithm


def advance_encrypt(key_id, plaintext):
    request = AdvanceEncryptRequest()
    request.plaintext = plaintext
    request.key_id = key_id
    runtime_options = RuntimeOptions()
    # ignore ssl
    # runtime_options.ignore_ssl = True
    # the param verify is ca certificate file path
    runtime_options.verify = "<your-ca-certificate-file-path>"
    resp = client.advance_encrypt_with_options(request, runtime_options)
    print(resp)
    return AdvanceEncryptContext(resp.key_id, resp.ciphertext_blob, resp.iv, resp.algorithm)


def advance_decrypt(context):
    request = AdvanceDecryptRequest()
    request.ciphertext_blob = context.ciphertext_blob
    request.key_id = context.key_id
    request.iv = context.iv
    request.algorithm = context.algorithm
    runtime_options = RuntimeOptions()
    # ignore ssl
    # runtime_options.ignore_ssl = True
    # the param verify is ca certificate file path
    runtime_options.verify = "<your-ca-certificate-file-path>"
    resp = client.advance_decrypt_with_options(request, runtime_options)
    print(resp)


plaintext = "<your-plaintext>".encode("utf-8")
key_id = "<your-key-id>"
context = advance_encrypt(key_id, plaintext)
advance_decrypt(context)
