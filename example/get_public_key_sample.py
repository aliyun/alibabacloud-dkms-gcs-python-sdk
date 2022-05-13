# -*- coding: utf-8 -*-

from openapi.models import Config
from openapi_util.models import RuntimeOptions
from sdk.client import Client
from sdk.models import GetPublicKeyRequest

config = Config()
config.protocol = "https"
config.client_key_file = "<your-client-key-file>"
config.password = "<your-password>"
config.endpoint = "<your-endpoint>"
client = Client(config)


def get_public_key(key_id):
    request = GetPublicKeyRequest()
    request.key_id = key_id
    runtime_options = RuntimeOptions()
    # ignore ssl
    # runtime_options.ignore_ssl = True
    # the param verify is ca certificate file path
    runtime_options.verify = "<your-ca-certificate-file-path>"
    resp = client.get_public_key_with_options(request, runtime_options)
    print(resp)


key_id = "<your-key-id>"
get_public_key(key_id)
