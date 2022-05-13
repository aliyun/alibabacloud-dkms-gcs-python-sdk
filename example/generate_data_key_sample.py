# -*- coding: utf-8 -*-

from openapi.models import Config
from openapi_util.models import RuntimeOptions
from sdk.client import Client
from sdk.models import GenerateDataKeyRequest

config = Config()
config.protocol = "https"
config.client_key_file = "<your-client-key-file>"
config.password = "<your-password>"
config.endpoint = "<your-endpoint>"
client = Client(config)


def generate_data_key(key_id, number_of_bytes):
    request = GenerateDataKeyRequest()
    request.key_id = key_id
    request.number_of_bytes = number_of_bytes
    runtime_options = RuntimeOptions()
    # ignore ssl
    # runtime_options.ignore_ssl = True
    # the param verify is ca certificate file path
    runtime_options.verify = "<your-ca-certificate-file-path>"
    resp = client.generate_data_key_with_options(request, runtime_options)
    print(resp)


key_id = "<your-key-id>"
number_of_bytes = "<your-number-of-bytes>"
generate_data_key(key_id, number_of_bytes)
