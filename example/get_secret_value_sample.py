# -*- coding: utf-8 -*-

from openapi.models import Config
from openapi_util.models import RuntimeOptions
from sdk.client import Client
from sdk.models import GetSecretValueRequest

config = Config()
config.protocol = "https"
config.client_key_file = "<your-client-key-file>"
config.password = "<your-password>"
config.endpoint = "<your-endpoint>"
client = Client(config)


def get_secret_value(secret_name):
    request = GetSecretValueRequest()
    request.secret_name = secret_name
    runtime_options = RuntimeOptions()
    # ignore ssl
    # runtime_options.ignore_ssl = True
    # the param verify is ca certificate file path
    runtime_options.verify = "<your-ca-certificate-file-path>"
    resp = client.get_secret_value_with_options(request, runtime_options)
    print(resp)


secret_name = "<your-secret-name>"
get_secret_value(secret_name)
