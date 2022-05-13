# coding=utf-8
import json

from openapi_credential.auth.credentials import RsaKeyPairCredential
from openapi_credential.auth.signer import get_signer
from openapi_credential.utils import json_utils, credential_utils


class Client(object):

    def __init__(
            self,
            config,
    ):

        if "rsa_key_pair" is config.type:
            if config.client_key_content:
                client_key_dict = json.loads(config.client_key_content)
            elif config.client_key_file:
                client_key_dict = json_utils.load(config.client_key_file)
            else:
                self.credentials = RsaKeyPairCredential(config.access_key_id, config.private_key)
                return

            if not client_key_dict:
                raise ValueError(str.format("read client key file failed: %s", config.client_key_file))
            private_key_data = client_key_dict.get("PrivateKeyData")
            if not private_key_data:
                raise ValueError("PrivateKeyData can not be None")
            private_key_pem = credential_utils.get_private_key_pem_from_private_key_data(private_key_data,
                                                                                         config.password)
            key_id = client_key_dict.get("KeyId")
            if not key_id:
                raise ValueError("KeyId can not be None")
            self.credentials = RsaKeyPairCredential(key_id, private_key_pem)
        else:
            raise ValueError("Only support rsa key pair credential provider now.")

    def get_access_key_id(self):
        return self.credentials.get_access_key_id()

    def get_access_key_secret(self):
        return self.credentials.get_access_key_secret()

    def get_signature(
            self,
            str_to_sign,
    ):
        signer = get_signer(self.credentials)
        return signer.sign_string_with_access_key_secret(str_to_sign, self.credentials.get_access_key_secret())
