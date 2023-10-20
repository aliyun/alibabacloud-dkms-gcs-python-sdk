# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
import base64
from Tea.exceptions import TeaException
from alibabacloud_darabonba_signature_util.signer import Signer

from openapi_credential import models as dedicated_kms_openapi_credential_models
from alibabacloud_tea_util.client import Client as UtilClient
from openapi_util.client import Client as DedicatedKmsOpenapiUtilClient
from alibabacloud_darabonba_stream.client import Client as StreamClient


class Client:
    _key_id: str = None
    _private_key_secret: str = None

    def __init__(
            self,
            config: dedicated_kms_openapi_credential_models.Config,
    ):
        if UtilClient.equal_string('rsa_key_pair', config.type):
            if not UtilClient.empty(config.client_key_content):
                json = UtilClient.parse_json(config.client_key_content)
                client_key = UtilClient.assert_as_map(json)
                private_key_data = base64.b64decode(UtilClient.assert_as_string(client_key.get('PrivateKeyData')))
                self._private_key_secret = DedicatedKmsOpenapiUtilClient.get_private_pem_from_pk_12(private_key_data,
                                                                                                    config.password)
                self._key_id = UtilClient.assert_as_string(client_key.get('KeyId'))
            elif not UtilClient.empty(config.client_key_file):
                json_from_file = UtilClient.read_as_json(StreamClient.read_from_file_path(config.client_key_file))
                if UtilClient.is_unset(json_from_file):
                    raise TeaException({
                        'message': f'read client key file failed: {config.client_key_file}'
                    })
                client_key_from_file = UtilClient.assert_as_map(json_from_file)
                private_key_data_from_file = base64.b64decode(
                    UtilClient.assert_as_string(client_key_from_file.get('PrivateKeyData')))
                self._private_key_secret = DedicatedKmsOpenapiUtilClient.get_private_pem_from_pk_12(
                    private_key_data_from_file, config.password)
                self._key_id = UtilClient.assert_as_string(client_key_from_file.get('KeyId'))
            else:
                self._private_key_secret = config.private_key
                self._key_id = config.access_key_id
        else:
            raise TeaException({
                'message': 'Only support rsa key pair credential provider now.'
            })

    def get_access_key_id(self) -> str:
        return self._key_id

    def get_access_key_secret(self) -> str:
        return self._private_key_secret

    def get_signature(
            self,
            str_to_sign: str,
    ) -> str:
        prefix = f'Bearer '
        sign = base64.b64encode(Signer.sha256with_rsasign(str_to_sign, self.get_access_key_secret())).decode().replace(
            "\n", "")
        return f'{prefix}{sign}'
