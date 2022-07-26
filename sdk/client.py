# coding=utf-8
# This file is auto-generated, don't edit it. Thanks.
from Tea.core import TeaCore

from openapi.client import Client as DedicatedKmsOpenapiClient
from sdk import models as dedicated_kms_sdk_models
from openapi_util import models as dedicated_kms_openapi_util_models
from alibabacloud_tea_util.client import Client as UtilClient
from openapi_util.client import Client as DedicatedKmsOpenapiUtilClient


class Client(DedicatedKmsOpenapiClient):
    def __init__(
            self,
            config,
    ):
        super(Client, self).__init__(config)

    def encrypt_with_options(
            self,
            request,
            runtime,
    ):
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_encrypt_request(req_body)
        resp_entity = self.do_request('Encrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                                      runtime, request.request_headers)
        resp_map = DedicatedKmsOpenapiUtilClient.parse_encrypt_response(resp_entity.body_bytes)
        encrypt_response = TeaCore.from_map(
            dedicated_kms_sdk_models.EncryptResponse(),
            {
                'RequestId': resp_map.get('RequestId'),
                'KeyId': resp_map.get('KeyId'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'Iv': resp_map.get('Iv'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode')
            }
        )
        encrypt_response.response_headers = resp_entity.response_headers
        return encrypt_response

    def encrypt(
            self,
            request,
    ):
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.encrypt_with_options(request, runtime)

    def decrypt_with_options(
            self,
            request,
            runtime,
    ):
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_decrypt_request(req_body)
        resp_entity = self.do_request('Decrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                                      runtime, request.request_headers)
        resp_map = DedicatedKmsOpenapiUtilClient.parse_decrypt_response(resp_entity.body_bytes)
        decrypt_response = TeaCore.from_map(
            dedicated_kms_sdk_models.DecryptResponse(),
            {
                'RequestId': resp_map.get('RequestId'),
                'KeyId': resp_map.get('KeyId'),
                'Plaintext': resp_map.get('Plaintext'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode')
            }
        )
        decrypt_response.response_headers = resp_entity.response_headers
        return decrypt_response

    def decrypt(
            self,
            request,
    ):
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.decrypt_with_options(request, runtime)

    def hmac_with_options(
            self,
            request,
            runtime,
    ):
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_hmac_request(req_body)
        resp_entity = self.do_request('Hmac', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                                      runtime, request.request_headers)
        resp_map = DedicatedKmsOpenapiUtilClient.parse_hmac_response(resp_entity.body_bytes)
        hmac_response = TeaCore.from_map(
            dedicated_kms_sdk_models.HmacResponse(),
            {
                'RequestId': resp_map.get('RequestId'),
                'KeyId': resp_map.get('KeyId'),
                'Signature': resp_map.get('Signature')
            }
        )
        hmac_response.response_headers = resp_entity.response_headers
        return hmac_response

    def hmac(
            self,
            request,
    ):
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.hmac_with_options(request, runtime)

    def sign_with_options(
            self,
            request,
            runtime,
    ):
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_sign_request(req_body)
        resp_entity = self.do_request('Sign', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                                      runtime, request.request_headers)
        resp_map = DedicatedKmsOpenapiUtilClient.parse_sign_response(resp_entity.body_bytes)
        sign_response = TeaCore.from_map(
            dedicated_kms_sdk_models.SignResponse(),
            {
                'RequestId': resp_map.get('RequestId'),
                'KeyId': resp_map.get('KeyId'),
                'Signature': resp_map.get('Signature'),
                'Algorithm': resp_map.get('Algorithm'),
                'MessageType': resp_map.get('MessageType')
            }
        )
        sign_response.response_headers = resp_entity.response_headers
        return sign_response

    def sign(
            self,
            request,
    ):
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.sign_with_options(request, runtime)

    def verify_with_options(
            self,
            request,
            runtime,
    ):
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_verify_request(req_body)
        resp_entity = self.do_request('Verify', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                                      runtime, request.request_headers)
        resp_map = DedicatedKmsOpenapiUtilClient.parse_verify_response(resp_entity.body_bytes)
        verify_response = TeaCore.from_map(
            dedicated_kms_sdk_models.VerifyResponse(),
            {
                'RequestId': resp_map.get('RequestId'),
                'KeyId': resp_map.get('KeyId'),
                'Value': resp_map.get('Value'),
                'Algorithm': resp_map.get('Algorithm'),
                'MessageType': resp_map.get('MessageType')
            }
        )
        verify_response.response_headers = resp_entity.response_headers
        return verify_response

    def verify(
            self,
            request,
    ):
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.verify_with_options(request, runtime)

    def generate_random_with_options(
            self,
            request,
            runtime,
    ):
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_random_request(req_body)
        resp_entity = self.do_request('GenerateRandom', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                      req_body_bytes, runtime, request.request_headers)
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_random_response(resp_entity.body_bytes)
        generate_random_response = TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateRandomResponse(),
            {
                'RequestId': resp_map.get('RequestId'),
                'Random': resp_map.get('Random')
            }
        )
        generate_random_response.response_headers = resp_entity.response_headers
        return generate_random_response

    def generate_random(
            self,
            request,
    ):
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.generate_random_with_options(request, runtime)

    def generate_data_key_with_options(
            self,
            request,
            runtime,
    ):
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_data_key_request(req_body)
        resp_entity = self.do_request('GenerateDataKey', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                      req_body_bytes, runtime, request.request_headers)
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_data_key_response(resp_entity.body_bytes)
        generate_data_key_response = TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateDataKeyResponse(),
            {
                'RequestId': resp_map.get('RequestId'),
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'Plaintext': resp_map.get('Plaintext'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'Algorithm': resp_map.get('Algorithm')
            }
        )
        generate_data_key_response.response_headers = resp_entity.response_headers
        return generate_data_key_response

    def generate_data_key(
            self,
            request,
    ):
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.generate_data_key_with_options(request, runtime)

    def get_public_key_with_options(
            self,
            request,
            runtime,
    ):
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_get_public_key_request(req_body)
        resp_entity = self.do_request('GetPublicKey', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                      req_body_bytes, runtime, request.request_headers)
        resp_map = DedicatedKmsOpenapiUtilClient.parse_get_public_key_response(resp_entity.body_bytes)
        get_public_key_response = TeaCore.from_map(
            dedicated_kms_sdk_models.GetPublicKeyResponse(),
            {
                'RequestId': resp_map.get('RequestId'),
                'KeyId': resp_map.get('KeyId'),
                'PublicKey': resp_map.get('PublicKey')
            }
        )
        get_public_key_response.response_headers = resp_entity.response_headers
        return get_public_key_response

    def get_public_key(
            self,
            request,
    ):
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.get_public_key_with_options(request, runtime)

    def get_secret_value_with_options(
            self,
            request,
            runtime,
    ):
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_get_secret_value_request(req_body)
        resp_entity = self.do_request('GetSecretValue', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                      req_body_bytes, runtime, request.request_headers)
        resp_map = DedicatedKmsOpenapiUtilClient.parse_get_secret_value_response(resp_entity.body_bytes)
        get_secret_value_response = TeaCore.from_map(
            dedicated_kms_sdk_models.GetSecretValueResponse(),
            {
                'RequestId': resp_map.get('RequestId'),
                'SecretName': resp_map.get('SecretName'),
                'SecretType': resp_map.get('SecretType'),
                'SecretData': resp_map.get('SecretData'),
                'SecretDataType': resp_map.get('SecretDataType'),
                'VersionStages': resp_map.get('VersionStages'),
                'VersionId': resp_map.get('VersionId'),
                'CreateTime': resp_map.get('CreateTime'),
                'LastRotationDate': resp_map.get('LastRotationDate'),
                'NextRotationDate': resp_map.get('NextRotationDate'),
                'ExtendedConfig': resp_map.get('ExtendedConfig'),
                'AutomaticRotation': resp_map.get('AutomaticRotation'),
                'RotationInterval': resp_map.get('RotationInterval')
            }
        )
        get_secret_value_response.response_headers = resp_entity.response_headers
        return get_secret_value_response

    def get_secret_value(
            self,
            request,
    ):
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.get_secret_value_with_options(request, runtime)
