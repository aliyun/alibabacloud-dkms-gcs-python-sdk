# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
from Tea.core import TeaCore

from openapi.client import Client as DedicatedKmsOpenapiClient
from openapi import models as dedicated_kms_openapi_models
from sdk import models as dedicated_kms_sdk_models
from openapi_util import models as dedicated_kms_openapi_util_models
from alibabacloud_tea_util.client import Client as UtilClient
from openapi_util.client import Client as DedicatedKmsOpenapiUtilClient


class Client(DedicatedKmsOpenapiClient):
    def __init__(
            self,
            config: dedicated_kms_openapi_models.Config,
    ):
        super().__init__(config)

    def encrypt(
            self,
            request: dedicated_kms_sdk_models.EncryptRequest,
    ) -> dedicated_kms_sdk_models.EncryptResponse:
        """
        调用Encrypt接口将明文加密为密文
        @param request:
        @return: EncryptResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.encrypt_with_options(request, runtime)

    async def encrypt_async(
            self,
            request: dedicated_kms_sdk_models.EncryptRequest,
    ) -> dedicated_kms_sdk_models.EncryptResponse:
        """
        调用Encrypt接口将明文加密为密文
        @param request:
        @return: EncryptResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.encrypt_with_options_async(request, runtime)

    def encrypt_with_options(
            self,
            request: dedicated_kms_sdk_models.EncryptRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.EncryptResponse:
        """
        带运行参数调用Encrypt接口将明文加密为密文
        @param request:
        @param runtime:
        @return: EncryptResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_encrypt_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('Encrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes, runtime,
                            request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_encrypt_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.EncryptResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'Iv': resp_map.get('Iv'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def encrypt_with_options_async(
            self,
            request: dedicated_kms_sdk_models.EncryptRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.EncryptResponse:
        """
        带运行参数调用Encrypt接口将明文加密为密文
        @param request:
        @param runtime:
        @return: EncryptResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_encrypt_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('Encrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                                        runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_encrypt_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.EncryptResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'Iv': resp_map.get('Iv'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def decrypt(
            self,
            request: dedicated_kms_sdk_models.DecryptRequest,
    ) -> dedicated_kms_sdk_models.DecryptResponse:
        """
        调用Decrypt接口将密文解密为明文
        @param request:
        @return: DecryptResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.decrypt_with_options(request, runtime)

    async def decrypt_async(
            self,
            request: dedicated_kms_sdk_models.DecryptRequest,
    ) -> dedicated_kms_sdk_models.DecryptResponse:
        """
        调用Decrypt接口将密文解密为明文
        @param request:
        @return: DecryptResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.decrypt_with_options_async(request, runtime)

    def decrypt_with_options(
            self,
            request: dedicated_kms_sdk_models.DecryptRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.DecryptResponse:
        """
        带运行参数调用Decrypt接口将密文解密为明文
        @param request:
        @param runtime:
        @return: DecryptResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_decrypt_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('Decrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes, runtime,
                            request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_decrypt_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.DecryptResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Plaintext': resp_map.get('Plaintext'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def decrypt_with_options_async(
            self,
            request: dedicated_kms_sdk_models.DecryptRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.DecryptResponse:
        """
        带运行参数调用Decrypt接口将密文解密为明文
        @param request:
        @param runtime:
        @return: DecryptResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_decrypt_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('Decrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                                        runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_decrypt_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.DecryptResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Plaintext': resp_map.get('Plaintext'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def sign(
            self,
            request: dedicated_kms_sdk_models.SignRequest,
    ) -> dedicated_kms_sdk_models.SignResponse:
        """
        调用Sign接口使用非对称密钥进行签名
        @param request:
        @return: SignResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.sign_with_options(request, runtime)

    async def sign_async(
            self,
            request: dedicated_kms_sdk_models.SignRequest,
    ) -> dedicated_kms_sdk_models.SignResponse:
        """
        调用Sign接口使用非对称密钥进行签名
        @param request:
        @return: SignResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.sign_with_options_async(request, runtime)

    def sign_with_options(
            self,
            request: dedicated_kms_sdk_models.SignRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.SignResponse:
        """
        带运行参数调用Sign接口使用非对称密钥进行签名
        @param request:
        @param runtime:
        @return: SignResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_sign_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('Sign', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes, runtime,
                            request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_sign_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.SignResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Signature': resp_map.get('Signature'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'MessageType': resp_map.get('MessageType'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def sign_with_options_async(
            self,
            request: dedicated_kms_sdk_models.SignRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.SignResponse:
        """
        带运行参数调用Sign接口使用非对称密钥进行签名
        @param request:
        @param runtime:
        @return: SignResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_sign_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('Sign', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                                        runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_sign_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.SignResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Signature': resp_map.get('Signature'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'MessageType': resp_map.get('MessageType'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def verify(
            self,
            request: dedicated_kms_sdk_models.VerifyRequest,
    ) -> dedicated_kms_sdk_models.VerifyResponse:
        """
        调用Verify接口使用非对称密钥进行验签
        @param request:
        @return: VerifyResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.verify_with_options(request, runtime)

    async def verify_async(
            self,
            request: dedicated_kms_sdk_models.VerifyRequest,
    ) -> dedicated_kms_sdk_models.VerifyResponse:
        """
        调用Verify接口使用非对称密钥进行验签
        @param request:
        @return: VerifyResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.verify_with_options_async(request, runtime)

    def verify_with_options(
            self,
            request: dedicated_kms_sdk_models.VerifyRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.VerifyResponse:
        """
        带运行参数调用Verify接口使用非对称密钥进行验签
        @param request:
        @param runtime:
        @return: VerifyResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_verify_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('Verify', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes, runtime,
                            request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_verify_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.VerifyResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Value': resp_map.get('Value'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'MessageType': resp_map.get('MessageType'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def verify_with_options_async(
            self,
            request: dedicated_kms_sdk_models.VerifyRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.VerifyResponse:
        """
        带运行参数调用Verify接口使用非对称密钥进行验签
        @param request:
        @param runtime:
        @return: VerifyResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_verify_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('Verify', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                                        runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_verify_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.VerifyResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Value': resp_map.get('Value'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'MessageType': resp_map.get('MessageType'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def generate_random(
            self,
            request: dedicated_kms_sdk_models.GenerateRandomRequest,
    ) -> dedicated_kms_sdk_models.GenerateRandomResponse:
        """
        调用GenerateRandom接口生成一个随机数
        @param request:
        @return: GenerateRandomResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.generate_random_with_options(request, runtime)

    async def generate_random_async(
            self,
            request: dedicated_kms_sdk_models.GenerateRandomRequest,
    ) -> dedicated_kms_sdk_models.GenerateRandomResponse:
        """
        调用GenerateRandom接口生成一个随机数
        @param request:
        @return: GenerateRandomResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.generate_random_with_options_async(request, runtime)

    def generate_random_with_options(
            self,
            request: dedicated_kms_sdk_models.GenerateRandomRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GenerateRandomResponse:
        """
        带运行参数调用GenerateRandom接口生成一个随机数
        @param request:
        @param runtime:
        @return: GenerateRandomResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_random_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('GenerateRandom', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                            runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_random_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateRandomResponse(),
            {
                'Random': resp_map.get('Random'),
                'RequestId': resp_map.get('RequestId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def generate_random_with_options_async(
            self,
            request: dedicated_kms_sdk_models.GenerateRandomRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GenerateRandomResponse:
        """
        带运行参数调用GenerateRandom接口生成一个随机数
        @param request:
        @param runtime:
        @return: GenerateRandomResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_random_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('GenerateRandom', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                        req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_random_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateRandomResponse(),
            {
                'Random': resp_map.get('Random'),
                'RequestId': resp_map.get('RequestId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def generate_data_key(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyRequest,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyResponse:
        """
        调用GenerateDataKey接口生成数据密钥
        @param request:
        @return: GenerateDataKeyResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.generate_data_key_with_options(request, runtime)

    async def generate_data_key_async(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyRequest,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyResponse:
        """
        调用GenerateDataKey接口生成数据密钥
        @param request:
        @return: GenerateDataKeyResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.generate_data_key_with_options_async(request, runtime)

    def generate_data_key_with_options(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyResponse:
        """
        带运行参数调用GenerateDataKey接口生成数据密钥
        @param request:
        @param runtime:
        @return: GenerateDataKeyResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_data_key_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('GenerateDataKey', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                            runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_data_key_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateDataKeyResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'Plaintext': resp_map.get('Plaintext'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def generate_data_key_with_options_async(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyResponse:
        """
        带运行参数调用GenerateDataKey接口生成数据密钥
        @param request:
        @param runtime:
        @return: GenerateDataKeyResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_data_key_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('GenerateDataKey', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                        req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_data_key_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateDataKeyResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'Plaintext': resp_map.get('Plaintext'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def get_public_key(
            self,
            request: dedicated_kms_sdk_models.GetPublicKeyRequest,
    ) -> dedicated_kms_sdk_models.GetPublicKeyResponse:
        """
        调用GetPublicKey接口获取指定非对称密钥的公钥
        @param request:
        @return: GetPublicKeyResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.get_public_key_with_options(request, runtime)

    async def get_public_key_async(
            self,
            request: dedicated_kms_sdk_models.GetPublicKeyRequest,
    ) -> dedicated_kms_sdk_models.GetPublicKeyResponse:
        """
        调用GetPublicKey接口获取指定非对称密钥的公钥
        @param request:
        @return: GetPublicKeyResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.get_public_key_with_options_async(request, runtime)

    def get_public_key_with_options(
            self,
            request: dedicated_kms_sdk_models.GetPublicKeyRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GetPublicKeyResponse:
        """
        带运行参数调用GetPublicKey接口获取指定非对称密钥的公钥
        @param request:
        @param runtime:
        @return: GetPublicKeyResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_get_public_key_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('GetPublicKey', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                            runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_get_public_key_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GetPublicKeyResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def get_public_key_with_options_async(
            self,
            request: dedicated_kms_sdk_models.GetPublicKeyRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GetPublicKeyResponse:
        """
        带运行参数调用GetPublicKey接口获取指定非对称密钥的公钥
        @param request:
        @param runtime:
        @return: GetPublicKeyResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_get_public_key_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('GetPublicKey', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                        req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_get_public_key_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GetPublicKeyResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def get_secret_value(
            self,
            request: dedicated_kms_sdk_models.GetSecretValueRequest,
    ) -> dedicated_kms_sdk_models.GetSecretValueResponse:
        """
        调用GetSecretValue接口通过KMS实例网关获取凭据值
        @param request:
        @return: GetSecretValueResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.get_secret_value_with_options(request, runtime)

    async def get_secret_value_async(
            self,
            request: dedicated_kms_sdk_models.GetSecretValueRequest,
    ) -> dedicated_kms_sdk_models.GetSecretValueResponse:
        """
        调用GetSecretValue接口通过KMS实例网关获取凭据值
        @param request:
        @return: GetSecretValueResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.get_secret_value_with_options_async(request, runtime)

    def get_secret_value_with_options(
            self,
            request: dedicated_kms_sdk_models.GetSecretValueRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GetSecretValueResponse:
        """
        带运行参数调用GetSecretValue接口通过KMS实例网关获取凭据值
        @param request:
        @param runtime:
        @return: GetSecretValueResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_get_secret_value_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('GetSecretValue', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                            runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_get_secret_value_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GetSecretValueResponse(),
            {
                'SecretName': resp_map.get('SecretName'),
                'SecretType': resp_map.get('SecretType'),
                'SecretData': resp_map.get('SecretData'),
                'SecretDataType': resp_map.get('SecretDataType'),
                'VersionStages': resp_map.get('VersionStages'),
                'VersionId': resp_map.get('VersionId'),
                'CreateTime': resp_map.get('CreateTime'),
                'RequestId': resp_map.get('RequestId'),
                'LastRotationDate': resp_map.get('LastRotationDate'),
                'NextRotationDate': resp_map.get('NextRotationDate'),
                'ExtendedConfig': resp_map.get('ExtendedConfig'),
                'AutomaticRotation': resp_map.get('AutomaticRotation'),
                'RotationInterval': resp_map.get('RotationInterval'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def get_secret_value_with_options_async(
            self,
            request: dedicated_kms_sdk_models.GetSecretValueRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GetSecretValueResponse:
        """
        带运行参数调用GetSecretValue接口通过KMS实例网关获取凭据值
        @param request:
        @param runtime:
        @return: GetSecretValueResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_get_secret_value_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('GetSecretValue', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                        req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_get_secret_value_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GetSecretValueResponse(),
            {
                'SecretName': resp_map.get('SecretName'),
                'SecretType': resp_map.get('SecretType'),
                'SecretData': resp_map.get('SecretData'),
                'SecretDataType': resp_map.get('SecretDataType'),
                'VersionStages': resp_map.get('VersionStages'),
                'VersionId': resp_map.get('VersionId'),
                'CreateTime': resp_map.get('CreateTime'),
                'RequestId': resp_map.get('RequestId'),
                'LastRotationDate': resp_map.get('LastRotationDate'),
                'NextRotationDate': resp_map.get('NextRotationDate'),
                'ExtendedConfig': resp_map.get('ExtendedConfig'),
                'AutomaticRotation': resp_map.get('AutomaticRotation'),
                'RotationInterval': resp_map.get('RotationInterval'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def advance_encrypt(
            self,
            request: dedicated_kms_sdk_models.AdvanceEncryptRequest,
    ) -> dedicated_kms_sdk_models.AdvanceEncryptResponse:
        """
        调用AdvanceEncrypt接口将明文高级加密为密文
        @param request:
        @return: AdvanceEncryptResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.advance_encrypt_with_options(request, runtime)

    async def advance_encrypt_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceEncryptRequest,
    ) -> dedicated_kms_sdk_models.AdvanceEncryptResponse:
        """
        调用AdvanceEncrypt接口将明文高级加密为密文
        @param request:
        @return: AdvanceEncryptResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.advance_encrypt_with_options_async(request, runtime)

    def advance_encrypt_with_options(
            self,
            request: dedicated_kms_sdk_models.AdvanceEncryptRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceEncryptResponse:
        """
        带运行参数调用AdvanceEncrypt接口将明文高级加密为密文
        @param request:
        @param runtime:
        @return: AdvanceEncryptResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_encrypt_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('AdvanceEncrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                            runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_encrypt_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceEncryptResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'Iv': resp_map.get('Iv'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def advance_encrypt_with_options_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceEncryptRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceEncryptResponse:
        """
        带运行参数调用AdvanceEncrypt接口将明文高级加密为密文
        @param request:
        @param runtime:
        @return: AdvanceEncryptResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_encrypt_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('AdvanceEncrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                        req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_encrypt_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceEncryptResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'Iv': resp_map.get('Iv'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def advance_decrypt(
            self,
            request: dedicated_kms_sdk_models.AdvanceDecryptRequest,
    ) -> dedicated_kms_sdk_models.AdvanceDecryptResponse:
        """
        调用AdvanceDecrypt接口将密文高级解密为明文
        @param request:
        @return: AdvanceDecryptResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.advance_decrypt_with_options(request, runtime)

    async def advance_decrypt_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceDecryptRequest,
    ) -> dedicated_kms_sdk_models.AdvanceDecryptResponse:
        """
        调用AdvanceDecrypt接口将密文高级解密为明文
        @param request:
        @return: AdvanceDecryptResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.advance_decrypt_with_options_async(request, runtime)

    def advance_decrypt_with_options(
            self,
            request: dedicated_kms_sdk_models.AdvanceDecryptRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceDecryptResponse:
        """
        带运行参数调用AdvanceDecrypt接口将密文高级解密为明文
        @param request:
        @param runtime:
        @return: AdvanceDecryptResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_decrypt_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('AdvanceDecrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                            runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_decrypt_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceDecryptResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Plaintext': resp_map.get('Plaintext'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def advance_decrypt_with_options_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceDecryptRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceDecryptResponse:
        """
        带运行参数调用AdvanceDecrypt接口将密文高级解密为明文
        @param request:
        @param runtime:
        @return: AdvanceDecryptResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_decrypt_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('AdvanceDecrypt', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                        req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_decrypt_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceDecryptResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Plaintext': resp_map.get('Plaintext'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'PaddingMode': resp_map.get('PaddingMode'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def advance_generate_data_key(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyRequest,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyResponse:
        """
        调用AdvanceGenerateDataKey接口高级生成数据密钥
        @param request:
        @return: AdvanceGenerateDataKeyRequest
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.advance_generate_data_key_with_options(request, runtime)

    async def advance_generate_data_key_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyRequest,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyResponse:
        """
        调用AdvanceGenerateDataKey接口高级生成数据密钥
        @param request:
        @return: AdvanceGenerateDataKeyRequest
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.advance_generate_data_key_with_options_async(request, runtime)

    def advance_generate_data_key_with_options(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyResponse:
        """
        带运行参数调用AdvanceGenerateDataKey接口高级生成数据密钥
        @param request:
        @param runtime:
        @return: AdvanceGenerateDataKeyRequest
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_generate_data_key_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('AdvanceGenerateDataKey', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                            req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_generate_data_key_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceGenerateDataKeyResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'Plaintext': resp_map.get('Plaintext'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def advance_generate_data_key_with_options_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyResponse:
        """
        带运行参数调用AdvanceGenerateDataKey接口高级生成数据密钥
        @param request:
        @param runtime:
        @return: AdvanceGenerateDataKeyRequest
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_generate_data_key_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('AdvanceGenerateDataKey', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                        req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_generate_data_key_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceGenerateDataKeyResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'Plaintext': resp_map.get('Plaintext'),
                'CiphertextBlob': resp_map.get('CiphertextBlob'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def generate_data_key_pair(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyPairRequest,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyPairResponse:
        """
        调用GenerateDataKeyPair接口生成密钥对
        @param request:
        @return: GenerateDataKeyPairResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.generate_data_key_pair_with_options(request, runtime)

    async def generate_data_key_pair_async(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyPairRequest,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyPairResponse:
        """
        调用GenerateDataKeyPair接口生成密钥对
        @param request:
        @return: GenerateDataKeyPairResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.generate_data_key_pair_with_options_async(request, runtime)

    def generate_data_key_pair_with_options(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyPairRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyPairResponse:
        """
        带运行参数调用GenerateDataKeyPairWithOptions接口生成密钥对
        @param request:
        @param runtime:
        @return: GenerateDataKeyPairResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_data_key_pair_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('GenerateDataKeyPair', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256', req_body_bytes,
                            runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_data_key_pair_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateDataKeyPairResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'KeyPairSpec': resp_map.get('KeyPairSpec'),
                'PrivateKeyPlaintext': resp_map.get('PrivateKeyPlaintext'),
                'PrivateKeyCiphertextBlob': resp_map.get('PrivateKeyCiphertextBlob'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def generate_data_key_pair_with_options_async(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyPairRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyPairResponse:
        """
        带运行参数调用GenerateDataKeyPairWithOptions接口生成密钥对
        @param request:
        @param runtime:
        @return: GenerateDataKeyPairResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_data_key_pair_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('GenerateDataKeyPair', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                                        req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_data_key_pair_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateDataKeyPairResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'KeyPairSpec': resp_map.get('KeyPairSpec'),
                'PrivateKeyPlaintext': resp_map.get('PrivateKeyPlaintext'),
                'PrivateKeyCiphertextBlob': resp_map.get('PrivateKeyCiphertextBlob'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def generate_data_key_pair_without_plaintext(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextRequest,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextResponse:
        """
        调用GenerateDataKeyPairWithoutPlaintext接口生成无明文密钥对
        @param request:
        @return: GenerateDataKeyPairWithoutPlaintextResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.generate_data_key_pair_without_plaintext_with_options(request, runtime)

    async def generate_data_key_pair_without_plaintext_async(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextRequest,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextResponse:
        """
        调用GenerateDataKeyPairWithoutPlaintext接口生成无明文密钥对
        @param request:
        @return: GenerateDataKeyPairWithoutPlaintextResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.generate_data_key_pair_without_plaintext_with_options_async(request, runtime)

    def generate_data_key_pair_without_plaintext_with_options(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextResponse:
        """
        带运行参数调用AdvanceGenerateDataKeyPair接口生成无明文密钥对
        @param request:
        @param runtime:
        @return: GenerateDataKeyPairWithoutPlaintextResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_data_key_pair_without_plaintext_request(
            req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('GenerateDataKeyPairWithoutPlaintext', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                            req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_data_key_pair_without_plaintext_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'KeyPairSpec': resp_map.get('KeyPairSpec'),
                'PrivateKeyCiphertextBlob': resp_map.get('PrivateKeyCiphertextBlob'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def generate_data_key_pair_without_plaintext_with_options_async(
            self,
            request: dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextResponse:
        """
        带运行参数调用AdvanceGenerateDataKeyPair接口生成无明文密钥对
        @param request:
        @param runtime:
        @return: GenerateDataKeyPairWithoutPlaintextResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_generate_data_key_pair_without_plaintext_request(
            req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('GenerateDataKeyPairWithoutPlaintext', 'dkms-gcs-0.2', 'https', 'POST',
                                        'RSA_PKCS1_SHA_256', req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_generate_data_key_pair_without_plaintext_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.GenerateDataKeyPairWithoutPlaintextResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'KeyPairSpec': resp_map.get('KeyPairSpec'),
                'PrivateKeyCiphertextBlob': resp_map.get('PrivateKeyCiphertextBlob'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def advance_generate_data_key_pair(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairRequest,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairResponse:
        """
        调用AdvanceGenerateDataKeyPair接口高级生成密钥对
        @param request:
        @return: AdvanceGenerateDataKeyPairResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.advance_generate_data_key_pair_with_options(request, runtime)

    async def advance_generate_data_key_pair_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairRequest,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairResponse:
        """
        调用AdvanceGenerateDataKeyPair接口高级生成密钥对
        @param request:
        @return: AdvanceGenerateDataKeyPairResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.advance_generate_data_key_pair_with_options_async(request, runtime)

    def advance_generate_data_key_pair_with_options(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairResponse:
        """
        带运行参数调用AdvanceGenerateDataKeyPairWithOptions接口高级生成密钥对
        @param request:
        @param runtime:
        @return: AdvanceGenerateDataKeyPairResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_generate_data_key_pair_request(req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('AdvanceGenerateDataKeyPair', 'dkms-gcs-0.2', 'https', 'POST', 'RSA_PKCS1_SHA_256',
                            req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_generate_data_key_pair_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'KeyPairSpec': resp_map.get('KeyPairSpec'),
                'PrivateKeyPlaintext': resp_map.get('PrivateKeyPlaintext'),
                'PrivateKeyCiphertextBlob': resp_map.get('PrivateKeyCiphertextBlob'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def advance_generate_data_key_pair_with_options_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairResponse:
        """
        带运行参数调用AdvanceGenerateDataKeyPairWithOptions接口高级生成密钥对
        @param request:
        @param runtime:
        @return: AdvanceGenerateDataKeyPairResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_generate_data_key_pair_request(req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('AdvanceGenerateDataKeyPair', 'dkms-gcs-0.2', 'https', 'POST',
                                        'RSA_PKCS1_SHA_256', req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_generate_data_key_pair_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'KeyPairSpec': resp_map.get('KeyPairSpec'),
                'PrivateKeyPlaintext': resp_map.get('PrivateKeyPlaintext'),
                'PrivateKeyCiphertextBlob': resp_map.get('PrivateKeyCiphertextBlob'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    def advance_generate_data_key_pair_without_plaintext(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextRequest,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextResponse:
        """
        调用AdvanceGenerateDataKeyPairWithoutPlaintext接口高级生成无明文密钥对
        @param request:
        @return: AdvanceGenerateDataKeyPairWithoutPlaintextResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return self.advance_generate_data_key_pair_without_plaintext_with_options(request, runtime)

    async def advance_generate_data_key_pair_without_plaintext_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextRequest,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextResponse:
        """
        调用AdvanceGenerateDataKeyPairWithoutPlaintext接口高级生成无明文密钥对
        @param request:
        @return: AdvanceGenerateDataKeyPairWithoutPlaintextResponse
        """
        runtime = dedicated_kms_openapi_util_models.RuntimeOptions()
        return await self.advance_generate_data_key_pair_without_plaintext_with_options_async(request, runtime)

    def advance_generate_data_key_pair_without_plaintext_with_options(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextResponse:
        """
        带运行参数调用AdvanceGenerateDataKeyPairWithoutPlaintextWithOptions接口高级生成无明文密钥对
        @param request:
        @param runtime:
        @return: AdvanceGenerateDataKeyPairWithoutPlaintextResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_generate_data_key_pair_without_plaintext_request(
            req_body)
        response_entity = UtilClient.assert_as_map(
            self.do_request('AdvanceGenerateDataKeyPairWithoutPlaintext', 'dkms-gcs-0.2', 'https', 'POST',
                            'RSA_PKCS1_SHA_256', req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_generate_data_key_pair_without_plaintext_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'KeyPairSpec': resp_map.get('KeyPairSpec'),
                'PrivateKeyCiphertextBlob': resp_map.get('PrivateKeyCiphertextBlob'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )

    async def advance_generate_data_key_pair_without_plaintext_with_options_async(
            self,
            request: dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextRequest,
            runtime: dedicated_kms_openapi_util_models.RuntimeOptions,
    ) -> dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextResponse:
        """
        带运行参数调用AdvanceGenerateDataKeyPairWithoutPlaintextWithOptions接口高级生成无明文密钥对
        @param request:
        @param runtime:
        @return: AdvanceGenerateDataKeyPairWithoutPlaintextResponse
        """
        UtilClient.validate_model(request)
        req_body = UtilClient.to_map(request)
        req_body_bytes = DedicatedKmsOpenapiUtilClient.get_serialized_advance_generate_data_key_pair_without_plaintext_request(
            req_body)
        response_entity = UtilClient.assert_as_map(
            await self.do_request_async('AdvanceGenerateDataKeyPairWithoutPlaintext', 'dkms-gcs-0.2', 'https', 'POST',
                                        'RSA_PKCS1_SHA_256', req_body_bytes, runtime, request.request_headers))
        resp_map = DedicatedKmsOpenapiUtilClient.parse_advance_generate_data_key_pair_without_plaintext_response(
            UtilClient.assert_as_bytes(response_entity.get('bodyBytes')))
        return TeaCore.from_map(
            dedicated_kms_sdk_models.AdvanceGenerateDataKeyPairWithoutPlaintextResponse(),
            {
                'KeyId': resp_map.get('KeyId'),
                'Iv': resp_map.get('Iv'),
                'KeyPairSpec': resp_map.get('KeyPairSpec'),
                'PrivateKeyCiphertextBlob': resp_map.get('PrivateKeyCiphertextBlob'),
                'PublicKey': resp_map.get('PublicKey'),
                'RequestId': resp_map.get('RequestId'),
                'Algorithm': resp_map.get('Algorithm'),
                'KeyVersionId': resp_map.get('KeyVersionId'),
                'responseHeaders': response_entity.get('responseHeaders')
            }
        )
