# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
from Tea.exceptions import TeaException
from typing import Dict, Any

from alibabacloud_tea_util.client import Client as UtilClient
from alibabacloud_darabonba_map.client import Client as MapClient
from alibabacloud_darabonba_array.client import Client as ArrayClient
from alibabacloud_darabonba_string.client import Client as StringClient

from openapi_util.protobuf import api_pb2
from OpenSSL import crypto


class Client:
    def __init__(self):
        pass

    @staticmethod
    def get_err_message(
            msg: bytes,
    ) -> dict:

        result = {}
        error = api_pb2.Error()
        error.ParseFromString(msg)
        result["Code"] = error.ErrorCode
        result["Message"] = error.ErrorMessage
        result["RequestId"] = error.RequestId
        return result

    @staticmethod
    def get_content_length(
            req_body: bytes,
    ) -> str:

        return str(len(req_body))

    @staticmethod
    def get_private_pem_from_pk_12(
            private_key_data: bytes,
            password: str,
    ) -> str:
        pk12 = crypto.load_pkcs12(private_key_data, password)
        private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pk12.get_privatekey()).decode()
        return Client.trim_private_key_pem(private_key)

    @staticmethod
    def trim_private_key_pem(private_key: str) -> str:
        prefix = "-----BEGIN PRIVATE KEY-----"
        newline = "\n"
        suffix = "-----END PRIVATE KEY-----"
        private_key = private_key.replace(prefix, "")
        private_key = private_key.replace(suffix, "")
        return private_key.replace(newline, "")

    @staticmethod
    def get_string_to_sign(
            method: str,
            pathname: str,
            headers: Dict[str, str],
            query: Dict[str, str],
    ) -> str:
        content_sha256 = headers.get('content-sha256')
        if UtilClient.is_unset(content_sha256):
            content_sha256 = ''
        content_type = headers.get('content-type')
        if UtilClient.is_unset(content_type):
            content_type = ''
        date = headers.get('date')
        if UtilClient.is_unset(date):
            date = ''
        header = f'{method}\n{content_sha256}\n{content_type}\n{date}\n'
        canonicalized_headers = Client.get_canonicalized_headers(headers)
        canonicalized_resource = Client.get_canonicalized_resource(pathname, query)
        return f'{header}{canonicalized_headers}{canonicalized_resource}'

    @staticmethod
    def get_canonicalized_headers(
            headers: Dict[str, str],
    ) -> str:
        if UtilClient.is_unset(headers):
            return
        prefix = 'x-kms-'
        keys = MapClient.key_set(headers)
        sorted_keys = ArrayClient.asc_sort(keys)
        canonicalized_headers = ''
        for key in sorted_keys:
            if StringClient.has_prefix(key, prefix):
                canonicalized_headers = f'{canonicalized_headers}{key}:{StringClient.trim(headers.get(key))}\n'
        return canonicalized_headers

    @staticmethod
    def get_canonicalized_resource(
            pathname: str,
            query: Dict[str, str],
    ) -> str:
        if not UtilClient.is_unset(pathname):
            return '/'
        if UtilClient.is_unset(query):
            return pathname
        canonicalized_resource = ''
        query_array = MapClient.key_set(query)
        sorted_query_array = ArrayClient.asc_sort(query_array)
        separator = ''
        canonicalized_resource = f'{pathname}?'
        for key in sorted_query_array:
            canonicalized_resource = f'{canonicalized_resource}{separator}{key}'
            if not UtilClient.empty(query.get(key)):
                canonicalized_resource = f'{canonicalized_resource}={query.get(key)}'
            separator = '&'
        return canonicalized_resource

    @staticmethod
    def default_boolean(
            bool_1: bool,
            bool_2: bool,
    ) -> bool:
        if UtilClient.is_unset(bool_1):
            return bool_2
        else:
            return bool_1

    @staticmethod
    def is_retry_err(
            err: TeaException,
    ) -> bool:
        if err.code == "Rejected.Throttling":
            return True
        return False

    @staticmethod
    def parse_encrypt_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        encrypt_response = api_pb2.EncryptResponse()
        encrypt_response.ParseFromString(res_body)
        result["KeyId"] = encrypt_response.KeyId
        result["CiphertextBlob"] = encrypt_response.CiphertextBlob
        result["Iv"] = encrypt_response.Iv
        result["RequestId"] = encrypt_response.RequestId
        result["Algorithm"] = encrypt_response.Algorithm
        result["PaddingMode"] = encrypt_response.PaddingMode
        return result

    @staticmethod
    def get_serialized_decrypt_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.DecryptRequest()
        ciphertext_blob = req_body.get("CiphertextBlob")
        if ciphertext_blob:
            request.CiphertextBlob = ciphertext_blob
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        algorithm = req_body.get("Algorithm")
        if algorithm:
            request.Algorithm = algorithm
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        iv = req_body.get("Iv")
        if iv:
            request.Iv = iv
        padding_mode = req_body.get("PaddingMode")
        if padding_mode:
            request.PaddingMode = padding_mode
        return request.SerializeToString()

    @staticmethod
    def parse_decrypt_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        decrypt_response = api_pb2.DecryptResponse()
        decrypt_response.ParseFromString(res_body)
        result["KeyId"] = decrypt_response.KeyId
        result["Plaintext"] = decrypt_response.Plaintext
        result["RequestId"] = decrypt_response.RequestId
        result["Algorithm"] = decrypt_response.Algorithm
        result["PaddingMode"] = decrypt_response.PaddingMode
        return result

    @staticmethod
    def get_serialized_sign_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.SignRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        digest = req_body.get("Digest")
        if digest:
            request.Digest = digest
        algorithm = req_body.get("Algorithm")
        if algorithm:
            request.Algorithm = algorithm
        message = req_body.get("Message")
        if message:
            request.Message = message
        message_type = req_body.get("MessageType")
        if message_type:
            request.MessageType = message_type
        return request.SerializeToString()

    @staticmethod
    def parse_sign_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        sign_response = api_pb2.SignResponse()
        sign_response.ParseFromString(res_body)
        result["KeyId"] = sign_response.KeyId
        result["Signature"] = sign_response.Signature
        result["RequestId"] = sign_response.RequestId
        result["Algorithm"] = sign_response.Algorithm
        result["MessageType"] = sign_response.MessageType
        return result

    @staticmethod
    def get_serialized_verify_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.VerifyRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        digest = req_body.get("Digest")
        if digest:
            request.Digest = digest
        signature = req_body.get("Signature")
        if signature:
            request.Signature = signature
        algorithm = req_body.get("Algorithm")
        if algorithm:
            request.Algorithm = algorithm
        message = req_body.get("Message")
        if message:
            request.Message = message
        message_type = req_body.get("MessageType")
        if message_type:
            request.MessageType = message_type
        return request.SerializeToString()

    @staticmethod
    def parse_verify_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        verify_response = api_pb2.VerifyResponse()
        verify_response.ParseFromString(res_body)
        result["KeyId"] = verify_response.KeyId
        result["Value"] = verify_response.Value
        result["RequestId"] = verify_response.RequestId
        result["Algorithm"] = verify_response.Algorithm
        result["MessageType"] = verify_response.MessageType
        return result

    @staticmethod
    def get_serialized_generate_random_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.GenerateRandomRequest()
        length = req_body.get("Length")
        if length:
            request.Length = length
        return request.SerializeToString()

    @staticmethod
    def parse_generate_random_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        generate_random_response = api_pb2.GenerateRandomResponse()
        generate_random_response.ParseFromString(res_body)
        result["Random"] = generate_random_response.Random
        result["RequestId"] = generate_random_response.RequestId
        return result

    @staticmethod
    def get_serialized_generate_data_key_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.GenerateDataKeyRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        algorithm = req_body.get("Algorithm")
        if algorithm:
            request.Algorithm = algorithm
        number_of_bytes = req_body.get("NumberOfBytes")
        if number_of_bytes:
            request.NumberOfBytes = number_of_bytes
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        return request.SerializeToString()

    @staticmethod
    def parse_generate_data_key_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        generate_data_key_response = api_pb2.GenerateDataKeyResponse()
        generate_data_key_response.ParseFromString(res_body)
        result["KeyId"] = generate_data_key_response.KeyId
        result["Iv"] = generate_data_key_response.Iv
        result["Plaintext"] = generate_data_key_response.Plaintext
        result["CiphertextBlob"] = generate_data_key_response.CiphertextBlob
        result["RequestId"] = generate_data_key_response.RequestId
        result["Algorithm"] = generate_data_key_response.Algorithm
        return result

    @staticmethod
    def get_serialized_get_public_key_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.GetPublicKeyRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        return request.SerializeToString()

    @staticmethod
    def parse_get_public_key_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        get_public_key_response = api_pb2.GetPublicKeyResponse()
        get_public_key_response.ParseFromString(res_body)
        result["KeyId"] = get_public_key_response.KeyId
        result["PublicKey"] = get_public_key_response.PublicKey
        result["RequestId"] = get_public_key_response.RequestId
        return result

    @staticmethod
    def get_serialized_get_secret_value_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.GetSecretValueRequest()
        secret_name = req_body.get("SecretName")
        if secret_name:
            request.SecretName = secret_name
        version_stage = req_body.get("VersionStage")
        if version_stage:
            request.VersionStage = version_stage
        version_id = req_body.get("VersionId")
        if version_id:
            request.VersionId = version_id
        fetch_extended_config = req_body.get("FetchExtendedConfig")
        if fetch_extended_config:
            request.FetchExtendedConfig = fetch_extended_config
        return request.SerializeToString()

    @staticmethod
    def parse_get_secret_value_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        get_secret_value_response = api_pb2.GetSecretValueResponse()
        get_secret_value_response.ParseFromString(res_body)
        result["SecretName"] = get_secret_value_response.SecretName
        result["SecretType"] = get_secret_value_response.SecretType
        result["SecretData"] = get_secret_value_response.SecretData
        result["SecretDataType"] = get_secret_value_response.SecretDataType
        result["VersionStages"] = get_secret_value_response.VersionStages
        result["VersionId"] = get_secret_value_response.VersionId
        result["CreateTime"] = get_secret_value_response.CreateTime
        result["RequestId"] = get_secret_value_response.RequestId
        result["LastRotationDate"] = get_secret_value_response.LastRotationDate
        result["NextRotationDate"] = get_secret_value_response.NextRotationDate
        result["ExtendedConfig"] = get_secret_value_response.ExtendedConfig
        result["AutomaticRotation"] = get_secret_value_response.AutomaticRotation
        result["RotationInterval"] = get_secret_value_response.RotationInterval
        return result

    @staticmethod
    def get_serialized_advance_encrypt_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.AdvanceEncryptRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        plaintext = req_body.get("Plaintext")
        if plaintext:
            request.Plaintext = plaintext
        algorithm = req_body.get("Algorithm")
        if algorithm:
            request.Algorithm = algorithm
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        iv = req_body.get("Iv")
        if iv:
            request.Iv = iv
        padding_mode = req_body.get("PaddingMode")
        if padding_mode:
            request.PaddingMode = padding_mode
        return request.SerializeToString()

    @staticmethod
    def parse_advance_encrypt_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        advance_encrypt_response = api_pb2.AdvanceEncryptResponse()
        advance_encrypt_response.ParseFromString(res_body)
        result["KeyId"] = advance_encrypt_response.KeyId
        result["CiphertextBlob"] = advance_encrypt_response.CiphertextBlob
        result["Iv"] = advance_encrypt_response.Iv
        result["RequestId"] = advance_encrypt_response.RequestId
        result["Algorithm"] = advance_encrypt_response.Algorithm
        result["PaddingMode"] = advance_encrypt_response.PaddingMode
        result["KeyVersionId"] = advance_encrypt_response.KeyVersionId
        return result

    @staticmethod
    def get_serialized_advance_decrypt_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.AdvanceDecryptRequest()
        ciphertext_blob = req_body.get("CiphertextBlob")
        if ciphertext_blob:
            request.CiphertextBlob = ciphertext_blob
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        algorithm = req_body.get("Algorithm")
        if algorithm:
            request.Algorithm = algorithm
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        iv = req_body.get("Iv")
        if iv:
            request.Iv = iv
        padding_mode = req_body.get("PaddingMode")
        if padding_mode:
            request.PaddingMode = padding_mode
        return request.SerializeToString()

    @staticmethod
    def parse_advance_decrypt_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        advance_decrypt_response = api_pb2.AdvanceDecryptResponse()
        advance_decrypt_response.ParseFromString(res_body)
        result["KeyId"] = advance_decrypt_response.KeyId
        result["Plaintext"] = advance_decrypt_response.Plaintext
        result["RequestId"] = advance_decrypt_response.RequestId
        result["Algorithm"] = advance_decrypt_response.Algorithm
        result["PaddingMode"] = advance_decrypt_response.PaddingMode
        result["KeyVersionId"] = advance_decrypt_response.KeyVersionId
        return result

    @staticmethod
    def get_serialized_advance_generate_data_key_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.AdvanceGenerateDataKeyRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        number_of_bytes = req_body.get("NumberOfBytes")
        if number_of_bytes:
            request.NumberOfBytes = number_of_bytes
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        return request.SerializeToString()

    @staticmethod
    def parse_advance_generate_data_key_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        advance_generate_data_key_response = api_pb2.AdvanceGenerateDataKeyResponse()
        advance_generate_data_key_response.ParseFromString(res_body)
        result["KeyId"] = advance_generate_data_key_response.KeyId
        result["Iv"] = advance_generate_data_key_response.Iv
        result["Plaintext"] = advance_generate_data_key_response.Plaintext
        result["CiphertextBlob"] = advance_generate_data_key_response.CiphertextBlob
        result["RequestId"] = advance_generate_data_key_response.RequestId
        result["Algorithm"] = advance_generate_data_key_response.Algorithm
        result["KeyVersionId"] = advance_generate_data_key_response.KeyVersionId
        return result

    @staticmethod
    def get_serialized_encrypt_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.EncryptRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        plaintext = req_body.get("Plaintext")
        if plaintext:
            request.Plaintext = plaintext
        algorithm = req_body.get("Algorithm")
        if algorithm:
            request.Algorithm = algorithm
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        iv = req_body.get("Iv")
        if iv:
            request.Iv = iv
        padding_mode = req_body.get("PaddingMode")
        if padding_mode:
            request.PaddingMode = padding_mode
        return request.SerializeToString()

    @staticmethod
    def get_serialized_generate_data_key_pair_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.GenerateDataKeyPairRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        algorithm = req_body.get("Algorithm")
        if algorithm:
            request.Algorithm = algorithm
        key_pair_spec = req_body.get("KeyPairSpec")
        if key_pair_spec:
            request.KeyPairSpec = key_pair_spec
        key_format = req_body.get("KeyFormat")
        if key_format:
            request.KeyFormat = key_format
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        return request.SerializeToString()

    @staticmethod
    def parse_generate_data_key_pair_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        generate_data_key_pair_response = api_pb2.GenerateDataKeyPairResponse()
        generate_data_key_pair_response.ParseFromString(res_body)
        result["KeyId"] = generate_data_key_pair_response.KeyId
        result["Iv"] = generate_data_key_pair_response.Iv
        result["KeyPairSpec"] = generate_data_key_pair_response.KeyPairSpec
        result["PrivateKeyPlaintext"] = generate_data_key_pair_response.PrivateKeyPlaintext
        result["PrivateKeyCiphertextBlob"] = generate_data_key_pair_response.PrivateKeyCiphertextBlob
        result["PublicKey"] = generate_data_key_pair_response.PublicKey
        result["RequestId"] = generate_data_key_pair_response.RequestId
        result["Algorithm"] = generate_data_key_pair_response.Algorithm
        return result

    @staticmethod
    def get_serialized_generate_data_key_pair_without_plaintext_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.GenerateDataKeyPairWithoutPlaintextRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        algorithm = req_body.get("Algorithm")
        if algorithm:
            request.Algorithm = algorithm
        key_pair_spec = req_body.get("KeyPairSpec")
        if key_pair_spec:
            request.KeyPairSpec = key_pair_spec
        key_format = req_body.get("KeyFormat")
        if key_format:
            request.KeyFormat = key_format
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        return request.SerializeToString()

    @staticmethod
    def parse_generate_data_key_pair_without_plaintext_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        generate_data_key_pair_without_plaintext_response = api_pb2.GenerateDataKeyPairWithoutPlaintextResponse()
        generate_data_key_pair_without_plaintext_response.ParseFromString(res_body)
        result["KeyId"] = generate_data_key_pair_without_plaintext_response.KeyId
        result["Iv"] = generate_data_key_pair_without_plaintext_response.Iv
        result["KeyPairSpec"] = generate_data_key_pair_without_plaintext_response.KeyPairSpec
        result["PrivateKeyCiphertextBlob"] = generate_data_key_pair_without_plaintext_response.PrivateKeyCiphertextBlob
        result["PublicKey"] = generate_data_key_pair_without_plaintext_response.PublicKey
        result["RequestId"] = generate_data_key_pair_without_plaintext_response.RequestId
        result["Algorithm"] = generate_data_key_pair_without_plaintext_response.Algorithm
        return result

    @staticmethod
    def get_serialized_advance_generate_data_key_pair_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.AdvanceGenerateDataKeyPairRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        key_pair_spec = req_body.get("KeyPairSpec")
        if key_pair_spec:
            request.KeyPairSpec = key_pair_spec
        key_format = req_body.get("KeyFormat")
        if key_format:
            request.KeyFormat = key_format
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        return request.SerializeToString()

    @staticmethod
    def parse_advance_generate_data_key_pair_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        advance_generate_data_key_pair_response = api_pb2.AdvanceGenerateDataKeyPairResponse()
        advance_generate_data_key_pair_response.ParseFromString(res_body)
        result["KeyId"] = advance_generate_data_key_pair_response.KeyId
        result["Iv"] = advance_generate_data_key_pair_response.Iv
        result["KeyPairSpec"] = advance_generate_data_key_pair_response.KeyPairSpec
        result["PrivateKeyPlaintext"] = advance_generate_data_key_pair_response.PrivateKeyPlaintext
        result["PrivateKeyCiphertextBlob"] = advance_generate_data_key_pair_response.PrivateKeyCiphertextBlob
        result["PublicKey"] = advance_generate_data_key_pair_response.PublicKey
        result["RequestId"] = advance_generate_data_key_pair_response.RequestId
        result["Algorithm"] = advance_generate_data_key_pair_response.Algorithm
        result["KeyVersionId"] = advance_generate_data_key_pair_response.KeyVersionId
        return result

    @staticmethod
    def get_serialized_advance_generate_data_key_pair_without_plaintext_request(
            req_body: Dict[str, Any],
    ) -> bytes:

        request = api_pb2.AdvanceGenerateDataKeyPairWithoutPlaintextRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            request.KeyId = key_id
        key_pair_spec = req_body.get("KeyPairSpec")
        if key_pair_spec:
            request.KeyPairSpec = key_pair_spec
        key_format = req_body.get("KeyFormat")
        if key_format:
            request.KeyFormat = key_format
        aad = req_body.get("Aad")
        if aad:
            request.Aad = aad
        return request.SerializeToString()

    @staticmethod
    def parse_advance_generate_data_key_pair_without_plaintext_response(
            res_body: bytes,
    ) -> dict:

        result = {}
        advance_generate_data_key_pair_without_plaintext_response = api_pb2.AdvanceGenerateDataKeyPairWithoutPlaintextResponse()
        advance_generate_data_key_pair_without_plaintext_response.ParseFromString(res_body)
        result["KeyId"] = advance_generate_data_key_pair_without_plaintext_response.KeyId
        result["Iv"] = advance_generate_data_key_pair_without_plaintext_response.Iv
        result["KeyPairSpec"] = advance_generate_data_key_pair_without_plaintext_response.KeyPairSpec
        result[
            "PrivateKeyCiphertextBlob"] = advance_generate_data_key_pair_without_plaintext_response.PrivateKeyCiphertextBlob
        result["PublicKey"] = advance_generate_data_key_pair_without_plaintext_response.PublicKey
        result["RequestId"] = advance_generate_data_key_pair_without_plaintext_response.RequestId
        result["Algorithm"] = advance_generate_data_key_pair_without_plaintext_response.Algorithm
        result["KeyVersionId"] = advance_generate_data_key_pair_without_plaintext_response.KeyVersionId
        return result
