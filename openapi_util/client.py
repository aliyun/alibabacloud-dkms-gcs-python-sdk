# coding=utf-8
import hashlib

from openapi_util.protobuf import api_pb2


class Client(object):
    def __init__(self):
        pass

    @staticmethod
    def get_host(
            region_id,
            endpoint,
    ):
        if endpoint:
            return endpoint
        if region_id:
            return "cn-hangzhou"
        return "kms-instance." + region_id + ".aliyuncs.com"

    @staticmethod
    def get_err_message(
            msg,
    ):
        result = {}
        error = api_pb2.Error()
        error.ParseFromString(msg)
        result["Code"] = error.ErrorCode
        result["Message"] = error.ErrorMessage
        result["RequestId"] = error.RequestId
        return result

    @staticmethod
    def get_string_to_sign(
            request,
    ):
        if not request:
            return ""
        method = request.method
        pathname = request.pathname
        headers = request.headers
        query = request.query
        content_sha256 = "" if not headers.get("content-sha256") else headers.get("content-sha256")
        content_type = "" if not headers.get("content-type") else headers.get("content-type")
        date = "" if not headers.get("date") else headers.get("date")
        header = method + "\n" + content_sha256 + "\n" + content_type + "\n" + date + "\n"
        canonicalized_headers = Client._get_canonicalized_headers(headers)
        canonicalized_resource = Client._get_canonicalized_resource(pathname, query)
        return header + canonicalized_headers + canonicalized_resource

    @staticmethod
    def _get_canonicalized_headers(headers):
        if not headers:
            return ""
        prefix = "x-kms-"
        keys = headers.keys()
        canonicalized_keys = []
        for key in keys:
            if key.startswith(prefix):
                canonicalized_keys.append(key)
        canonicalized_keys.sort()
        result_list = []
        for canonicalized_key in canonicalized_keys:
            result_list.append(canonicalized_key)
            result_list.append(":")
            result_list.append(headers.get(canonicalized_key).strip())
            result_list.append("\n")
        return "".join(result_list)

    @staticmethod
    def _get_canonicalized_resource(pathname, query):
        if not pathname:
            return "/"
        if not query:
            return pathname
        keys = query.keys()
        path = [pathname, "?"]
        return Client._get_canonicalized_query_string(path, query, list(keys))

    @staticmethod
    def _get_canonicalized_query_string(path, query, keys):
        if not query:
            return ""
        if not path:
            path = []
        if not keys:
            return ""
        keys.sort()
        for key in keys:
            path.append(key)
            value = query.get(key)
            if value:
                path.append("=")
                path.append(value)
            path.append("&")
        path.pop()
        return "".join(path)

    @staticmethod
    def get_content_length(
            req_body,
    ):
        return str(len(req_body))

    @staticmethod
    def get_content_sha256(
            req_body,
    ):
        return hashlib.sha256(req_body).hexdigest().upper()

    @staticmethod
    def to_hex_string(
            byte_array,
    ):
        return byte_array.hex().upper()

    @staticmethod
    def get_serialized_encrypt_request(
            req_body,
    ):
        encrypt_request = api_pb2.EncryptRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            encrypt_request.KeyId = key_id
        plaintext = req_body.get("Plaintext")
        if plaintext:
            encrypt_request.Plaintext = plaintext
        algorithm = req_body.get("Algorithm")
        if algorithm:
            encrypt_request.Algorithm = algorithm
        iv = req_body.get("Iv")
        if iv:
            encrypt_request.Iv = iv
        aad = req_body.get("Aad")
        if aad:
            encrypt_request.Aad = aad
        padding_mode = req_body.get("PaddingMode")
        if padding_mode:
            encrypt_request.PaddingMode = padding_mode
        return encrypt_request.SerializeToString()

    @staticmethod
    def parse_encrypt_response(
            res_body,
    ):
        result = {}
        encrypt_response = api_pb2.EncryptResponse()
        encrypt_response.ParseFromString(res_body)
        result["KeyId"] = encrypt_response.KeyId
        result["CiphertextBlob"] = encrypt_response.CiphertextBlob
        result["Iv"] = encrypt_response.Iv
        result["Algorithm"] = encrypt_response.Algorithm
        result["PaddingMode"] = encrypt_response.PaddingMode
        result["RequestId"] = encrypt_response.RequestId
        return result

    @staticmethod
    def get_serialized_decrypt_request(
            req_body,
    ):
        decrypt_request = api_pb2.DecryptRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            decrypt_request.KeyId = key_id
        ciphertext_blob = req_body.get("CiphertextBlob")
        if ciphertext_blob:
            decrypt_request.CiphertextBlob = ciphertext_blob
        algorithm = req_body.get("Algorithm")
        if algorithm:
            decrypt_request.Algorithm = algorithm
        iv = req_body.get("Iv")
        if iv:
            decrypt_request.Iv = iv
        aad = req_body.get("Aad")
        if aad:
            decrypt_request.Aad = aad
        padding_mode = req_body.get("PaddingMode")
        if padding_mode:
            decrypt_request.PaddingMode = padding_mode
        return decrypt_request.SerializeToString()

    @staticmethod
    def parse_decrypt_response(
            res_body,
    ):
        result = {}
        decrypt_response = api_pb2.DecryptResponse()
        decrypt_response.ParseFromString(res_body)
        result["KeyId"] = decrypt_response.KeyId
        result["Plaintext"] = decrypt_response.Plaintext
        result["Algorithm"] = decrypt_response.Algorithm
        result["PaddingMode"] = decrypt_response.PaddingMode
        result["RequestId"] = decrypt_response.RequestId
        return result

    @staticmethod
    def get_serialized_hmac_request(
            req_body,
    ):
        hmac_request = api_pb2.HmacRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            hmac_request.KeyId = key_id
        message = req_body.get("Message")
        if message:
            hmac_request.Message = message
        return hmac_request.SerializeToString()

    @staticmethod
    def parse_hmac_response(
            res_body,
    ):
        result = {}
        hmac_response = api_pb2.HmacResponse()
        hmac_response.ParseFromString(res_body)
        result["KeyId"] = hmac_response.KeyId
        result["Signature"] = hmac_response.Signature
        result["RequestId"] = hmac_response.RequestId
        return result

    @staticmethod
    def get_serialized_sign_request(
            req_body,
    ):
        sign_request = api_pb2.SignRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            sign_request.KeyId = key_id
        algorithm = req_body.get("Algorithm")
        if algorithm:
            sign_request.Algorithm = algorithm
        message = req_body.get("Message")
        if message:
            sign_request.Message = message
        message_type = req_body.get("MessageType")
        if message_type:
            sign_request.MessageType = message_type
        return sign_request.SerializeToString()

    @staticmethod
    def parse_sign_response(
            res_body,
    ):
        result = {}
        sign_response = api_pb2.SignResponse()
        sign_response.ParseFromString(res_body)
        result["KeyId"] = sign_response.KeyId
        result["Signature"] = sign_response.Signature
        result["Algorithm"] = sign_response.Algorithm
        result["MessageType"] = sign_response.MessageType
        result["RequestId"] = sign_response.RequestId
        return result

    @staticmethod
    def get_serialized_verify_request(
            req_body,
    ):
        verify_request = api_pb2.VerifyRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            verify_request.KeyId = key_id
        algorithm = req_body.get("Algorithm")
        if algorithm:
            verify_request.Algorithm = algorithm
        signature = req_body.get("Signature")
        if signature:
            verify_request.Signature = signature
        message = req_body.get("Message")
        if message:
            verify_request.Message = message
        message_type = req_body.get("MessageType")
        if message_type:
            verify_request.MessageType = message_type
        return verify_request.SerializeToString()

    @staticmethod
    def parse_verify_response(
            res_body,
    ):
        result = {}
        verify_response = api_pb2.VerifyResponse()
        verify_response.ParseFromString(res_body)
        result["KeyId"] = verify_response.KeyId
        result["Value"] = verify_response.Value
        result["Algorithm"] = verify_response.Algorithm
        result["MessageType"] = verify_response.MessageType
        result["RequestId"] = verify_response.RequestId
        return result

    @staticmethod
    def get_serialized_generate_random_request(
            req_body,
    ):
        random_request = api_pb2.GenerateRandomRequest()
        length = req_body.get("Length")
        if length:
            random_request.Length = length
        return random_request.SerializeToString()

    @staticmethod
    def parse_generate_random_response(
            res_body,
    ):
        result = {}
        random_response = api_pb2.GenerateRandomResponse()
        random_response.ParseFromString(res_body)
        result["Random"] = random_response.Random
        result["RequestId"] = random_response.RequestId
        return result

    @staticmethod
    def get_serialized_generate_data_key_request(
            req_body,
    ):
        generate_data_key_request = api_pb2.GenerateDataKeyRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            generate_data_key_request.KeyId = key_id
        algorithm = req_body.get("Algorithm")
        if algorithm:
            generate_data_key_request.Algorithm = algorithm
        number_of_bytes = req_body.get("NumberOfBytes")
        if number_of_bytes:
            generate_data_key_request.NumberOfBytes = number_of_bytes
        aad = req_body.get("Aad")
        if aad:
            generate_data_key_request.Aad = aad
        return generate_data_key_request.SerializeToString()

    @staticmethod
    def parse_generate_data_key_response(
            res_body,
    ):
        result = {}
        generate_data_key_response = api_pb2.GenerateDataKeyResponse()
        generate_data_key_response.ParseFromString(res_body)
        result["KeyId"] = generate_data_key_response.KeyId
        result["Iv"] = generate_data_key_response.Iv
        result["Plaintext"] = generate_data_key_response.Plaintext
        result["CiphertextBlob"] = generate_data_key_response.CiphertextBlob
        result["Algorithm"] = generate_data_key_response.Algorithm
        result["RequestId"] = generate_data_key_response.RequestId
        return result

    @staticmethod
    def get_serialized_get_public_key_request(
            req_body,
    ):
        get_public_key_request = api_pb2.GetPublicKeyRequest()
        key_id = req_body.get("KeyId")
        if key_id:
            get_public_key_request.KeyId = key_id
        return get_public_key_request.SerializeToString()

    @staticmethod
    def parse_get_public_key_response(
            res_body,
    ):
        result = {}
        get_public_key_response = api_pb2.GetPublicKeyResponse()
        get_public_key_response.ParseFromString(res_body)
        result["KeyId"] = get_public_key_response.KeyId
        result["PublicKey"] = get_public_key_response.PublicKey
        result["RequestId"] = get_public_key_response.RequestId
        return result

    @staticmethod
    def get_serialized_hash_request(
            req_body,
    ):
        hash_request = api_pb2.HashRequest()
        algorithm = req_body.get("Algorithm")
        if algorithm:
            hash_request.Algorithm = algorithm
        message = req_body.get("Message")
        if message:
            hash_request.Message = message
        return hash_request.SerializeToString()

    @staticmethod
    def parse_hash_response(
            res_body,
    ):
        result = {}
        hash_response = api_pb2.HashResponse()
        hash_response.ParseFromString(res_body)
        result["Digest"] = hash_response.Digest
        result["RequestId"] = hash_response.RequestId
        return result

    @staticmethod
    def get_serialized_kms_encrypt_request(
            req_body,
    ):
        kms_encrypt_request = api_pb2.KmsEncryptRequest()
        plaintext = req_body.get("Plaintext")
        if plaintext:
            kms_encrypt_request.Plaintext = plaintext
        key_id = req_body.get("KeyId")
        if key_id:
            kms_encrypt_request.KeyId = key_id
        aad = req_body.get("Aad")
        if aad:
            kms_encrypt_request.Aad = aad
        return kms_encrypt_request.SerializeToString()

    @staticmethod
    def parse_kms_encrypt_response(
            res_body,
    ):
        result = {}
        kms_encrypt_response = api_pb2.KmsEncryptResponse()
        kms_encrypt_response.ParseFromString(res_body)
        result["KeyId"] = kms_encrypt_response.KeyId
        result["CiphertextBlob"] = kms_encrypt_response.CiphertextBlob
        result["RequestId"] = kms_encrypt_response.RequestId
        return result

    @staticmethod
    def get_serialized_kms_decrypt_request(
            req_body,
    ):
        kms_decrypt_request = api_pb2.KmsDecryptRequest()
        ciphertext_blob = req_body.get("CiphertextBlob")
        if ciphertext_blob:
            kms_decrypt_request.CiphertextBlob = ciphertext_blob
        aad = req_body.get("Aad")
        if aad:
            kms_decrypt_request.Aad = aad
        return kms_decrypt_request.SerializeToString()

    @staticmethod
    def parse_kms_decrypt_response(
            res_body,
    ):
        result = {}
        kms_decrypt_response = api_pb2.KmsDecryptResponse()
        kms_decrypt_response.ParseFromString(res_body)
        result["KeyId"] = kms_decrypt_response.KeyId
        result["Plaintext"] = kms_decrypt_response.Plaintext
        result["RequestId"] = kms_decrypt_response.RequestId
        return result

    @staticmethod
    def get_serialized_get_secret_value_request(
            req_body,
    ):
        get_secret_value_request = api_pb2.GetSecretValueRequest()
        secret_name = req_body.get("SecretName")
        if secret_name:
            get_secret_value_request.SecretName = secret_name
        version_stage = req_body.get("VersionStage")
        if version_stage:
            get_secret_value_request.VersionStage = version_stage
        version_id = req_body.get("VersionId")
        if version_id:
            get_secret_value_request.VersionId = version_id
        fetch_extended_config = req_body.get("FetchExtendedConfig")
        if fetch_extended_config:
            get_secret_value_request.FetchExtendedConfig = fetch_extended_config
        return get_secret_value_request.SerializeToString()

    @staticmethod
    def parse_get_secret_value_response(
            res_body,
    ):
        result = {}
        get_secret_value_response = api_pb2.GetSecretValueResponse()
        get_secret_value_response.ParseFromString(res_body)
        result["SecretName"] = get_secret_value_response.SecretName
        result["SecretType"] = get_secret_value_response.SecretType
        result["SecretData"] = get_secret_value_response.SecretData
        result["SecretDataType"] = get_secret_value_response.SecretDataType
        result["VersionStages"] = [version_stage for version_stage in get_secret_value_response.VersionStages]
        result["VersionId"] = get_secret_value_response.VersionId
        result["CreateTime"] = get_secret_value_response.CreateTime
        result["LastRotationDate"] = get_secret_value_response.LastRotationDate
        result["NextRotationDate"] = get_secret_value_response.NextRotationDate
        result["ExtendedConfig"] = get_secret_value_response.ExtendedConfig
        result["AutomaticRotation"] = get_secret_value_response.AutomaticRotation
        result["RotationInterval"] = get_secret_value_response.RotationInterval
        result["RequestId"] = get_secret_value_response.RequestId
        return result
