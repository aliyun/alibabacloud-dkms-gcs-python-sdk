# coding=utf-8
from Tea.model import TeaModel


class DKMSRequest(TeaModel):
    def __init__(self):
        self.request_headers = None


class DKMSResponse(TeaModel):
    def __init__(self):
        self.response_headers = None


class EncryptRequest(DKMSRequest):
    def __init__(
            self,
            key_id=None,
            plaintext=None,
            algorithm=None,
            aad=None,
            iv=None,
            padding_mode=None,
    ):
        super(EncryptRequest, self).__init__()
        self.key_id = key_id
        self.plaintext = plaintext
        self.algorithm = algorithm
        self.aad = aad
        self.iv = iv
        self.padding_mode = padding_mode

    def validate(self):
        pass

    def to_map(self):
        _map = super(EncryptRequest, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.plaintext is not None:
            result['Plaintext'] = self.plaintext
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.aad is not None:
            result['Aad'] = self.aad
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.padding_mode is not None:
            result['PaddingMode'] = self.padding_mode
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Plaintext') is not None:
            self.plaintext = m.get('Plaintext')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('Aad') is not None:
            self.aad = m.get('Aad')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('PaddingMode') is not None:
            self.padding_mode = m.get('PaddingMode')
        return self


class EncryptResponse(DKMSResponse):
    def __init__(
            self,
            key_id=None,
            ciphertext_blob=None,
            iv=None,
            algorithm=None,
            padding_mode=None,
            request_id=None,
    ):
        super(EncryptResponse, self).__init__()
        self.key_id = key_id
        self.ciphertext_blob = ciphertext_blob
        self.iv = iv
        self.algorithm = algorithm
        self.padding_mode = padding_mode
        self.request_id = request_id

    def validate(self):
        pass

    def to_map(self):
        _map = super(EncryptResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.ciphertext_blob is not None:
            result['CiphertextBlob'] = self.ciphertext_blob
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.padding_mode is not None:
            result['PaddingMode'] = self.padding_mode
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('CiphertextBlob') is not None:
            self.ciphertext_blob = m.get('CiphertextBlob')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('PaddingMode') is not None:
            self.padding_mode = m.get('PaddingMode')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        return self


class DecryptRequest(DKMSRequest):
    def __init__(
            self,
            ciphertext_blob=None,
            key_id=None,
            algorithm=None,
            aad=None,
            iv=None,
            padding_mode=None,
    ):
        super(DecryptRequest, self).__init__()
        self.ciphertext_blob = ciphertext_blob
        self.key_id = key_id
        self.algorithm = algorithm
        self.aad = aad
        self.iv = iv
        self.padding_mode = padding_mode

    def validate(self):
        pass

    def to_map(self):
        _map = super(DecryptRequest, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.ciphertext_blob is not None:
            result['CiphertextBlob'] = self.ciphertext_blob
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.aad is not None:
            result['Aad'] = self.aad
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.padding_mode is not None:
            result['PaddingMode'] = self.padding_mode
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('CiphertextBlob') is not None:
            self.ciphertext_blob = m.get('CiphertextBlob')
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('Aad') is not None:
            self.aad = m.get('Aad')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('PaddingMode') is not None:
            self.padding_mode = m.get('PaddingMode')
        return self


class DecryptResponse(DKMSResponse):
    def __init__(
            self,
            key_id=None,
            plaintext=None,
            algorithm=None,
            padding_mode=None,
            request_id=None,
    ):
        super(DecryptResponse, self).__init__()
        self.key_id = key_id
        self.plaintext = plaintext
        self.algorithm = algorithm
        self.padding_mode = padding_mode
        self.request_id = request_id

    def validate(self):
        pass

    def to_map(self):
        _map = super(DecryptResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.plaintext is not None:
            result['Plaintext'] = self.plaintext
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.padding_mode is not None:
            result['PaddingMode'] = self.padding_mode
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Plaintext') is not None:
            self.plaintext = m.get('Plaintext')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('PaddingMode') is not None:
            self.padding_mode = m.get('PaddingMode')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        return self


class HmacRequest(DKMSRequest):
    def __init__(
            self,
            key_id=None,
            message=None,
    ):
        super(HmacRequest, self).__init__()
        self.key_id = key_id
        self.message = message

    def validate(self):
        pass

    def to_map(self):
        _map = super(HmacRequest, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.message is not None:
            result['Message'] = self.message
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Message') is not None:
            self.message = m.get('Message')
        return self


class HmacResponse(DKMSResponse):
    def __init__(
            self,
            key_id=None,
            signature=None,
            request_id=None,
    ):
        super(HmacResponse, self).__init__()
        self.key_id = key_id
        self.signature = signature
        self.request_id = request_id

    def validate(self):
        pass

    def to_map(self):
        _map = super(HmacResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.signature is not None:
            result['Signature'] = self.signature
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Signature') is not None:
            self.signature = m.get('Signature')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        return self


class SignRequest(DKMSRequest):
    def __init__(
            self,
            key_id=None,
            algorithm=None,
            message=None,
            message_type=None,
    ):
        super(SignRequest, self).__init__()
        self.key_id = key_id
        self.algorithm = algorithm
        self.message = message
        self.message_type = message_type

    def validate(self):
        pass

    def to_map(self):
        _map = super(SignRequest, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.message is not None:
            result['Message'] = self.message
        if self.message_type is not None:
            result['MessageType'] = self.message_type
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('Message') is not None:
            self.message = m.get('Message')
        if m.get('MessageType') is not None:
            self.message_type = m.get('MessageType')
        return self


class SignResponse(DKMSResponse):
    def __init__(
            self,
            key_id=None,
            signature=None,
            algorithm=None,
            message_type=None,
            request_id=None,
    ):
        super(SignResponse, self).__init__()
        self.key_id = key_id
        self.signature = signature
        self.algorithm = algorithm
        self.message_type = message_type
        self.request_id = request_id

    def validate(self):
        pass

    def to_map(self):
        _map = super(SignResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.signature is not None:
            result['Signature'] = self.signature
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.message_type is not None:
            result['MessageType'] = self.message_type
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Signature') is not None:
            self.signature = m.get('Signature')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('MessageType') is not None:
            self.message_type = m.get('MessageType')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        return self


class VerifyRequest(DKMSRequest):
    def __init__(
            self,
            key_id=None,
            signature=None,
            algorithm=None,
            message=None,
            message_type=None,
    ):
        super(VerifyRequest, self).__init__()
        self.key_id = key_id
        self.signature = signature
        self.algorithm = algorithm
        self.message = message
        self.message_type = message_type

    def validate(self):
        pass

    def to_map(self):
        _map = super(VerifyRequest, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.signature is not None:
            result['Signature'] = self.signature
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.message is not None:
            result['Message'] = self.message
        if self.message_type is not None:
            result['MessageType'] = self.message_type
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Signature') is not None:
            self.signature = m.get('Signature')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('Message') is not None:
            self.message = m.get('Message')
        if m.get('MessageType') is not None:
            self.message_type = m.get('MessageType')
        return self


class VerifyResponse(DKMSResponse):
    def __init__(
            self,
            key_id=None,
            value=None,
            algorithm=None,
            message_type=None,
            request_id=None,
    ):
        super(VerifyResponse, self).__init__()
        self.key_id = key_id
        self.value = value
        self.algorithm = algorithm
        self.message_type = message_type
        self.request_id = request_id

    def validate(self):
        pass

    def to_map(self):
        _map = super(VerifyResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.value is not None:
            result['Value'] = self.value
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.message_type is not None:
            result['MessageType'] = self.message_type
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Value') is not None:
            self.value = m.get('Value')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('MessageType') is not None:
            self.message_type = m.get('MessageType')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        return self


class GenerateRandomRequest(DKMSRequest):
    def __init__(
            self,
            length=None,
    ):
        super(GenerateRandomRequest, self).__init__()
        self.length = length

    def validate(self):
        pass

    def to_map(self):
        _map = super(GenerateRandomRequest, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.length is not None:
            result['Length'] = self.length
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('Length') is not None:
            self.length = m.get('Length')
        return self


class GenerateRandomResponse(DKMSResponse):
    def __init__(
            self,
            random=None,
            request_id=None,
    ):
        super(GenerateRandomResponse, self).__init__()
        self.random = random
        self.request_id = request_id

    def validate(self):
        pass

    def to_map(self):
        _map = super(GenerateRandomResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.random is not None:
            result['Random'] = self.random
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('Random') is not None:
            self.random = m.get('Random')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        return self


class GenerateDataKeyRequest(DKMSRequest):
    def __init__(
            self,
            key_id=None,
            algorithm=None,
            number_of_bytes=None,
            aad=None,
    ):
        super(GenerateDataKeyRequest, self).__init__()
        self.key_id = key_id
        self.algorithm = algorithm
        self.number_of_bytes = number_of_bytes
        self.aad = aad

    def validate(self):
        pass

    def to_map(self):
        _map = super(GenerateDataKeyRequest, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.number_of_bytes is not None:
            result['NumberOfBytes'] = self.number_of_bytes
        if self.aad is not None:
            result['Aad'] = self.aad
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('NumberOfBytes') is not None:
            self.number_of_bytes = m.get('NumberOfBytes')
        if m.get('Aad') is not None:
            self.aad = m.get('Aad')
        return self


class GenerateDataKeyResponse(DKMSResponse):
    def __init__(
            self,
            key_id=None,
            iv=None,
            plaintext=None,
            ciphertext_blob=None,
            algorithm=None,
            request_id=None,
    ):
        super(GenerateDataKeyResponse, self).__init__()
        self.key_id = key_id
        self.iv = iv
        self.plaintext = plaintext
        self.ciphertext_blob = ciphertext_blob
        self.algorithm = algorithm
        self.request_id = request_id

    def validate(self):
        pass

    def to_map(self):
        _map = super(GenerateDataKeyResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.plaintext is not None:
            result['Plaintext'] = self.plaintext
        if self.ciphertext_blob is not None:
            result['CiphertextBlob'] = self.ciphertext_blob
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('Plaintext') is not None:
            self.plaintext = m.get('Plaintext')
        if m.get('CiphertextBlob') is not None:
            self.ciphertext_blob = m.get('CiphertextBlob')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        return self


class GetPublicKeyRequest(DKMSRequest):
    def __init__(
            self,
            key_id=None,
    ):
        super(GetPublicKeyRequest, self).__init__()
        self.key_id = key_id

    def validate(self):
        pass

    def to_map(self):
        _map = super(GetPublicKeyRequest, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        return self


class GetPublicKeyResponse(DKMSResponse):
    def __init__(
            self,
            key_id=None,
            public_key=None,
            request_id=None,
    ):
        super(GetPublicKeyResponse, self).__init__()
        self.key_id = key_id
        self.public_key = public_key
        self.request_id = request_id

    def validate(self):
        pass

    def to_map(self):
        _map = super(GetPublicKeyResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.public_key is not None:
            result['PublicKey'] = self.public_key
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('PublicKey') is not None:
            self.public_key = m.get('PublicKey')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        return self


class GetSecretValueRequest(DKMSRequest):
    def __init__(
            self,
            secret_name=None,
            version_stage=None,
            version_id=None,
            fetch_extended_config=None
    ):
        super(GetSecretValueRequest, self).__init__()
        self.secret_name = secret_name
        self.version_stage = version_stage
        self.version_id = version_id
        self.fetch_extended_config = fetch_extended_config

    def validate(self):
        pass

    def to_map(self):
        _map = super(GetSecretValueRequest, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.secret_name is not None:
            result['SecretName'] = self.secret_name
        if self.version_stage is not None:
            result['VersionStage'] = self.version_stage
        if self.version_id is not None:
            result['VersionId'] = self.version_id
        if self.fetch_extended_config is not None:
            result['FetchExtendedConfig'] = self.fetch_extended_config
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('SecretName') is not None:
            self.secret_name = m.get('SecretName')
        if m.get('VersionStage') is not None:
            self.version_stage = m.get('VersionStage')
        if m.get('VersionId') is not None:
            self.version_id = m.get('VersionId')
        if m.get('FetchExtendedConfig') is not None:
            self.fetch_extended_config = m.get('FetchExtendedConfig')
        return self


class GetSecretValueResponse(DKMSResponse):
    def __init__(
        self,
        secret_name=None,
        secret_type=None,
        secret_data=None,
        secret_data_type=None,
        version_stages=None,
        version_id=None,
        create_time=None,
        request_id=None,
        last_rotation_date=None,
        next_rotation_date=None,
        extended_config=None,
        automatic_rotation=None,
        rotation_interval=None,
    ):
        super(GetSecretValueResponse, self).__init__()
        self.secret_name = secret_name
        self.secret_type = secret_type
        self.secret_data = secret_data
        self.secret_data_type = secret_data_type
        self.version_stages = version_stages
        self.version_id = version_id
        self.create_time = create_time
        self.request_id = request_id
        self.last_rotation_date = last_rotation_date
        self.next_rotation_date = next_rotation_date
        self.extended_config = extended_config
        self.automatic_rotation = automatic_rotation
        self.rotation_interval = rotation_interval

    def validate(self):
        pass

    def to_map(self):
        _map = super(GetSecretValueResponse, self).to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.secret_name is not None:
            result['SecretName'] = self.secret_name
        if self.secret_type is not None:
            result['SecretType'] = self.secret_type
        if self.secret_data is not None:
            result['SecretData'] = self.secret_data
        if self.secret_data_type is not None:
            result['SecretDataType'] = self.secret_data_type
        if self.version_stages is not None:
            result['VersionStages'] = self.version_stages
        if self.version_id is not None:
            result['VersionId'] = self.version_id
        if self.create_time is not None:
            result['CreateTime'] = self.create_time
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.last_rotation_date is not None:
            result['LastRotationDate'] = self.last_rotation_date
        if self.next_rotation_date is not None:
            result['NextRotationDate'] = self.next_rotation_date
        if self.extended_config is not None:
            result['ExtendedConfig'] = self.extended_config
        if self.automatic_rotation is not None:
            result['AutomaticRotation'] = self.automatic_rotation
        if self.rotation_interval is not None:
            result['RotationInterval'] = self.rotation_interval
        return result

    def from_map(self, m=None):
        m = m or dict()
        if m.get('SecretName') is not None:
            self.secret_name = m.get('SecretName')
        if m.get('SecretType') is not None:
            self.secret_type = m.get('SecretType')
        if m.get('SecretData') is not None:
            self.secret_data = m.get('SecretData')
        if m.get('SecretDataType') is not None:
            self.secret_data_type = m.get('SecretDataType')
        if m.get('VersionStages') is not None:
            self.version_stages = m.get('VersionStages')
        if m.get('VersionId') is not None:
            self.version_id = m.get('VersionId')
        if m.get('CreateTime') is not None:
            self.create_time = m.get('CreateTime')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('LastRotationDate') is not None:
            self.last_rotation_date = m.get('LastRotationDate')
        if m.get('NextRotationDate') is not None:
            self.next_rotation_date = m.get('NextRotationDate')
        if m.get('ExtendedConfig') is not None:
            self.extended_config = m.get('ExtendedConfig')
        if m.get('AutomaticRotation') is not None:
            self.automatic_rotation = m.get('AutomaticRotation')
        if m.get('RotationInterval') is not None:
            self.rotation_interval = m.get('RotationInterval')
        return self
