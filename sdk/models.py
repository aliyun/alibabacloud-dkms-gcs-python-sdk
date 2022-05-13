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
