# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
from Tea.model import TeaModel
from typing import Dict, List


class EncryptRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            plaintext: bytes = None,
            algorithm: str = None,
            aad: bytes = None,
            iv: bytes = None,
            padding_mode: str = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 待加密的明文数据
        self.plaintext = plaintext
        # 加密算法
        self.algorithm = algorithm
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 对数据加密时使用的初始向量
        self.iv = iv
        # 填充模式
        self.padding_mode = padding_mode
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
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
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class EncryptResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            ciphertext_blob: bytes = None,
            iv: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            padding_mode: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 数据被指定密钥加密后的密文
        self.ciphertext_blob = ciphertext_blob
        # 加密数据时使用的初始向量
        self.iv = iv
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 填充模式
        self.padding_mode = padding_mode
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.ciphertext_blob is not None:
            result['CiphertextBlob'] = self.ciphertext_blob
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.padding_mode is not None:
            result['PaddingMode'] = self.padding_mode
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('CiphertextBlob') is not None:
            self.ciphertext_blob = m.get('CiphertextBlob')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('PaddingMode') is not None:
            self.padding_mode = m.get('PaddingMode')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class DecryptRequest(TeaModel):
    def __init__(
            self,
            ciphertext_blob: bytes = None,
            key_id: str = None,
            algorithm: str = None,
            aad: bytes = None,
            iv: bytes = None,
            padding_mode: str = None,
            request_headers: Dict[str, str] = None,
    ):
        # 数据被指定密钥加密后的密文
        self.ciphertext_blob = ciphertext_blob
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密算法
        self.algorithm = algorithm
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 加密数据时使用的初始向量
        self.iv = iv
        # 填充模式
        self.padding_mode = padding_mode
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
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
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class DecryptResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            plaintext: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            padding_mode: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 待加密的明文数据
        self.plaintext = plaintext
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 填充模式
        self.padding_mode = padding_mode
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.plaintext is not None:
            result['Plaintext'] = self.plaintext
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.padding_mode is not None:
            result['PaddingMode'] = self.padding_mode
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Plaintext') is not None:
            self.plaintext = m.get('Plaintext')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('PaddingMode') is not None:
            self.padding_mode = m.get('PaddingMode')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class SignRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            algorithm: str = None,
            message: bytes = None,
            message_type: str = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密算法
        self.algorithm = algorithm
        # 签名消息
        self.message = message
        # 消息类型: 1. RAW（默认值）：原始数据2. DIGEST：原始数据的消息摘要
        self.message_type = message_type
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('Message') is not None:
            self.message = m.get('Message')
        if m.get('MessageType') is not None:
            self.message_type = m.get('MessageType')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class SignResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            signature: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            message_type: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 计算出来的签名值
        self.signature = signature
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 消息类型: 1. RAW（默认值）：原始数据2. DIGEST：原始数据的消息摘要
        self.message_type = message_type
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.signature is not None:
            result['Signature'] = self.signature
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.message_type is not None:
            result['MessageType'] = self.message_type
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Signature') is not None:
            self.signature = m.get('Signature')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('MessageType') is not None:
            self.message_type = m.get('MessageType')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class VerifyRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            signature: bytes = None,
            algorithm: str = None,
            message: bytes = None,
            message_type: str = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 计算出来的签名值
        self.signature = signature
        # 加密算法
        self.algorithm = algorithm
        # 签名消息
        self.message = message
        # 消息类型: 1. RAW（默认值）：原始数据2. DIGEST：原始数据的消息摘要
        self.message_type = message_type
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
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
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class VerifyResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            value: bool = None,
            request_id: str = None,
            algorithm: str = None,
            message_type: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 签名验证是否通过
        self.value = value
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 消息类型: 1. RAW（默认值）：原始数据2. DIGEST：原始数据的消息摘要
        self.message_type = message_type
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.value is not None:
            result['Value'] = self.value
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.message_type is not None:
            result['MessageType'] = self.message_type
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Value') is not None:
            self.value = m.get('Value')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('MessageType') is not None:
            self.message_type = m.get('MessageType')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class GenerateRandomRequest(TeaModel):
    def __init__(
            self,
            length: int = None,
            request_headers: Dict[str, str] = None,
    ):
        # 要生成的随机数字节长度
        self.length = length
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.length is not None:
            result['Length'] = self.length
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('Length') is not None:
            self.length = m.get('Length')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class GenerateRandomResponse(TeaModel):
    def __init__(
            self,
            random: bytes = None,
            request_id: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 随机数
        self.random = random
        # 请求ID
        self.request_id = request_id
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.random is not None:
            result['Random'] = self.random
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('Random') is not None:
            self.random = m.get('Random')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class GenerateDataKeyRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            algorithm: str = None,
            number_of_bytes: int = None,
            aad: bytes = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密算法
        self.algorithm = algorithm
        # 生成的数据密钥的长度
        self.number_of_bytes = number_of_bytes
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('NumberOfBytes') is not None:
            self.number_of_bytes = m.get('NumberOfBytes')
        if m.get('Aad') is not None:
            self.aad = m.get('Aad')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class GenerateDataKeyResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            iv: bytes = None,
            plaintext: bytes = None,
            ciphertext_blob: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密数据时使用的初始向量
        self.iv = iv
        # 待加密的明文数据
        self.plaintext = plaintext
        # 数据被指定密钥加密后的密文
        self.ciphertext_blob = ciphertext_blob
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('Plaintext') is not None:
            self.plaintext = m.get('Plaintext')
        if m.get('CiphertextBlob') is not None:
            self.ciphertext_blob = m.get('CiphertextBlob')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class GetPublicKeyRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class GetPublicKeyResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            public_key: str = None,
            request_id: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # PEM格式的公钥
        self.public_key = public_key
        # 请求ID
        self.request_id = request_id
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.public_key is not None:
            result['PublicKey'] = self.public_key
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('PublicKey') is not None:
            self.public_key = m.get('PublicKey')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class GetSecretValueRequest(TeaModel):
    def __init__(
            self,
            secret_name: str = None,
            version_stage: str = None,
            version_id: str = None,
            fetch_extended_config: bool = None,
            request_headers: Dict[str, str] = None,
    ):
        # 凭据名称
        self.secret_name = secret_name
        # 版本状态
        self.version_stage = version_stage
        # 版本号
        self.version_id = version_id
        # 是否获取凭据的拓展配置true（默认值）：是,false：否
        self.fetch_extended_config = fetch_extended_config
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('SecretName') is not None:
            self.secret_name = m.get('SecretName')
        if m.get('VersionStage') is not None:
            self.version_stage = m.get('VersionStage')
        if m.get('VersionId') is not None:
            self.version_id = m.get('VersionId')
        if m.get('FetchExtendedConfig') is not None:
            self.fetch_extended_config = m.get('FetchExtendedConfig')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class GetSecretValueResponse(TeaModel):
    def __init__(
            self,
            secret_name: str = None,
            secret_type: str = None,
            secret_data: str = None,
            secret_data_type: str = None,
            version_stages: List[str] = None,
            version_id: str = None,
            create_time: str = None,
            request_id: str = None,
            last_rotation_date: str = None,
            next_rotation_date: str = None,
            extended_config: str = None,
            automatic_rotation: str = None,
            rotation_interval: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 凭据名称
        self.secret_name = secret_name
        # 凭据类型
        self.secret_type = secret_type
        # 凭据值
        self.secret_data = secret_data
        # 凭据值类型
        self.secret_data_type = secret_data_type
        # 凭据版本的状态标记
        self.version_stages = version_stages
        # 凭据版本的标识符
        self.version_id = version_id
        # 创建凭据的时间
        self.create_time = create_time
        # 请求ID
        self.request_id = request_id
        # 最近一次轮转的时间
        self.last_rotation_date = last_rotation_date
        # 下一次轮转的时间
        self.next_rotation_date = next_rotation_date
        # 凭据的拓展配置
        self.extended_config = extended_config
        # 是否开启自动轮转
        self.automatic_rotation = automatic_rotation
        # 凭据自动轮转的周期
        self.rotation_interval = rotation_interval
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
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
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class AdvanceEncryptRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            plaintext: bytes = None,
            algorithm: str = None,
            aad: bytes = None,
            iv: bytes = None,
            padding_mode: str = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 待加密的明文数据
        self.plaintext = plaintext
        # 加密算法
        self.algorithm = algorithm
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 加密数据时使用的初始向量
        self.iv = iv
        # 填充模式
        self.padding_mode = padding_mode
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
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
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class AdvanceEncryptResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            ciphertext_blob: bytes = None,
            iv: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            padding_mode: str = None,
            key_version_id: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 数据被指定密钥加密后的密文
        self.ciphertext_blob = ciphertext_blob
        # 加密数据时使用的初始向量
        self.iv = iv
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 填充模式
        self.padding_mode = padding_mode
        # 密钥版本唯一标识符
        self.key_version_id = key_version_id
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.ciphertext_blob is not None:
            result['CiphertextBlob'] = self.ciphertext_blob
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.padding_mode is not None:
            result['PaddingMode'] = self.padding_mode
        if self.key_version_id is not None:
            result['KeyVersionId'] = self.key_version_id
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('CiphertextBlob') is not None:
            self.ciphertext_blob = m.get('CiphertextBlob')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('PaddingMode') is not None:
            self.padding_mode = m.get('PaddingMode')
        if m.get('KeyVersionId') is not None:
            self.key_version_id = m.get('KeyVersionId')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class AdvanceDecryptRequest(TeaModel):
    def __init__(
            self,
            ciphertext_blob: bytes = None,
            key_id: str = None,
            algorithm: str = None,
            aad: bytes = None,
            iv: bytes = None,
            padding_mode: str = None,
            request_headers: Dict[str, str] = None,
    ):
        # 数据被指定密钥加密后的密文
        self.ciphertext_blob = ciphertext_blob
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密算法
        self.algorithm = algorithm
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 加密数据时使用的初始向量
        self.iv = iv
        # 填充模式
        self.padding_mode = padding_mode
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
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
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class AdvanceDecryptResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            plaintext: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            padding_mode: str = None,
            key_version_id: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 待加密的明文数据
        self.plaintext = plaintext
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 填充模式
        self.padding_mode = padding_mode
        # 密钥版本唯一标识符
        self.key_version_id = key_version_id
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.plaintext is not None:
            result['Plaintext'] = self.plaintext
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.padding_mode is not None:
            result['PaddingMode'] = self.padding_mode
        if self.key_version_id is not None:
            result['KeyVersionId'] = self.key_version_id
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Plaintext') is not None:
            self.plaintext = m.get('Plaintext')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('PaddingMode') is not None:
            self.padding_mode = m.get('PaddingMode')
        if m.get('KeyVersionId') is not None:
            self.key_version_id = m.get('KeyVersionId')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class AdvanceGenerateDataKeyRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            number_of_bytes: int = None,
            aad: bytes = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 生成的数据密钥的长度
        self.number_of_bytes = number_of_bytes
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.number_of_bytes is not None:
            result['NumberOfBytes'] = self.number_of_bytes
        if self.aad is not None:
            result['Aad'] = self.aad
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('NumberOfBytes') is not None:
            self.number_of_bytes = m.get('NumberOfBytes')
        if m.get('Aad') is not None:
            self.aad = m.get('Aad')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class AdvanceGenerateDataKeyResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            iv: bytes = None,
            plaintext: bytes = None,
            ciphertext_blob: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            key_version_id: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密数据时使用的初始向量
        self.iv = iv
        # 待加密的明文数据
        self.plaintext = plaintext
        # 数据被指定密钥加密后的密文
        self.ciphertext_blob = ciphertext_blob
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 密钥版本唯一标识符
        self.key_version_id = key_version_id
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
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
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.key_version_id is not None:
            result['KeyVersionId'] = self.key_version_id
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('Plaintext') is not None:
            self.plaintext = m.get('Plaintext')
        if m.get('CiphertextBlob') is not None:
            self.ciphertext_blob = m.get('CiphertextBlob')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('KeyVersionId') is not None:
            self.key_version_id = m.get('KeyVersionId')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class GenerateDataKeyPairRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            algorithm: str = None,
            key_pair_spec: str = None,
            key_format: str = None,
            aad: bytes = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密算法
        self.algorithm = algorithm
        # 指定生成的数据密钥对类型
        self.key_pair_spec = key_pair_spec
        # 生成数据密钥对格式，取值:PEM,DER
        self.key_format = key_format
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.key_pair_spec is not None:
            result['KeyPairSpec'] = self.key_pair_spec
        if self.key_format is not None:
            result['KeyFormat'] = self.key_format
        if self.aad is not None:
            result['Aad'] = self.aad
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('KeyPairSpec') is not None:
            self.key_pair_spec = m.get('KeyPairSpec')
        if m.get('KeyFormat') is not None:
            self.key_format = m.get('KeyFormat')
        if m.get('Aad') is not None:
            self.aad = m.get('Aad')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class GenerateDataKeyPairResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            iv: bytes = None,
            key_pair_spec: str = None,
            private_key_plaintext: bytes = None,
            private_key_ciphertext_blob: bytes = None,
            public_key: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密数据时使用的初始向量
        self.iv = iv
        # 指定生成的数据密钥对类型
        self.key_pair_spec = key_pair_spec
        # 私钥明文
        self.private_key_plaintext = private_key_plaintext
        # 私钥密文
        self.private_key_ciphertext_blob = private_key_ciphertext_blob
        # 公钥
        self.public_key = public_key
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.key_pair_spec is not None:
            result['KeyPairSpec'] = self.key_pair_spec
        if self.private_key_plaintext is not None:
            result['PrivateKeyPlaintext'] = self.private_key_plaintext
        if self.private_key_ciphertext_blob is not None:
            result['PrivateKeyCiphertextBlob'] = self.private_key_ciphertext_blob
        if self.public_key is not None:
            result['PublicKey'] = self.public_key
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('KeyPairSpec') is not None:
            self.key_pair_spec = m.get('KeyPairSpec')
        if m.get('PrivateKeyPlaintext') is not None:
            self.private_key_plaintext = m.get('PrivateKeyPlaintext')
        if m.get('PrivateKeyCiphertextBlob') is not None:
            self.private_key_ciphertext_blob = m.get('PrivateKeyCiphertextBlob')
        if m.get('PublicKey') is not None:
            self.public_key = m.get('PublicKey')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class GenerateDataKeyPairWithoutPlaintextRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            algorithm: str = None,
            key_pair_spec: str = None,
            key_format: str = None,
            aad: bytes = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密算法
        self.algorithm = algorithm
        # 指定生成的数据密钥对类型
        self.key_pair_spec = key_pair_spec
        # 生成数据密钥对格式，取值:PEM,DER
        self.key_format = key_format
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.key_pair_spec is not None:
            result['KeyPairSpec'] = self.key_pair_spec
        if self.key_format is not None:
            result['KeyFormat'] = self.key_format
        if self.aad is not None:
            result['Aad'] = self.aad
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('KeyPairSpec') is not None:
            self.key_pair_spec = m.get('KeyPairSpec')
        if m.get('KeyFormat') is not None:
            self.key_format = m.get('KeyFormat')
        if m.get('Aad') is not None:
            self.aad = m.get('Aad')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class GenerateDataKeyPairWithoutPlaintextResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            iv: bytes = None,
            key_pair_spec: str = None,
            private_key_ciphertext_blob: bytes = None,
            public_key: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密数据时使用的初始向量
        self.iv = iv
        # 指定生成的数据密钥对类型
        self.key_pair_spec = key_pair_spec
        # 私钥密文
        self.private_key_ciphertext_blob = private_key_ciphertext_blob
        # 公钥
        self.public_key = public_key
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.key_pair_spec is not None:
            result['KeyPairSpec'] = self.key_pair_spec
        if self.private_key_ciphertext_blob is not None:
            result['PrivateKeyCiphertextBlob'] = self.private_key_ciphertext_blob
        if self.public_key is not None:
            result['PublicKey'] = self.public_key
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('KeyPairSpec') is not None:
            self.key_pair_spec = m.get('KeyPairSpec')
        if m.get('PrivateKeyCiphertextBlob') is not None:
            self.private_key_ciphertext_blob = m.get('PrivateKeyCiphertextBlob')
        if m.get('PublicKey') is not None:
            self.public_key = m.get('PublicKey')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class AdvanceGenerateDataKeyPairRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            key_pair_spec: str = None,
            key_format: str = None,
            aad: bytes = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 指定生成的数据密钥对类型
        self.key_pair_spec = key_pair_spec
        # 生成数据密钥对格式，取值:PEM,DER
        self.key_format = key_format
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.key_pair_spec is not None:
            result['KeyPairSpec'] = self.key_pair_spec
        if self.key_format is not None:
            result['KeyFormat'] = self.key_format
        if self.aad is not None:
            result['Aad'] = self.aad
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('KeyPairSpec') is not None:
            self.key_pair_spec = m.get('KeyPairSpec')
        if m.get('KeyFormat') is not None:
            self.key_format = m.get('KeyFormat')
        if m.get('Aad') is not None:
            self.aad = m.get('Aad')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class AdvanceGenerateDataKeyPairResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            iv: bytes = None,
            key_pair_spec: str = None,
            private_key_plaintext: bytes = None,
            private_key_ciphertext_blob: bytes = None,
            public_key: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            key_version_id: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密数据时使用的初始向量
        self.iv = iv
        # 指定生成的数据密钥对类型
        self.key_pair_spec = key_pair_spec
        # 私钥明文
        self.private_key_plaintext = private_key_plaintext
        # 私钥密文
        self.private_key_ciphertext_blob = private_key_ciphertext_blob
        # 公钥
        self.public_key = public_key
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 密钥版本唯一标识符
        self.key_version_id = key_version_id
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.key_pair_spec is not None:
            result['KeyPairSpec'] = self.key_pair_spec
        if self.private_key_plaintext is not None:
            result['PrivateKeyPlaintext'] = self.private_key_plaintext
        if self.private_key_ciphertext_blob is not None:
            result['PrivateKeyCiphertextBlob'] = self.private_key_ciphertext_blob
        if self.public_key is not None:
            result['PublicKey'] = self.public_key
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.key_version_id is not None:
            result['KeyVersionId'] = self.key_version_id
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('KeyPairSpec') is not None:
            self.key_pair_spec = m.get('KeyPairSpec')
        if m.get('PrivateKeyPlaintext') is not None:
            self.private_key_plaintext = m.get('PrivateKeyPlaintext')
        if m.get('PrivateKeyCiphertextBlob') is not None:
            self.private_key_ciphertext_blob = m.get('PrivateKeyCiphertextBlob')
        if m.get('PublicKey') is not None:
            self.public_key = m.get('PublicKey')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('KeyVersionId') is not None:
            self.key_version_id = m.get('KeyVersionId')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self


class AdvanceGenerateDataKeyPairWithoutPlaintextRequest(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            key_pair_spec: str = None,
            key_format: str = None,
            aad: bytes = None,
            request_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 指定生成的数据密钥对类型
        self.key_pair_spec = key_pair_spec
        # 生成数据密钥对格式，取值:PEM,DER
        self.key_format = key_format
        # 对数据密钥加密时使用的GCM加密模式认证数据
        self.aad = aad
        # 请求头
        self.request_headers = request_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.key_pair_spec is not None:
            result['KeyPairSpec'] = self.key_pair_spec
        if self.key_format is not None:
            result['KeyFormat'] = self.key_format
        if self.aad is not None:
            result['Aad'] = self.aad
        if self.request_headers is not None:
            result['requestHeaders'] = self.request_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('KeyPairSpec') is not None:
            self.key_pair_spec = m.get('KeyPairSpec')
        if m.get('KeyFormat') is not None:
            self.key_format = m.get('KeyFormat')
        if m.get('Aad') is not None:
            self.aad = m.get('Aad')
        if m.get('requestHeaders') is not None:
            self.request_headers = m.get('requestHeaders')
        return self


class AdvanceGenerateDataKeyPairWithoutPlaintextResponse(TeaModel):
    def __init__(
            self,
            key_id: str = None,
            iv: bytes = None,
            key_pair_spec: str = None,
            private_key_ciphertext_blob: bytes = None,
            public_key: bytes = None,
            request_id: str = None,
            algorithm: str = None,
            key_version_id: str = None,
            response_headers: Dict[str, str] = None,
    ):
        # 密钥的全局唯一标识符该参数也可以被指定为密钥别名
        self.key_id = key_id
        # 加密数据时使用的初始向量
        self.iv = iv
        # 指定生成的数据密钥对类型
        self.key_pair_spec = key_pair_spec
        # 私钥密文
        self.private_key_ciphertext_blob = private_key_ciphertext_blob
        # 公钥
        self.public_key = public_key
        # 请求ID
        self.request_id = request_id
        # 加密算法
        self.algorithm = algorithm
        # 密钥版本唯一标识符
        self.key_version_id = key_version_id
        # 响应头
        self.response_headers = response_headers

    def validate(self):
        pass

    def to_map(self):
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.key_id is not None:
            result['KeyId'] = self.key_id
        if self.iv is not None:
            result['Iv'] = self.iv
        if self.key_pair_spec is not None:
            result['KeyPairSpec'] = self.key_pair_spec
        if self.private_key_ciphertext_blob is not None:
            result['PrivateKeyCiphertextBlob'] = self.private_key_ciphertext_blob
        if self.public_key is not None:
            result['PublicKey'] = self.public_key
        if self.request_id is not None:
            result['RequestId'] = self.request_id
        if self.algorithm is not None:
            result['Algorithm'] = self.algorithm
        if self.key_version_id is not None:
            result['KeyVersionId'] = self.key_version_id
        if self.response_headers is not None:
            result['responseHeaders'] = self.response_headers
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('KeyId') is not None:
            self.key_id = m.get('KeyId')
        if m.get('Iv') is not None:
            self.iv = m.get('Iv')
        if m.get('KeyPairSpec') is not None:
            self.key_pair_spec = m.get('KeyPairSpec')
        if m.get('PrivateKeyCiphertextBlob') is not None:
            self.private_key_ciphertext_blob = m.get('PrivateKeyCiphertextBlob')
        if m.get('PublicKey') is not None:
            self.public_key = m.get('PublicKey')
        if m.get('RequestId') is not None:
            self.request_id = m.get('RequestId')
        if m.get('Algorithm') is not None:
            self.algorithm = m.get('Algorithm')
        if m.get('KeyVersionId') is not None:
            self.key_version_id = m.get('KeyVersionId')
        if m.get('responseHeaders') is not None:
            self.response_headers = m.get('responseHeaders')
        return self
