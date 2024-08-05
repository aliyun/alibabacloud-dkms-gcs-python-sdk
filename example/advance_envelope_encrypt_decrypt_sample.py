# -*- coding: utf-8 -*-
import base64
import os
import random
import string

from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from openapi.models import Config
from sdk.client import Client
from sdk.models import AdvanceGenerateDataKeyRequest, AdvanceDecryptRequest, AdvanceGenerateDataKeyResponse, \
    AdvanceDecryptResponse

# consts
number_of_bytes = 32
gcm_iv_length = 12
tag_length = 16
global client


class EnvelopeCipherPersistObject(object):
    def __init__(self, data_key_iv: bytes = None, encrypted_data_key: bytes = None, iv: bytes = None,
                 cipher_text: str = None):
        self.data_key_iv = data_key_iv
        self.encrypted_data_key = encrypted_data_key
        self.iv = iv
        self.cipher_text = cipher_text


def init_client():
    config = Config()
    config.protocol = "https"
    config.client_key_file = "<your-client-key-file>"
    config.password = os.getenv('CLIENT_KEY_PASSWORD_ENV_KEY')
    config.endpoint = "<your-endpoint>"
    config.ca_file_path = "<your-ca-file-path>"
    # 忽略ssl验证
    # config.ignore_ssl = True
    global client
    client = Client(config)


def envelope_advance_encrypt_sample():
    key_id = "<your-key-id>"
    resp = advance_generate_data_key(key_id, number_of_bytes)
    data = "<your-plaintext-data>".encode("utf-8")
    iv, ciphertext = local_encrypt(resp.plaintext, data)
    print(ciphertext)
    out_cipher_text = EnvelopeCipherPersistObject()
    out_cipher_text.iv = iv
    out_cipher_text.encrypted_data_key = resp.ciphertext_blob
    out_cipher_text.data_key_iv = resp.iv
    out_cipher_text.cipher_text = ciphertext
    # 保存信封密文持久化对象
    save_envelope_cipher_persist_object(out_cipher_text)


def envelope_advance_decrypt_sample():
    out_cipher_text = get_envelope_cipher_persist_object()
    resp = decrypt(out_cipher_text.data_key_iv, out_cipher_text.encrypted_data_key)
    data_key = resp.plaintext
    # 解密 cipher_text
    decypted_text = local_decrypt(data_key, out_cipher_text.iv, out_cipher_text.cipher_text)
    # 根据实际业务场景,使用解密后的密文数据,此处仅做打印处理
    print(decypted_text.decode("utf-8"))


def advance_generate_data_key(key_id: str, number_of_bytes: int) -> AdvanceGenerateDataKeyResponse:
    request = AdvanceGenerateDataKeyRequest()
    request.key_id = key_id
    request.number_of_bytes = number_of_bytes
    resp = client.advance_generate_data_key(request)
    return resp


def decrypt(data_key_iv: bytes, encrypted_data_key: bytes) -> AdvanceDecryptResponse:
    request = AdvanceDecryptRequest()
    request.ciphertext_blob = encrypted_data_key
    request.iv = data_key_iv
    resp = client.advance_decrypt(request)
    return resp


def local_encrypt(key: bytes, plaintext: bytes) -> (bytes, str):
    iv = bytes(''.join(random.sample(string.ascii_letters + string.digits, gcm_iv_length)), encoding="utf-8")
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, base64.b64encode(ciphertext + encryptor.tag)


def local_decrypt(key: bytes, iv: bytes, ciphertext: str) -> bytes:
    en_data = base64.b64decode(ciphertext)
    tag = en_data[-tag_length:]
    cipher_data = en_data[:-tag_length]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    return decryptor.update(cipher_data) + decryptor.finalize()


def save_envelope_cipher_persist_object(out_cipher_text: EnvelopeCipherPersistObject):
    # 用户自行保存输出的密文对象
    pass


def get_envelope_cipher_persist_object() -> EnvelopeCipherPersistObject:
    # 用户需要在此处代码进行替换，从存储中读取封信加密持久化对象
    pass


# 初始化kms实例客户端
init_client()
# 高级接口信封加密示例
envelope_advance_encrypt_sample()
# 高级接口信封解密示例
envelope_advance_decrypt_sample()
