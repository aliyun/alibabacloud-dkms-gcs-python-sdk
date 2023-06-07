# -*- coding: utf-8 -*-
import base64
import os
import random
import string

from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from openapi.models import Config
from openapi_util.models import RuntimeOptions
from sdk.client import Client
from sdk.models import GenerateDataKeyRequest, DecryptRequest

config = Config()
config.protocol = "https"
config.client_key_file = "<your-client-key-file>"
config.password = os.getenv('CLIENT_KEY_PASSWORD')
config.endpoint = "<your-endpoint>"
client = Client(config)


class EnvelopeCipherPersistObject(object):
    def __init__(self):
        self.data_key_iv = None
        self.encrypted_data_key = None
        self.iv = None
        self.cipher_text = None


def generate_data_key(key_id, number_of_bytes):
    request = GenerateDataKeyRequest()
    request.key_id = key_id
    request.number_of_bytes = number_of_bytes
    runtime_options = RuntimeOptions()
    # ignore ssl
    runtime_options.ignore_ssl = True
    # the param verify is ca certificate file path
    # runtime_options.verify = "<your-ca-certificate-file-path>"
    resp = client.generate_data_key_with_options(request, runtime_options)
    return resp


def kms_decrypt(key_id, data_key_iv, encrypted_data_key):
    request = DecryptRequest()
    request.ciphertext_blob = encrypted_data_key
    request.key_id = key_id
    request.iv = data_key_iv
    runtime_options = RuntimeOptions()
    # ignore ssl
    runtime_options.ignore_ssl = True
    # the param verify is ca certificate file path
    # runtime_options.verify = "<your-ca-certificate-file-path>"
    resp = client.decrypt_with_options(request, runtime_options)
    return resp


def encrypt(key, iv, plaintext, associated_data):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, base64.b64encode(ciphertext), encryptor.tag)


def decrypt(key, associated_data, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()


key_id = "<your-key-id>"
number_of_bytes = "<your-number-of-bytes>"
associated_data = b"<your-associated-data>"
resp = generate_data_key(key_id, number_of_bytes)
gcm_iv_length = 12
iv = bytes(''.join(random.sample(string.ascii_letters + string.digits, gcm_iv_length)), encoding="utf-8")
# encrypt
data = "<your-plaintext-data>".encode("utf-8")
iv, ciphertext, tag = encrypt(resp.plaintext, iv, data, associated_data)
print(ciphertext)
out_cipher_text = EnvelopeCipherPersistObject()
out_cipher_text.iv = iv
out_cipher_text.encrypted_data_key = resp.ciphertext_blob
out_cipher_text.data_key_iv = resp.iv
out_cipher_text.cipher_text = ciphertext

# decrypt data_key
resp = kms_decrypt(key_id, out_cipher_text.data_key_iv, out_cipher_text.encrypted_data_key)
data_key = resp.plaintext
# decrypt cipher_text
decypted_text = decrypt(data_key, associated_data, out_cipher_text.iv, out_cipher_text.cipher_text, tag)
print(decypted_text.decode())
