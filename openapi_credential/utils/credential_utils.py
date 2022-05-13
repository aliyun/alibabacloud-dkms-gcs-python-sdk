# coding=utf-8
import base64

from OpenSSL import crypto


def get_private_key_pem_from_private_key_data(private_key_data, password):
    private_key_bytes = base64.b64decode(private_key_data.encode())
    pk12 = crypto.load_pkcs12(private_key_bytes, password)
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pk12.get_privatekey()).decode()
    return trim_private_key_pem(private_key)


def trim_private_key_pem(private_key):
    prefix = "-----BEGIN PRIVATE KEY-----"
    newline = "\n"
    suffix = "-----END PRIVATE KEY-----"
    private_key = private_key.replace(prefix, "")
    private_key = private_key.replace(suffix, "")
    return private_key.replace(newline, "")
