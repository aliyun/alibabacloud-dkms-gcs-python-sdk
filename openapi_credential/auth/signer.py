# coding=utf-8
import abc
import base64

import OpenSSL.crypto as ct

from openapi_credential.auth.credentials import RsaKeyPairCredential


class Signer(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def sign_string_with_credentials(self, string_to_sign, credentials):
        pass

    @abc.abstractmethod
    def sign_string_with_access_key_secret(self, string_to_sign, access_key_secret):
        pass

    @abc.abstractmethod
    def get_signer_name(self):
        pass

    @abc.abstractmethod
    def get_signer_version(self):
        pass

    @abc.abstractmethod
    def get_signer_type(self):
        pass


__pem_begin = '-----BEGIN RSA PRIVATE KEY-----\n'
__pem_end = '\n-----END RSA PRIVATE KEY-----'


def _format_private_key(private_key):
    if not private_key.startswith(__pem_begin):
        private_key = __pem_begin + private_key
    if not private_key.endswith(__pem_end):
        private_key = private_key + __pem_end
    return private_key


class SHA256withRSASigner(Signer):

    def sign_string_with_access_key_secret(self, string_to_sign, access_key_secret):
        private_key = _format_private_key(access_key_secret)
        pkey = ct.load_privatekey(ct.FILETYPE_PEM, private_key)
        signature = ct.sign(pkey, string_to_sign.encode(), 'sha256')
        return "Bearer " + base64.b64encode(signature).decode().replace('\n', '')

    def sign_string_with_credentials(self, string_to_sign, credentials):
        return self.sign_string_with_access_key_secret(string_to_sign, credentials.get_access_key_secret())

    def get_signer_name(self):
        return "RSA_PKCS1_SHA_256"

    def get_signer_version(self):
        return "1.0"

    def get_signer_type(self):
        return "rsa_key_pair"


_sha256_with_rsa_signer = SHA256withRSASigner()


def get_signer(credential):
    if isinstance(credential, RsaKeyPairCredential):
        return _sha256_with_rsa_signer
    else:
        raise ValueError("Only support rsa key pair credential now.")
