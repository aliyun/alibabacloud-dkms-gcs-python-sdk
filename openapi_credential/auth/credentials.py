# coding=utf-8
import abc


class AlibabaCloudCredentials(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_access_key_id(self):
        """get access key id"""

    @abc.abstractmethod
    def get_access_key_secret(self):
        """get access key secret"""


class RsaKeyPairCredential(AlibabaCloudCredentials):

    def __init__(self, public_key_id, private_key):
        self._public_key_id = public_key_id
        self._private_key = private_key

    def get_access_key_id(self):
        return self._public_key_id

    def get_access_key_secret(self):
        return self._private_key
