# coding=utf-8

import os
from setuptools import setup, find_packages

"""
setup module for alibabacloud-dkms-gcs.

Created on 04/24/2022

@author: Alibaba Cloud SDK
"""

packages = find_packages()
NAME = "alibabacloud-dkms-gcs"
DESCRIPTION = "AlibabaCloud DKMS-GCS SDK for Python"
AUTHOR = "Alibaba Cloud SDK"
AUTHOR_EMAIL = "sdk-team@alibabacloud.com"
URL = "https://github.com/aliyun/alibabacloud-dkms-gcs-python-sdk"
VERSION = "1.0.0"
REQUIRES = [
	"alibabacloud_openapi_util>=0.2.1, <1.0.0",
    "protobuf>=3.12.0 ,<4.0.0",
    "pyopenssl>=16.2.0",
    "alibabacloud_darabonba_array>=0.1.0, <1.0.0",
    "alibabacloud_darabonba_stream>=0.0.1, <1.0.0",
    "alibabacloud_darabonba_string>=0.0.4, <1.0.0",
    "alibabacloud_darabonba_number>=0.0.4, <1.0.0",
    "alibabacloud_darabonba_signature_util>=0.0.4, <1.0.0",
    "alibabacloud_darabonba_map>=0.0.1, <1.0.0",
    "alibabacloud_tea_util>=0.3.11, <1.0.0"
]

LONG_DESCRIPTION = ''
if os.path.exists('./README.md'):
    with open("README.md", encoding='utf-8') as fp:
        LONG_DESCRIPTION = fp.read()

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    license="Apache License 2.0",
    url=URL,
    keywords=["alibabacloud", "dkms_gcs_sdk"],
    packages=find_packages(exclude=["example*"]),
    include_package_data=True,
    platforms="any",
    install_requires=REQUIRES,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python",
	"Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Software Development"
    ],
)