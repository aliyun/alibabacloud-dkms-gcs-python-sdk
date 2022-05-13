# coding=utf-8

import json
import os


def load(file_path):
    if not os.path.isfile(file_path):
        return {}
    with open(file_path, 'r') as load_file:
        return json.load(load_file)
