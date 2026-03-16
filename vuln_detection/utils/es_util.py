#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   es_util.py
@Time    :   2024/07/18 14:13:50
@Author  :   LFY
'''

# here put the import lib

from elasticsearch import Elasticsearch
from config import vuln_scan_config


class SingletonMeta(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class ElasticsearchClient(metaclass=SingletonMeta):
    def __init__(self):
        # self.client = Elasticsearch(vuln_scan_config.ES_ADDR, http_auth=(vuln_scan_config.ES_USER, vuln_scan_config.ES_PASS), verify_certs=False)
        # 使用http连接
        self.client = Elasticsearch(["http://10.176.36.21:9200"])
    def get_client(self):
        return self.client

