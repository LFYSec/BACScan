#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   domtree2data.py
@Time    :   2024/07/17 15:13:44
@Author  :   LFY
'''

# here put the import lib

import math
from copy import deepcopy
import hashlib
from config import vuln_scan_config
from urllib.parse import urlparse


class Converter:
    def __init__(self, dom_tree, dimension):
        self.dom_tree = dom_tree
        self.node_info_list = []
        self.dimension = dimension
        self.initial_weight = vuln_scan_config.DOM_INITIAL_WEIGHT
        self.attenuation_ratio = vuln_scan_config.DOM_ATTENUATION_RATIO
        self.dom_eigenvector = {}.fromkeys(range(0, dimension), 0)
        # 存储完整维度向量，便于二次确认
        self.full_dimension = vuln_scan_config.DOM_FULL_DIMENSION
        self.full_dom_eigenvector = {}.fromkeys(range(0, self.full_dimension), 0)

    def get_full_eigenvector(self):
        full_dom_tmp = deepcopy(self.full_dom_eigenvector)
        for key, value in self.full_dom_eigenvector.items():
            new_weight = math.floor(value / vuln_scan_config.DOM_WEIGHT_DIVISOR)
            if new_weight == 0:
                del full_dom_tmp[key]
            else:
                full_dom_tmp[key] = new_weight
        return full_dom_tmp

    def get_eigenvector(self):
        # 根据node_id遍历节点
        for node_id in range(1, self.dom_tree.size() + 1):
            node = self.dom_tree.get_node(node_id)
            node_feature = self.create_feature(node)  # 获取node标签名属性
            feature_hash = self.feature_hash(node_feature)
            node_weight = self.calculate_weight(node, node_id, feature_hash)  # 计算当前节点权重
            self.construct_eigenvector(feature_hash, node_weight)

            # print(f"{node_id}, {node_feature}, {feature_hash}, {feature_hash % self.dimension}, {math.floor(node_weight/vuln_scan_config.DOM_WEIGHT_DIVISOR)}")

        return self.dom_eigenvector

    @staticmethod
    def create_feature(node):
        node_attr_list = []
        node_feature = node.data.label + '|'

        if node.data.label == "meta":
            values = ''.join(node.data.attrs.values())
            if "keywords" in values:
                return f"meta|name:keywords|content:KEYWORDS"
            if "description" in values:
                return f"meta|name:description|content:DESCRIPTION"

        for attr in node.data.attrs.keys():
            # 处理成相对路径
            if attr == "href" or attr == "src":
                p = urlparse(node.data.attrs[attr])
                if p.path == "":
                    node_attr_list.append(attr + ':None')
                elif p.path == "/":
                    node_attr_list.append(attr + ':LINK')
                else:
                    node_attr_list.append(f"{attr}:{p.scheme}-{p.path}")
            elif attr == "alt":
                node_attr_list.append(f'{attr}:ALT')
            elif attr == "title":
                node_attr_list.append(f'{attr}:TITLE')
            else:
                node_attr_list.append(attr + ':' + str(node.data.attrs[attr]))

        node_feature += '|'.join(node_attr_list)
        # 和go统一
        if node_feature[-1] == "|":
            node_feature = node_feature[:-1]
        return node_feature

    # @staticmethod
    # def feature_hash(node_feature):
    #     return abs(hash(node_feature)) % (10 ** 8)

    @staticmethod
    def feature_hash(node_feature):
        return abs(int(hashlib.md5(node_feature.encode()).hexdigest(), 16))

    # 计算节点权重
    def calculate_weight(self, node, node_id, feature_hash):
        brother_node_count = 0
        depth = self.dom_tree.depth(node)
        # 遍历兄弟节点，如果有相同的兄弟，则计数器+1
        for brother_node in self.dom_tree.siblings(node_id):
            brother_node_feature_hash = self.feature_hash(self.create_feature(brother_node))
            if brother_node_feature_hash == feature_hash:
                brother_node_count = brother_node_count + 1

        self.initial_weight = vuln_scan_config.DOM_INITIAL_WEIGHT
        # form表单权重增加
        if self.dom_tree.get_node(node_id).tag == "form":
            self.initial_weight = 2

        # 初始权重1 * 递减因子的depth次方 * 递减因子的兄弟数次方 (为什么兄弟节点要影响权重?)
        if brother_node_count:
            node_weight = self.initial_weight * self.attenuation_ratio ** depth * self.attenuation_ratio ** brother_node_count
        else:
            node_weight = self.initial_weight * self.attenuation_ratio ** depth
        return node_weight

    def construct_eigenvector(self, feature_hash, node_weight):
        full_feature_hash = feature_hash % self.full_dimension
        self.full_dom_eigenvector[full_feature_hash] = node_weight
        feature_hash = feature_hash % self.dimension  # feature_hash降维，即取余
        self.dom_eigenvector[feature_hash] += node_weight  # 同维度的节点权重相加

    # 将结果离散成整数
    @staticmethod
    def format_node_weight(eigenvector):
        # print("Raw: ", str(eigenvector))
        new_eigenvenctor = {}.fromkeys(range(0, len(eigenvector)), 0)
        for i, weight in eigenvector.items():
            new_weight = math.floor(weight / vuln_scan_config.DOM_WEIGHT_DIVISOR)
            new_eigenvenctor[i] = new_weight
            if new_weight == 0:
                del new_eigenvenctor[i]

        # print("New: ",new_eigenvenctor)
        return new_eigenvenctor
