#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   dom_similarity.py
@Time    :   2024/07/17 15:14:04
@Author  :   LFY
'''

# here put the import lib

from html.parser import HTMLParser
from vuln_detection.utils.dom_converter_util import Converter
from treelib import Tree
from bs4 import BeautifulSoup
import bs4
import warnings

from config import vuln_scan_config
from vuln_detection.utils.es_util import ElasticsearchClient

warnings.filterwarnings("ignore", category=bs4.MarkupResemblesLocatorWarning)

class DOMTree:
    def __init__(self, label, attrs):
        self.label = label
        self.attrs = attrs


class HTMLParser:
    def __init__(self, html):
        self.dom_id = 1
        self.dom_tree = Tree()
        # self.bs_html = BeautifulSoup(html, 'html.parser')
        self.bs_html = BeautifulSoup(html, 'html.parser')

    def get_dom_structure_tree(self):
        # self.bs_html.contents 为列表，第一个元素为doctype, 直到找到Tag类型，才为我们的html
        for content in self.bs_html.contents:
            if isinstance(content, bs4.element.Tag):
                self.bs_html = content
        self.recursive_descendants(self.bs_html, 1)
        return self.dom_tree

    def recursive_descendants(self, descendants, parent_id):
        if self.dom_id == 1:
            self.dom_tree.create_node(descendants.name, self.dom_id, data=DOMTree(descendants.name, descendants.attrs))
            self.dom_id = self.dom_id + 1
        for child in descendants.contents:  # 递归找Tag 即子dom
            if isinstance(child, bs4.element.Tag):
                self.dom_tree.create_node(child.name, self.dom_id, parent_id, data=DOMTree(child.name, child.attrs))
                self.dom_id = self.dom_id + 1
                self.recursive_descendants(child, self.dom_id - 1)  # -1是因为存parent_id


def get_all_vector(content: str):
    if content == "" or content is None:
        return False, False
    hp1 = HTMLParser(content)
    html_doc_dom_tree = hp1.get_dom_structure_tree()
    converter = Converter(html_doc_dom_tree, vuln_scan_config.DOM_VECTOR_DIMENSION)
    dom_eigenvector = converter.get_eigenvector()
    full_eigenvector = converter.get_full_eigenvector()
    vector = converter.format_node_weight(dom_eigenvector)
    if len(vector) < vuln_scan_config.DOM_VECTOR_MIN_LEN:
        # 去掉一些简单的html页面
        return False, False
    return vector, full_eigenvector


def format_vector(vector):
    if isinstance(vector, dict):
        new_vector = ""
        for k, v in vector.items():
            new_vector += f"{k}:{v} "
        return new_vector.strip()
    else:
        return str(vector).strip()


def calculated_similarity(dom1_eigenvector, dom2_eigenvector, dimension):
    a, b = 0, 0
    exit_dom_target = False
    for i in range(dimension):
        if i not in dom1_eigenvector.keys():
            dom1_eigenvector[i] = 0
        if i not in dom2_eigenvector.keys():
            dom2_eigenvector[i] = 0
        if dom2_eigenvector[i] != 0 and dom1_eigenvector[i] != 0:
            null_dom_target = True
        a += dom1_eigenvector[i] - dom2_eigenvector[i]
        if dom1_eigenvector[i] and dom2_eigenvector[i]:
            b += dom1_eigenvector[i] + dom2_eigenvector[i]
    if a == 0 and null_dom_target:
        similarity = 1
    else:
        similarity = abs(a) / b
    return similarity


def get_dom_similarity(html1, html2):
    dimension = vuln_scan_config.DOM_FULL_DIMENSION
    dom_similarity_threshold = vuln_scan_config.DOM_SIMILARITY_THRESHOLD
    full_vector_similarity = 0
    vector1, dom1_eigenvector = get_all_vector(html1)
    vector2, dom2_eigenvector = get_all_vector(html2)
    if type(dom1_eigenvector) == dict and type(dom2_eigenvector) == dict:
        full_vector_similarity = calculated_similarity(dom1_eigenvector, dom2_eigenvector, dimension)
        if full_vector_similarity > dom_similarity_threshold and full_vector_similarity <= 1:
            return True
    return False


def DSM(node_1, node_2):
    es = ElasticsearchClient().get_client()
    html1 = es.get(index="node_info", id=node_1["es_id"])
    html2 = es.get(index="node_info", id=node_2["es_id"])
    return get_dom_similarity(html1["_source"]["response"], html2["_source"]["response"])
