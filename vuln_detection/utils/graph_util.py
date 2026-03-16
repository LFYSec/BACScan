#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   naviGraphOperation.py
@Time    :   2024/07/17 15:15:55
@Author  :   LFY
'''

# here put the import lib
import json
import logging
import os
from typing import Dict
from config import *
from vuln_detection.similarity.dom_similarity import DSM


def normalize_role(role):
    role_text = str(role or "").strip().lower()
    if not role_text:
        return ""
    aliases = {
        vuln_scan_config.VISITOR: vuln_scan_config.VISITOR,
        vuln_scan_config.USER_ROLE: vuln_scan_config.USER_ROLE,
        vuln_scan_config.ADMIN_ROLE: vuln_scan_config.ADMIN_ROLE,
        vuln_scan_config.DET_USER_ROLE: vuln_scan_config.DET_USER_ROLE,
        "all_user": "all_user",
    }
    return aliases.get(role_text, role_text)


def role_token(role):
    normalized = normalize_role(role)
    return str(normalized).upper() if normalized else ""


def split_role_signature(signature):
    text = str(signature or "")
    if "|" not in text:
        return None, text
    first, rest = text.split("|", 1)
    normalized = normalize_role(first)
    valid_roles = {
        vuln_scan_config.VISITOR,
        vuln_scan_config.USER_ROLE,
        vuln_scan_config.ADMIN_ROLE,
        vuln_scan_config.DET_USER_ROLE,
        "all_user",
    }
    if normalized in valid_roles:
        return normalized, rest
    return None, text


def strip_role_from_signature(signature):
    _, rest = split_role_signature(signature)
    return rest


def extract_node_role(node_key, node_info=None, role_hint=None):
    if isinstance(node_info, dict):
        role = normalize_role(node_info.get("role"))
        if role:
            return role
        roles = node_info.get("roles") or []
        if isinstance(roles, list) and roles:
            role = normalize_role(roles[0])
            if role:
                return role
    role, _ = split_role_signature(node_key)
    if role:
        return role
    role = normalize_role(role_hint)
    return role or None


def compose_role_signature(role, signature):
    role_prefix, rest = split_role_signature(signature)
    if role_prefix:
        return signature
    token = role_token(role)
    if not token:
        return signature
    return f"{token}|{rest}"


def _remap_edges(edges, key_mapping):
    updated = []
    for edge in edges or []:
        mapped = key_mapping.get(edge, edge)
        if mapped not in updated:
            updated.append(mapped)
    return updated


def normalize_graph_signatures(graph, role_hint=None):
    if not isinstance(graph, dict):
        return {}
    key_mapping = {}
    normalized = {}

    for node_key, raw_info in graph.items():
        if not isinstance(raw_info, dict):
            continue
        info = dict(raw_info)
        role = extract_node_role(node_key, info, role_hint=role_hint)
        signature = compose_role_signature(role, node_key)
        key_mapping[node_key] = signature
        info.pop("roles", None)
        info["role"] = role
        info["signature"] = signature
        info["es_id"] = signature
        normalized[signature] = info

    for signature, info in normalized.items():
        info["edges"] = _remap_edges(info.get("edges", []), key_mapping)

    return normalized


def annotate_public_field(graph):
    signature_roles = {}
    for node_key, info in graph.items():
        role = extract_node_role(node_key, info)
        base_signature = strip_role_from_signature(node_key)
        signature_roles.setdefault(base_signature, set()).add(role)

    for node_key, info in graph.items():
        role = extract_node_role(node_key, info)
        base_signature = strip_role_from_signature(node_key)
        roles = signature_roles.get(base_signature, set())
        is_public = role == vuln_scan_config.VISITOR or vuln_scan_config.VISITOR in roles
        info["public"] = bool(is_public)


def equal_graph_node(node_1, node_2):
    # 通过节点参数判断是不是相同的
    if len(node_1["get_params"]) == 0 and len(node_1["get_params"]) == 0 and len(node_1["post_params"]) == 0 and len(
            node_1["post_params"]) == 0:
        return True
    else:
        pass

        return DSM(node_1, node_2)


def merge_node(node_1, node_2):
    for i in node_2["edges"]:
        if i not in node_1["edges"]:
            node_1["edges"].append(i)
    if not node_1.get("role") and node_2.get("role"):
        node_1["role"] = node_2.get("role")
    if "public" not in node_1:
        node_1["public"] = bool(node_2.get("public", False))
    else:
        node_1["public"] = bool(node_1.get("public") or node_2.get("public"))

    return node_1


def merge_graph(graph_1, graph_2):
    merged_graph = graph_2.copy()
    equal_node_count = 0
    # 遍历graph_1中的每个节点和边，添加到merged_graph中
    for node, _ in graph_1.items():
        if node not in merged_graph:
            merged_graph[node] = graph_1[node]
        else:
            if equal_graph_node(graph_1[node], merged_graph[node]):
                merged_graph[node] = merge_node(graph_1[node], graph_2[node])
                equal_node_count += 1
    return merged_graph, equal_node_count


def get_one_role_node(graph):
    one_role_node_dict = {}
    for node, _ in graph.items():
        if graph[node].get("role"):
            one_role_node_dict[node] = graph[node]
    return one_role_node_dict


def get_multi_role_node(graph):
    multi_role_node_dict = {}
    for node, _ in graph.items():
        if graph[node].get("public") is False:
            multi_role_node_dict[node] = graph[node]
    return multi_role_node_dict


def generate_merge_graph() -> Dict:
    merged_graph = dict()

    for filename in os.listdir(vuln_scan_config.NAV_GRAPH_DIR):
        file_path = os.path.join(vuln_scan_config.NAV_GRAPH_DIR, filename)
        if os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                graph = json.load(f)
            role_hint = None
            if filename.endswith("_navigraph.json"):
                role_hint = filename.replace("_navigraph.json", "")
            graph = normalize_graph_signatures(graph, role_hint=role_hint)
            merged_graph, equal_node_count = merge_graph(merged_graph, graph)

    annotate_public_field(merged_graph)

    with open(vuln_scan_config.MERGE_NAVIGRAPH_PATH, 'w') as f:
        json.dump(merged_graph, f, indent=4)

    return merged_graph
