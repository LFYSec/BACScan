import json
import os
from typing import Dict

from config import vuln_scan_config
from vuln_detection.utils.graph_util import (
    annotate_public_field,
    generate_merge_graph,
    split_role_signature,
)


def _graph_needs_rebuild(graph) -> bool:
    if not isinstance(graph, dict):
        return True
    for node_key, info in graph.items():
        if not isinstance(info, dict):
            return True
        if "role" not in info or "public" not in info:
            return True
        if not split_role_signature(node_key)[0]:
            return True
    return False


def load_or_generate_merged_graph() -> Dict:
    path = vuln_scan_config.MERGE_NAVIGRAPH_PATH
    if os.path.exists(path):
        with open(path, "r") as f:
            graph = json.load(f)
        if _graph_needs_rebuild(graph):
            return generate_merge_graph()
        annotate_public_field(graph)
        return graph
    return generate_merge_graph()


def load_existing_merged_graph() -> Dict:
    path = vuln_scan_config.MERGE_NAVIGRAPH_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(f"Merged graph not found: {path}")
    with open(path, "r") as f:
        graph = json.load(f)
    if _graph_needs_rebuild(graph):
        raise ValueError(
            f"Merged graph is outdated or invalid: {path}. Please run build_dependence.py first."
        )
    annotate_public_field(graph)
    return graph


def load_dependence_map() -> Dict:
    path = vuln_scan_config.DATA_DEPENDENCE_PATH
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        return {}
    return {}


def load_existing_dependence_map() -> Dict:
    path = vuln_scan_config.DATA_DEPENDENCE_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dependence map not found: {path}")
    with open(path, "r") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Dependence map is invalid: {path}")
    return data


def should_rebuild_dependence(graph, dependence_map) -> bool:
    if not os.path.exists(vuln_scan_config.DATA_DEPENDENCE_PATH):
        return True
    if not isinstance(dependence_map, dict):
        return True
    for node_key in dependence_map.keys():
        if node_key not in graph:
            return True
    return False
