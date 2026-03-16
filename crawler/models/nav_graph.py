#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   nav_graph.py
@Time    :   2024/07/17 14:32:12
@Author  :   LFY
'''

# here put the import lib

import json
import logging
import threading
import re
from urllib.parse import urlparse, parse_qs

from crawler.models.request import Request
from config import *
from vuln_detection.utils.es_util import ElasticsearchClient


class NavigationGraph:
    def __init__(self, role="visitor"):
        self.graph = {}
        self.role = self._normalize_role(role)
        self.role_token = self.role.upper()
        self.cms = None
        self.param_variants = self._load_param_variants()
        self.es = ElasticsearchClient().get_client()
        self.url_index = {}
        self.base_index = {}
        self._signature_lock = threading.Lock()
        self._pending_signatures = set()
        self._indexed_es_ids = set()
        self._id_regex = [re.compile(p) for p in vuln_scan_config.SIGNATURE_ID_REGEX]
        self._ignore_query_keys = self._lower_set(vuln_scan_config.SIGNATURE_IGNORE_QUERY_KEYS)
        self._ignore_body_keys = self._lower_set(vuln_scan_config.SIGNATURE_IGNORE_BODY_KEYS)
        self._id_query_keys = self._lower_set(vuln_scan_config.SIGNATURE_ID_QUERY_KEYS)
        self._value_query_keys = self._lower_set(vuln_scan_config.SIGNATURE_VALUE_QUERY_KEYS)
        self._value_body_keys = self._lower_set(vuln_scan_config.SIGNATURE_VALUE_BODY_KEYS)

    @staticmethod
    def _lower_set(values):
        if not values:
            return set()
        return {str(v).lower() for v in values}

    @staticmethod
    def _normalize_role(role):
        role_text = str(role or vuln_scan_config.VISITOR).strip().lower()
        if role_text in {
            vuln_scan_config.VISITOR,
            vuln_scan_config.USER_ROLE,
            vuln_scan_config.ADMIN_ROLE,
            vuln_scan_config.DET_USER_ROLE,
            "all_user",
        }:
            return role_text
        return vuln_scan_config.VISITOR

    def _load_param_variants(self):
        path = getattr(vuln_scan_config, "CONTROLLABLE_PARAM_PATH", None)
        if not path or not os.path.exists(path):
            return {}
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception as e:
            logging.error(f"[-] Failed to load param variants: {repr(e)}")
        return {}

    @staticmethod
    def _is_placeholder_request(req: Request) -> bool:
        if req is None:
            return False
        method = (req.method or "").strip().upper()
        if method:
            return False
        if req.response is not None:
            return False
        if req.headers:
            return False
        if req.post_data not in (None, "", b""):
            return False
        return True

    @staticmethod
    def _is_placeholder_node(node_info: dict) -> bool:
        if not isinstance(node_info, dict):
            return False
        method = node_info.get("method")
        return (
            method in (None, "", "GET")
            and not node_info.get("headers")
            and node_info.get("post_params") in ("None", "", None)
        )

    @staticmethod
    def _is_more_informative(req: Request) -> bool:
        if req is None:
            return False
        if req.method and req.method.upper() != "GET":
            return True
        if req.headers:
            return True
        if req.post_data not in (None, "", b""):
            return True
        return False

    def _is_id_segment(self, segment: str) -> bool:
        for regex in self._id_regex:
            if regex.fullmatch(segment):
                return True
        return False

    def _normalize_path(self, path: str) -> str:
        if not path:
            return "/"
        segments = [seg for seg in path.split("/") if seg]
        normalized = []
        for seg in segments:
            if self._is_id_segment(seg):
                normalized.append("{id}")
            else:
                normalized.append(seg)
        normalized_path = "/" + "/".join(normalized)
        if normalized_path != "/" and normalized_path.endswith("/"):
            normalized_path = normalized_path.rstrip("/")
        return normalized_path or "/"

    def _extract_path_ids(self, path: str):
        if not path:
            return []
        segments = [seg for seg in path.split("/") if seg]
        ids = []
        for seg in segments:
            if self._is_id_segment(seg):
                ids.append(seg)
        return ids

    @staticmethod
    def _normalize_body(post_data):
        if post_data is None:
            return ""
        if isinstance(post_data, (bytes, bytearray)):
            return post_data.decode(errors="ignore")
        return str(post_data)

    @staticmethod
    def _normalize_value(value):
        if value is None:
            return "null"
        if isinstance(value, (list, tuple, set, dict)):
            try:
                return json.dumps(value, sort_keys=True, separators=(",", ":"))
            except Exception:
                return str(value)
        text = str(value)
        if len(text) > 128:
            return text[:128]
        return text

    def _normalize_values(self, values):
        if isinstance(values, (list, tuple, set)):
            return [self._normalize_value(v) for v in values]
        return [self._normalize_value(values)]

    def _build_param_signature(self, params, ignore_keys, value_keys, id_keys):
        keys = set()
        value_items = []
        for key, values in params.items():
            key_lower = str(key).lower()
            if key_lower in ignore_keys:
                continue
            keys.add(key_lower)
            if key_lower in value_keys and key_lower not in id_keys:
                for val in self._normalize_values(values):
                    value_items.append(f"{key_lower}={val}")
        return sorted(keys), sorted(value_items)

    @staticmethod
    def _get_content_type(headers):
        if not headers:
            return ""
        for k, v in headers.items():
            if str(k).lower() == "content-type":
                return str(v)
        return ""

    def _get_body_kind(self, headers, post_data):
        content_type = self._get_content_type(headers)
        for ct in vuln_scan_config.JSON_POST_DATA_TYPE:
            if content_type.startswith(ct):
                return "json"
        for ct in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
            if content_type.startswith(ct):
                return "urlencoded"
        body = self._normalize_body(post_data).strip()
        if not body:
            return ""
        if body.startswith("{") or body.startswith("["):
            return "json"
        if "=" in body:
            return "urlencoded"
        return "raw"

    def _extract_param_config(self, req: Request):
        if req is None:
            return None
        parsed = urlparse(req.url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        path_ids = self._extract_path_ids(parsed.path)
        body_kind = self._get_body_kind(req.headers or {}, req.post_data)
        body_text = self._normalize_body(req.post_data).strip()
        body_params = None
        if body_kind == "json" and body_text:
            try:
                body_params = json.loads(body_text)
            except Exception:
                body_params = body_text
        elif body_kind == "urlencoded" and body_text:
            body_params = parse_qs(body_text, keep_blank_values=True)
        elif body_text:
            body_params = body_text
        return {
            "method": req.method,
            "path": parsed.path,
            "path_ids": path_ids,
            "query": query_params,
            "body": body_params,
            "body_kind": body_kind,
        }

    def _record_param_variant(self, signature, req: Request):
        if not signature:
            return
        config = self._extract_param_config(req)
        if config is None:
            return
        existing = self.param_variants.setdefault(signature, [])
        if config not in existing:
            existing.append(config)

    def _build_body_signature(self, req: Request):
        body = self._normalize_body(req.post_data)
        if not body:
            return "", [], []
        body_kind = self._get_body_kind(req.headers or {}, req.post_data)
        if body_kind == "json":
            try:
                data = json.loads(body)
            except Exception:
                return "raw", ["__raw__"], []
            if isinstance(data, dict):
                keys, value_items = self._build_param_signature(
                    data, self._ignore_body_keys, self._value_body_keys, self._id_query_keys
                )
                return "json", keys, value_items
            if isinstance(data, list):
                return "json", ["__list__"], []
            return "raw", ["__raw__"], []
        if body_kind == "urlencoded":
            params = parse_qs(body, keep_blank_values=True)
            keys, value_items = self._build_param_signature(
                params, self._ignore_body_keys, self._value_body_keys, self._id_query_keys
            )
            return "urlencoded", keys, value_items
        return "raw", ["__raw__"], []

    @staticmethod
    def _format_base_signature(base_url, query_keys, query_values, body_keys, body_values, body_kind):
        parts = [base_url]
        if query_keys:
            parts.append("q:" + ",".join(query_keys))
        if query_values:
            parts.append("qv:" + ",".join(query_values))
        if body_keys:
            parts.append("b:" + ",".join(body_keys))
        if body_values:
            parts.append("bv:" + ",".join(body_values))
        if body_kind:
            parts.append("ct:" + body_kind)
        return "|".join(parts)

    def _build_signature(self, req: Request):
        parsed = urlparse(req.url)
        path_template = self._normalize_path(parsed.path)
        base_url = f"{parsed.scheme}://{parsed.netloc}{path_template}"
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        query_keys, query_values = self._build_param_signature(
            query_params, self._ignore_query_keys, self._value_query_keys, self._id_query_keys
        )
        body_kind, body_keys, body_values = self._build_body_signature(req)
        base_signature = self._format_base_signature(
            base_url, query_keys, query_values, body_keys, body_values, body_kind
        )
        method = None if self._is_placeholder_request(req) else req.method
        method = method.upper() if method else None
        signature_method = method if method else "ANY"
        signature = f"{self.role_token}|{signature_method}|{base_signature}"
        meta = {
            "signature": signature,
            "signature_base": base_signature,
            "path_template": base_url,
            "role": self.role,
            "param_signature": {
                "query_keys": query_keys,
                "query_values": query_values,
                "body_keys": body_keys,
                "body_values": body_values,
                "body_kind": body_kind,
            },
        }
        return signature, base_signature, method, meta

    def get_signature(self, req: Request):
        signature, _, _, _ = self._build_signature(req)
        return signature

    def _placeholder_key(self, base_signature):
        return f"{self.role_token}|ANY|{base_signature}"

    def _register_indices(self, node_key, base_signature, url):
        if url:
            self.url_index[url] = node_key
        if base_signature:
            self.base_index.setdefault(base_signature, set()).add(node_key)

    def _index_response(self, es_id, response):
        if response is None:
            return
        if es_id in self._indexed_es_ids:
            return
        try:
            self.es.index(index="node_info", id=es_id, body={"response": response})
            self._indexed_es_ids.add(es_id)
        except Exception as e:
            logging.error(f"[-] ES error: {repr(e)}")

    def _merge_nodes(self, target_key, source_key):
        target = self.graph[target_key]
        source = self.graph[source_key]
        for edge in source.get("edges", []):
            if edge not in target["edges"]:
                target["edges"].append(edge)
        if not target.get("role") and source.get("role"):
            target["role"] = source.get("role")
        if "public" not in target:
            target["public"] = bool(source.get("public", False))
        else:
            target["public"] = bool(target.get("public") or source.get("public"))
        if self._is_placeholder_node(target) and not self._is_placeholder_node(source):
            for key in ("req_url", "headers", "get_params", "post_params", "method"):
                target[key] = source.get(key)

    def _rename_node(self, old_key, new_key, base_signature):
        if old_key == new_key or old_key not in self.graph:
            return new_key
        if new_key in self.graph:
            self._merge_nodes(new_key, old_key)
            del self.graph[old_key]
        else:
            self.graph[new_key] = self.graph.pop(old_key)
        self.graph[new_key]["es_id"] = new_key
        self.graph[new_key]["signature"] = new_key
        self.graph[new_key]["signature_base"] = base_signature
        for node_info in self.graph.values():
            edges = node_info.get("edges", [])
            updated_edges = [new_key if edge == old_key else edge for edge in edges]
            node_info["edges"] = list(dict.fromkeys(updated_edges))
        for url, key in list(self.url_index.items()):
            if key == old_key:
                self.url_index[url] = new_key
        if base_signature:
            nodes = self.base_index.get(base_signature, set())
            if old_key in nodes:
                nodes.discard(old_key)
                nodes.add(new_key)
        return new_key

    def _resolve_node_for_url(self, url):
        if not url:
            return None
        if url in self.url_index:
            return self.url_index[url]
        parsed = urlparse(url)
        path_template = self._normalize_path(parsed.path)
        base_url = f"{parsed.scheme}://{parsed.netloc}{path_template}"
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        query_keys, query_values = self._build_param_signature(
            query_params, self._ignore_query_keys, self._value_query_keys, self._id_query_keys
        )
        base_signature = self._format_base_signature(
            base_url, query_keys, query_values, [], [], ""
        )
        candidates = list(self.base_index.get(base_signature, []))
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        for node_key in candidates:
            if self.graph.get(node_key, {}).get("method") == "GET":
                return node_key
        return candidates[0]

    def record_param_variant(self, req: Request):
        signature, _, _, _ = self._build_signature(req)
        return signature

    def should_execute_request(self, req: Request) -> bool:
        signature, base_signature, method, _ = self._build_signature(req)
        with self._signature_lock:
            self._record_param_variant(signature, req)
            if signature in self.graph or signature in self._pending_signatures:
                url = req.url
                if url:
                    self.url_index[url] = signature
                if base_signature:
                    self.base_index.setdefault(base_signature, set()).add(signature)
                return False
            placeholder_key = self._placeholder_key(base_signature)
            if method and placeholder_key in self.graph:
                self._pending_signatures.add(signature)
                return True
            self._pending_signatures.add(signature)
            return True

    def _release_pending_signature(self, signature):
        if not signature:
            return
        with self._signature_lock:
            self._pending_signatures.discard(signature)

    def add_page(self, req: Request):
        url = req.url

        parsed_url = urlparse(url)
        get_params = str(parsed_url.query)
        post_params = self._normalize_body(req.post_data)
        headers = req.headers

        signature, base_signature, method, meta = self._build_signature(req)
        self._record_param_variant(signature, req)
        if method is None:
            candidates = list(self.base_index.get(base_signature, []))
            if candidates:
                chosen = candidates[0]
                for node_key in candidates:
                    if self.graph.get(node_key, {}).get("method") == "GET":
                        chosen = node_key
                        break
                if url:
                    self.url_index[url] = chosen
                self._release_pending_signature(signature)
                return chosen
        placeholder_key = self._placeholder_key(base_signature)
        if method and placeholder_key in self.graph:
            signature = self._rename_node(placeholder_key, signature, base_signature)

        if signature not in self.graph:
            logging.debug(f"[+] Add {signature} to es.")
            es_id = signature
            self._index_response(es_id, req.response)
            self.graph[signature] = {
                "req_url": url,
                "headers": headers,
                "get_params": get_params,
                "post_params": post_params,
                "edges": [],
                "role": self.role,
                "public": self.role == vuln_scan_config.VISITOR,
                "es_id": es_id,
                "method": method,
                "operation": "SELECT",
                "signature": signature,
                "signature_base": base_signature,
                "path_template": meta["path_template"],
                "param_signature": meta["param_signature"]
            }
            self._register_indices(signature, base_signature, url)
            self._release_pending_signature(signature)
            return signature

        node_info = self.graph[signature]
        if self._is_placeholder_node(node_info) and self._is_more_informative(req):
            node_info["req_url"] = url
            node_info["headers"] = headers
            node_info["get_params"] = get_params
            node_info["post_params"] = post_params
            node_info["method"] = method or node_info.get("method")
            node_info["param_signature"] = meta["param_signature"]
        if method and node_info.get("method") is None:
            node_info["method"] = method
        if not node_info.get("role"):
            node_info["role"] = self.role
        if "public" not in node_info:
            node_info["public"] = self.role == vuln_scan_config.VISITOR
        if url:
            self.url_index[url] = signature
        if base_signature:
            self.base_index.setdefault(base_signature, set()).add(signature)
        self._index_response(signature, req.response)
        self._release_pending_signature(signature)
        return signature

    def add_link(self, req: Request):
        source = req.from_url
        target_node = self.add_page(req)
        if source is None:
            return
        source_node = self._resolve_node_for_url(source)
        if source_node is None:
            source_req = Request(source, method="GET", headers=None, post_data=None, response=None)
            source_node = self.add_page(source_req)
        if source_node in self.graph:
            if target_node not in self.graph[source_node]["edges"]:
                self.graph[source_node]["edges"].append(target_node)

    def visualize(self):

        if getattr(vuln_scan_config, "CONTROLLABLE_PARAM_PATH", None):
            try:
                param_dir = os.path.dirname(vuln_scan_config.CONTROLLABLE_PARAM_PATH)
                if param_dir and not os.path.exists(param_dir):
                    os.makedirs(param_dir)
                with open(vuln_scan_config.CONTROLLABLE_PARAM_PATH, "w") as f:
                    json.dump(self.param_variants, f, indent=4)
                print("[*] storage controllable params...")
            except Exception as e:
                logging.error(f"[-] Failed to save controllable params: {repr(e)}")

        # dump当前role的nav graph到json文件
        if not os.path.exists(vuln_scan_config.NAV_GRAPH_DIR):
            os.makedirs(vuln_scan_config.NAV_GRAPH_DIR)
        serialized_graph = {}
        for node, info in self.graph.items():
            if isinstance(info, dict):
                filtered = {
                    key: value
                    for key, value in info.items()
                    if key not in {"signature", "signature_base", "path_template", "variants"}
                }
            else:
                filtered = info
            serialized_graph[node] = filtered
        with open(vuln_scan_config.ROLE_NAVIGRAPH_PATH.format(self.role), 'w') as f:
            json.dump(serialized_graph, f, indent=4)
        print("[*] storage nav graph...")
        print(f"[*] param variants count: {len(self.param_variants)}")
