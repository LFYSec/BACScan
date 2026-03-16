#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   add_node.py
@Time    :   2024/07/17 14:50:10
@Author  :   LFY
'''
import asyncio
import json
import os
from urllib.parse import urlparse

from config.config import vuln_scan_config
from crawler.crawl.crawl import Crawler
from crawler.models.nav_graph import NavigationGraph
from crawler.models.request import Request
from vuln_detection.utils.graph_util import normalize_graph_signatures


def _load_role_graph(role):
    path = vuln_scan_config.ROLE_NAVIGRAPH_PATH.format(role)
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return normalize_graph_signatures(data, role_hint=role)
    return {}


def _bootstrap_indices(navgraph):
    for node_key, info in navgraph.graph.items():
        if not isinstance(info, dict):
            continue
        url = info.get("req_url")
        if url:
            navgraph.url_index[url] = node_key
        if "|" in node_key:
            parts = node_key.split("|", 2)
            if len(parts) == 3 and parts[1] in {"GET", "POST", "PATCH", "DELETE", "PUT", "FETCH", "ANY"}:
                base_signature = parts[2]
            else:
                base_signature = node_key.split("|", 1)[1]
            navgraph.base_index.setdefault(base_signature, set()).add(node_key)


def _infer_scheme(headers):
    for key in ("origin", "referer"):
        value = headers.get(key)
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.scheme:
            return parsed.scheme
    return "http"


def _build_url(path, headers):
    if path.startswith("http://") or path.startswith("https://"):
        return path
    host = headers.get("host")
    if not host:
        raise ValueError("missing Host header")
    scheme = _infer_scheme(headers)
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}{path}"


def parse_raw_request(request_text):
    lines = request_text.strip("\n").splitlines()
    if not lines:
        raise ValueError("empty request")
    method, path, _ = lines[0].split()
    headers = {}
    body_lines = []
    in_body = False
    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
            continue
        if line.strip() == "":
            in_body = True
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    body = "\n".join(body_lines).strip()
    url = _build_url(path, headers)
    post_data = body if body else None
    return Request(url, method=method.upper(), headers=headers, post_data=post_data, base_url=url)


async def add_node(role, request_text):
    req = parse_raw_request(request_text)
    navgraph = NavigationGraph(role=role)
    navgraph.graph = _load_role_graph(role)
    _bootstrap_indices(navgraph)
    should_execute = navgraph.should_execute_request(req)
    if should_execute:
        crawler = await Crawler.create()
        response = await crawler.get_content(req)
        req.set_response(response)
        await crawler.browser_handler.safe_close_browser()

    node_key = navgraph.add_page(req)
    navgraph.visualize()
    print(f"[add_node] role={role} node={node_key} url={req.url} executed={should_execute}")


if __name__ == '__main__':
    role = "admin"
    request_text = """
PATCH /api/memo/1018 HTTP/1.1
Host: 10.176.36.21:5231
Content-Length: 74
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36
Content-Type: application/json
Origin: http://10.176.36.21:5231
Referer: http://10.176.36.21:5231/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: memos_session=MTc3MzUwMDYxMXxEdi1EQkFFQ180UUFBUkFCRUFBQUh2LUVBQUVHYzNSeWFXNW5EQWtBQjNWelpYSXRhV1FEYVc1MEJBSUFBZz09fHgh3hHLIJ7b_8rEpIwetThm2T3UA_URHOgSgZqat0pK
Connection: close

{"id":1018,"content":"asaasas","visibility":"PRIVATE","resourceIdList":[]}
"""
    asyncio.run(add_node(role, request_text))
