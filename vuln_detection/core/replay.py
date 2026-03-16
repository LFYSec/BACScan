# -*- coding: utf-8 -*-
import json
from urllib.parse import urlencode, urlparse, urlunparse

from vuln_detection.core.failure import is_failure_response
from vuln_detection.core.http_client import get_html
from vuln_detection.core.param_variants import load_param_variants, save_param_variants


def clone_request_info(info):
    cloned = dict(info)
    if isinstance(info.get("headers"), dict):
        cloned["headers"] = dict(info["headers"])
    return cloned


def apply_param_config(info, config, apply_method=True):
    updated = clone_request_info(info)
    parsed = urlparse(updated.get("req_url") or "")
    path = config.get("path") or parsed.path
    query = config.get("query") or {}
    query_string = urlencode(query, doseq=True)
    updated["req_url"] = urlunparse((parsed.scheme, parsed.netloc, path, "", query_string, ""))
    updated["get_params"] = query_string

    body_kind = config.get("body_kind") or ""
    body = config.get("body")
    if body is None:
        updated["post_params"] = None
    else:
        if body_kind == "json":
            if isinstance(body, (dict, list)):
                updated["post_params"] = json.dumps(body)
            else:
                updated["post_params"] = str(body)
        elif body_kind == "urlencoded":
            if isinstance(body, dict):
                updated["post_params"] = urlencode(body, doseq=True)
            else:
                updated["post_params"] = str(body)
        else:
            updated["post_params"] = str(body)

    method = config.get("method")
    if apply_method and method:
        updated["method"] = method
    return updated


async def replay_with_param_variants(info, cookie_path, node_key=None, prepare_info=None, base_response=None, base_info=None):
    key = node_key or info.get("signature") or info.get("es_id")
    if not key:
        return base_response, base_info or info, {"success": False, "response": None}
    variants_map = load_param_variants()
    variants = list(variants_map.get(key, []))
    if not variants:
        return base_response, base_info or info, {"success": False, "response": None}

    dirty = False
    for config in variants:
        candidate = apply_param_config(info, config, apply_method=True)
        if prepare_info:
            candidate = prepare_info(candidate)
        candidate_resp = await get_html(candidate, cookie_path)
        if config in variants_map.get(key, []):
            variants_map[key].remove(config)
            dirty = True
            if not variants_map[key]:
                variants_map.pop(key, None)
        if is_failure_response(candidate_resp, candidate.get("req_url")):
            continue
        if dirty:
            save_param_variants(variants_map)
        return candidate_resp, candidate, {"success": True, "response": candidate_resp}
    if dirty:
        save_param_variants(variants_map)
    return base_response, base_info or info, {"success": False, "response": None}


async def replay_with_param_fallback(info, cookie_path, node_key=None, prepare_info=None):
    base_info = prepare_info(info) if prepare_info else info
    response = await get_html(base_info, cookie_path)
    if not is_failure_response(response, base_info.get("req_url")):
        return response, base_info, {"success": False, "response": None}
    return await replay_with_param_variants(
        info,
        cookie_path,
        node_key=node_key,
        prepare_info=prepare_info,
        base_response=response,
        base_info=base_info,
    )
