#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os
from copy import deepcopy
from urllib.parse import parse_qs, urlparse

from config import vuln_scan_config
from vuln_detection.core.replay import apply_param_config
from vuln_detection.core.http_client import get_session_by_role
from vuln_detection.core.http_client import (
    _apply_session_entries,
    _extract_session_data,
    _get_header_key,
    _load_cookie_dict,
    _resolve_header_token,
)
from vuln_detection.utils.data_dependence_util import insert_str_token, update_num_token


def _truncate(value, limit=240):
    if value is None:
        return "None"
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _normalize_post_params(value):
    if value in (None, "", "None", "null"):
        return None
    return value


def _normalize_headers(headers):
    if not isinstance(headers, dict):
        return {}
    normalized = {}
    for key, value in headers.items():
        if value is None:
            continue
        normalized[str(key).lower()] = value
    return normalized


def _normalize_map(data):
    if not isinstance(data, dict):
        return {}
    normalized = {}
    for key, value in data.items():
        if isinstance(value, list):
            values = [str(v) for v in value]
        elif value is None:
            values = []
        else:
            values = [str(value)]
        normalized[str(key)] = sorted(values)
    return normalized


def _normalize_json(value):
    if isinstance(value, dict):
        return {str(k): _normalize_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_json(v) for v in value]
    if value is None:
        return None
    return str(value)


def _content_type(headers):
    return headers.get(vuln_scan_config.CONTENT_TYPE_HEADER, "")


def _find_keys_for_body(content_type, body_text):
    if not body_text:
        return []
    if content_type in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
        params = parse_qs(str(body_text), keep_blank_values=True)
        return list(params.keys())
    if content_type in vuln_scan_config.JSON_POST_DATA_TYPE:
        try:
            data = json.loads(body_text)
        except Exception:
            return []
        if isinstance(data, dict):
            return list(data.keys())
    return []


def _is_insertable_key(key):
    key_lower = str(key).lower()
    if any(k in key_lower for k in vuln_scan_config.INPUT_STRING_LIST):
        return True
    return any(k in key_lower for k in vuln_scan_config.EMAIL_FIELD_KEYWORDS)


def _test_insert_str_token(info, strict):
    headers = info.get("headers") or {}
    content_type = _content_type(headers)
    body = info.get("post_params")
    if not body:
        return "skip", "no body", []
    keys = _find_keys_for_body(content_type, body)
    if not keys:
        return "skip", "unsupported content-type or empty body", []
    insertable = [k for k in keys if _is_insertable_key(k)]
    if not insertable:
        if strict:
            return "fail", "no insertable keys", []
        return "skip", "no insertable keys", []

    updated, token, fields, inserted = insert_str_token(deepcopy(info))
    if not inserted:
        return "fail", "insertable keys found but no replacement occurred", []
    details = [
        f"post_params(before)={_truncate(body)}",
        f"post_params(after)={_truncate(updated.get('post_params'))}",
    ]
    return "pass", f"fields={fields} token={token}", details


def _test_update_num_token(info, strict):
    headers = info.get("headers") or {}
    content_type = _content_type(headers)
    body = info.get("post_params")
    if not body:
        return "skip", "no body", []
    keys = _find_keys_for_body(content_type, body)
    if not keys:
        return "skip", "unsupported content-type or empty body", []
    numeric_keys = [
        k for k in keys if any(n in str(k).lower() for n in vuln_scan_config.INPUT_NUM_LIST)
    ]
    if not numeric_keys:
        if strict:
            return "fail", "no numeric keys", []
        return "skip", "no numeric keys", []

    updated, token = update_num_token(deepcopy(info))
    details = [
        f"post_params(before)={_truncate(body)}",
        f"post_params(after)={_truncate(updated.get('post_params'))}",
    ]
    return "pass", f"keys={numeric_keys} token={token}", details


def _validate_variant(updated, config):
    parsed = urlparse(updated.get("req_url") or "")
    config_path = config.get("path") or parsed.path
    if parsed.path != config_path:
        return False, f"path mismatch expected={config_path} got={parsed.path}"

    config_query = _normalize_map(config.get("query") or {})
    updated_query = _normalize_map(parse_qs(parsed.query, keep_blank_values=True))
    if updated_query != config_query:
        return False, f"query mismatch expected={config_query} got={updated_query}"

    body_kind = config.get("body_kind") or ""
    body = config.get("body")
    updated_body = updated.get("post_params")
    if body is None:
        if updated_body not in (None, "", "None"):
            return False, f"body mismatch expected=None got={updated_body}"
        return True, "ok"

    if body_kind == "urlencoded":
        updated_params = _normalize_map(parse_qs(str(updated_body), keep_blank_values=True))
        config_params = _normalize_map(body if isinstance(body, dict) else {})
        if updated_params != config_params:
            return False, f"body mismatch expected={config_params} got={updated_params}"
        return True, "ok"

    if body_kind == "json":
        try:
            updated_json = json.loads(updated_body)
        except Exception:
            return False, f"body mismatch expected json got={updated_body}"
        if _normalize_json(updated_json) != _normalize_json(body):
            return False, f"body mismatch expected={body} got={updated_json}"
        return True, "ok"

    if str(updated_body) != str(body):
        return False, f"body mismatch expected={body} got={updated_body}"
    return True, "ok"


def _test_controllable(signature, base_info, variants):
    if not variants:
        return "skip", "no controllable variants", []
    details = []
    for idx, config in enumerate(variants):
        updated = apply_param_config(base_info, config, apply_method=True)
        ok, message = _validate_variant(updated, config)
        if not ok:
            return "fail", f"config[{idx}] {message}", details
        if idx == 0:
            details.append(
                "variant[{0}] req_url={1} post_params={2}".format(
                    idx,
                    _truncate(updated.get("req_url")),
                    _truncate(updated.get("post_params")),
                )
            )
    return "pass", f"variants={len(variants)}", details


def _test_session_replace(info, role):
    headers = info.get("headers") or {}
    if not headers:
        return "skip", "no headers", []
    cookie_path = get_session_by_role(role)
    if not cookie_path or not os.path.exists(cookie_path):
        return "skip", "session file missing", []
    cookie_dict = _load_cookie_dict(cookie_path)
    if cookie_dict is None:
        return "skip", "invalid session file", []
    session_data = _extract_session_data(cookie_dict)
    if not session_data.get("cookies") and not session_data.get("local_storage"):
        return "skip", "empty session data", []

    relevant_keys = set()
    for key in headers.keys():
        key_lower = str(key).lower()
        if key_lower == "cookie" or key_lower in [k.lower() for k in vuln_scan_config.HEADER_TOKEN_KEYS]:
            relevant_keys.add(key)
    if not relevant_keys:
        return "skip", "no auth headers", []

    expected = _apply_session_entries(headers, session_data)
    details = []
    auth_parts = []
    for key in sorted(relevant_keys):
        auth_parts.append(f"{key}={_truncate(expected.get(key))}")
    if auth_parts:
        details.append("headers(after)=" + "; ".join(auth_parts))
    changed_keys = [k for k in relevant_keys if headers.get(k) != expected.get(k)]
    if changed_keys:
        return "pass", f"updated={changed_keys}", details

    matched = []
    for header in vuln_scan_config.HEADER_TOKEN_KEYS:
        header_key = _get_header_key(headers, header)
        if not header_key:
            continue
        token = _resolve_header_token(header.lower(), session_data)
        if token and headers.get(header_key) == token:
            matched.append(header_key)
    if matched:
        return "pass", f"already matched={matched}", details

    if any(str(k).lower() == "cookie" for k in relevant_keys):
        return "pass", "cookie already matched session", details
    return "fail", "auth headers not updated", details


def _build_base_info(signature, node_info):
    return {
        "signature": signature,
        "req_url": node_info.get("req_url"),
        "get_params": node_info.get("get_params") or "",
        "post_params": _normalize_post_params(node_info.get("post_params")),
        "method": node_info.get("method") or "GET",
        "headers": _normalize_headers(node_info.get("headers") or {}),
    }


def _load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def _print_detail_lines(lines):
    for line in lines:
        print(f"    {line}")


def _print_node_result(signature, insert_res, num_res, ctrl_res, session_res):
    print(f"[node] {signature}")
    print(f"  insert_str_token: {insert_res[0]} ({insert_res[1]})")
    _print_detail_lines(insert_res[2])
    print(f"  update_num_token: {num_res[0]} ({num_res[1]})")
    _print_detail_lines(num_res[2])
    print(f"  controllable: {ctrl_res[0]} ({ctrl_res[1]})")
    _print_detail_lines(ctrl_res[2])
    print(f"  session_replace: {session_res[0]} ({session_res[1]})")
    _print_detail_lines(session_res[2])


def _iter_nav_graphs(nav_dir):
    if not nav_dir or not os.path.isdir(nav_dir):
        return
    for root, _, files in os.walk(nav_dir):
        for name in files:
            if not name.endswith("_navigraph.json"):
                continue
            yield os.path.join(root, name)


def _role_from_filename(path):
    name = os.path.basename(path)
    if not name.endswith("_navigraph.json"):
        return "visitor"
    return name[: -len("_navigraph.json")]


def main():
    nav_dir = vuln_scan_config.NAV_GRAPH_DIR
    if not nav_dir or not os.path.isdir(nav_dir):
        print(f"nav graph dir not found: {nav_dir}")
        raise SystemExit(2)

    controllable = {}
    controllable_path = vuln_scan_config.CONTROLLABLE_PARAM_PATH
    if controllable_path and os.path.exists(controllable_path):
        controllable = _load_json(controllable_path)
        if not isinstance(controllable, dict):
            controllable = {}
    else:
        print(f"[warn] controllable params not found: {controllable_path}")

    totals = {
        "insert": {"pass": 0, "fail": 0, "skip": 0},
        "num": {"pass": 0, "fail": 0, "skip": 0},
        "ctrl": {"pass": 0, "fail": 0, "skip": 0},
        "session": {"pass": 0, "fail": 0, "skip": 0},
    }
    failed_nodes = []

    nav_files = list(_iter_nav_graphs(nav_dir))
    if not nav_files:
        print(f"no nav graph files found in: {nav_dir}")
        raise SystemExit(2)

    for nav_path in nav_files:
        nav_graph = _load_json(nav_path)
        if not isinstance(nav_graph, dict) or not nav_graph:
            print(f"[skip] empty nav graph: {nav_path}")
            continue
        role = _role_from_filename(nav_path)
        print(f"[nav] {nav_path} role={role} nodes={len(nav_graph)}")

        for signature, node_info in nav_graph.items():
            base_info = _build_base_info(signature, node_info or {})
            insert_res = _test_insert_str_token(base_info, strict=False)
            num_res = _test_update_num_token(base_info, strict=False)
            ctrl_res = _test_controllable(signature, base_info, controllable.get(signature, []))
            session_res = _test_session_replace(base_info, role)

            totals["insert"][insert_res[0]] += 1
            totals["num"][num_res[0]] += 1
            totals["ctrl"][ctrl_res[0]] += 1
            totals["session"][session_res[0]] += 1

            if "fail" in (insert_res[0], num_res[0], ctrl_res[0], session_res[0]):
                failed_nodes.append(signature)

            _print_node_result(signature, insert_res, num_res, ctrl_res, session_res)

    print("[summary]")
    print(f"  nav_dir={nav_dir}")
    print(f"  insert_str_token={totals['insert']}")
    print(f"  update_num_token={totals['num']}")
    print(f"  controllable={totals['ctrl']}")
    print(f"  session_replace={totals['session']}")
    if failed_nodes:
        print("  failed_nodes:")
        for signature in failed_nodes:
            print(f"    - {signature}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
