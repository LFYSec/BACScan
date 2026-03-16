# -*- coding: utf-8 -*-
import json
import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from config import vuln_scan_config
from config.crawl_config import crawler_config
from crawler.crawl.crawl import Crawler
from crawler.models.request import Request


def _load_cookie_dict(cookie_path):
    if not cookie_path:
        return None
    try:
        with open(cookie_path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception as e:
        logging.error(f"[-] Failed to load cookie data: {cookie_path}, error={repr(e)}")
    return None


def _extract_session_data(cookie_dict):
    cookies = {}
    local_storage = {}
    if not isinstance(cookie_dict, dict):
        return {"cookies": cookies, "local_storage": local_storage}
    for origin in cookie_dict.get("origins", []) or []:
        for session_dict in origin.get("localStorage", []) or []:
            name = session_dict.get("name")
            value = session_dict.get("value")
            if name is None or value is None:
                continue
            local_storage[str(name)] = str(value)
    for cookie in cookie_dict.get("cookies", []) or []:
        name = cookie.get("name")
        value = cookie.get("value")
        if name is None or value is None:
            continue
        cookies[str(name)] = str(value)
    return {"cookies": cookies, "local_storage": local_storage}


def _should_replace_session(session_name):
    name_lower = str(session_name).lower()
    return any(token in name_lower for token in vuln_scan_config.TOKEN_KEY_LIST)


def _get_header_key(headers, target):
    for key in headers.keys():
        if key.lower() == target:
            return key
    return None


def _parse_cookie_header(cookie_header):
    pairs = []
    if cookie_header is None:
        return pairs
    for part in str(cookie_header).split(";"):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        if not sep:
            pairs.append((name, ""))
        else:
            pairs.append((name, value))
    return pairs


def _format_cookie_header(pairs):
    return "; ".join(f"{name}={value}" if value != "" else name for name, value in pairs)


def _update_cookie_header(cookie_header, cookie_map):
    pairs = _parse_cookie_header(cookie_header)
    if not pairs:
        return cookie_header
    updated_pairs = []
    existing_names = set()
    for name, value in pairs:
        existing_names.add(name)
        if name in cookie_map:
            value = cookie_map[name]
        updated_pairs.append((name, value))
    if vuln_scan_config.COOKIE_APPEND_MISSING:
        for name, value in cookie_map.items():
            if name not in existing_names:
                updated_pairs.append((name, value))
    return _format_cookie_header(updated_pairs)


def _find_json_tokens(obj, key_set):
    tokens = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in key_set:
                if isinstance(value, (str, int)):
                    tokens.append(str(value))
            tokens.extend(_find_json_tokens(value, key_set))
    elif isinstance(obj, list):
        for item in obj:
            tokens.extend(_find_json_tokens(item, key_set))
    return tokens


def _extract_tokens_from_json(value):
    if not value:
        return []
    obj = value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped[0] not in ("{", "["):
            return []
        try:
            obj = json.loads(stripped)
        except Exception:
            return []
    key_set = {k.lower() for k in vuln_scan_config.SESSION_VALUE_JSON_KEYS}
    return _find_json_tokens(obj, key_set)


def _normalize_token_value(value):
    tokens = _extract_tokens_from_json(value)
    if tokens:
        return tokens[0]
    return value


def _resolve_header_token(header_lower, session_data):
    local_storage = session_data.get("local_storage", {})
    cookies = session_data.get("cookies", {})
    for name, target in vuln_scan_config.SESSION_NAME_MAP.items():
        if str(target).lower() == header_lower:
            if name in local_storage:
                return _normalize_token_value(local_storage[name])
            if name in cookies:
                return cookies[name]
    for cookie_name in vuln_scan_config.HEADER_COOKIE_MAP.get(header_lower, []):
        if cookie_name in cookies:
            return cookies[cookie_name]
    for name, value in local_storage.items():
        if _should_replace_session(name):
            return _normalize_token_value(value)
    for value in local_storage.values():
        tokens = _extract_tokens_from_json(value)
        if tokens:
            return tokens[0]
    return None


def _apply_session_entries(headers, session_data):
    if headers is None:
        return None
    updated = dict(headers)
    cookie_key = _get_header_key(updated, "cookie")
    if cookie_key:
        updated[cookie_key] = _update_cookie_header(updated.get(cookie_key), session_data.get("cookies", {}))
    for header_name in vuln_scan_config.HEADER_TOKEN_KEYS:
        header_key = _get_header_key(updated, header_name)
        if not header_key:
            continue
        token = _resolve_header_token(header_name.lower(), session_data)
        if token:
            updated[header_key] = token
    return updated


def _strip_auth_headers(headers):
    if headers is None:
        return None
    updated = dict(headers)
    token_keys = {"cookie"}
    token_keys.update(key.lower() for key in vuln_scan_config.HEADER_TOKEN_KEYS)
    for key in list(updated.keys()):
        if key.lower() in token_keys:
            updated[key] = None
    return updated


def _prepare_request_headers(info, cookie_path):
    headers = info.get("headers")
    if headers is None:
        return None
    if cookie_path:
        cookie_dict = _load_cookie_dict(cookie_path)
        if cookie_dict is None:
            return dict(headers)
        session_data = _extract_session_data(cookie_dict)
        return _apply_session_entries(headers, session_data)
    # Keep the original request session headers when no override is provided.
    return dict(headers)


def _is_visibility_key(key):
    return str(key or "").strip().lower() == "visibility"


def _force_visibility_in_json(obj):
    changed = False
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _is_visibility_key(key):
                if value != "PRIVATE":
                    changed = True
                obj[key] = "PRIVATE"
                continue
            if _force_visibility_in_json(value):
                changed = True
    elif isinstance(obj, list):
        for item in obj:
            if _force_visibility_in_json(item):
                changed = True
    return changed


def _normalize_visibility_in_query(info):
    req_url = info.get("req_url") or ""
    parsed = urlparse(req_url)
    query_source = parsed.query if parsed.query else str(info.get("get_params") or "")
    if not query_source:
        return
    params = parse_qs(query_source, keep_blank_values=True)
    changed = False
    for key in list(params.keys()):
        if _is_visibility_key(key):
            params[key] = ["PRIVATE"]
            changed = True
    if not changed:
        return
    new_query = urlencode(params, doseq=True)
    info["get_params"] = new_query
    if req_url:
        info["req_url"] = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
        )


def _content_type_of(headers):
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == "content-type":
            return str(value or "")
    return ""


def _normalize_visibility_in_post(info):
    post_params = info.get("post_params")
    if post_params in (None, ""):
        return

    content_type = _content_type_of(info.get("headers"))

    if isinstance(post_params, (dict, list)):
        if _force_visibility_in_json(post_params):
            info["post_params"] = post_params
        return

    raw = str(post_params)
    stripped = raw.strip()
    is_json_type = any(content_type.startswith(ct) for ct in vuln_scan_config.JSON_POST_DATA_TYPE)
    is_form_type = any(content_type.startswith(ct) for ct in vuln_scan_config.URLENCODED_POST_DATA_TYPE)

    if is_json_type or (stripped and stripped[0] in ("{", "[")):
        try:
            obj = json.loads(stripped)
        except Exception:
            obj = None
        if obj is not None and _force_visibility_in_json(obj):
            info["post_params"] = json.dumps(obj)
            return

    if is_form_type or "=" in raw:
        params = parse_qs(raw, keep_blank_values=True)
        changed = False
        for key in list(params.keys()):
            if _is_visibility_key(key):
                params[key] = ["PRIVATE"]
                changed = True
        if changed:
            info["post_params"] = urlencode(params, doseq=True)


def _enforce_visibility_private(info):
    if not isinstance(info, dict):
        return
    _normalize_visibility_in_query(info)
    _normalize_visibility_in_post(info)


async def get_html(info, cookie_path):
    html = ""
    url = info.get("req_url", "") if isinstance(info, dict) else ""
    try:
        _enforce_visibility_private(info)
        crawler_config.COOKIE_PATH = cookie_path
        crawler = await Crawler.create()
        url = info["req_url"]
        req = Request(url, base_url=url)
        req.method = info["method"]
        req.post_data = info["post_params"]
        req.headers = _prepare_request_headers(info, cookie_path)
        html = await crawler.get_content(req)
        await crawler.browser_handler.safe_close_browser()
    except Exception as e:
        print(e)
        logging.error(f"[-] Failed to get html content for {url}")
        return ""
    return html


def get_session_by_role(role):
    if role == vuln_scan_config.ADMIN_ROLE:
        return vuln_scan_config.ADMIN_COOKIE_PATH
    if role == vuln_scan_config.USER_ROLE:
        return vuln_scan_config.USER_COOKIE_PATH
    if role == vuln_scan_config.DET_USER_ROLE:
        return vuln_scan_config.USER_DET_COOKIE_PATH
    return None
