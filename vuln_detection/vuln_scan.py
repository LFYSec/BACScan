# -*- coding: utf-8 -*-
import logging
import os
import random
import string
from typing import Dict

from config.crawl_config import crawler_config
from config import *
from vuln_detection.similarity.dom_similarity import *
from vuln_detection.similarity.json_similarity import get_json_similarity
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import json
import re
import textwrap

from vuln_detection.core.failure import is_failure_response as _core_is_failure_response, is_html_shell_failure as _core_is_html_shell_failure
from vuln_detection.core.param_variants import load_param_variants as _core_load_param_variants, save_param_variants as _core_save_param_variants
from vuln_detection.core.http_client import get_html as _core_get_html, get_session_by_role as _core_get_session_by_role
from vuln_detection.core.response_store import get_normal_response as _core_get_normal_response
from vuln_detection.utils.graph_util import extract_node_role
from vuln_detection.core.replay import (
    replay_with_param_variants as _core_replay_with_param_variants,
    replay_with_param_fallback as _core_replay_with_param_fallback,
    apply_param_config as _core_apply_param_config,
    clone_request_info as _core_clone_request_info,
)


def load_data_dependence_map():
    path = vuln_scan_config.DATA_DEPENDENCE_PATH
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception as e:
        logging.error(f"[-] Failed to load data dependence map: {repr(e)}")
    return {}


def get_data_dependence_list(url, dependence_map):
    return dependence_map.get(url, [])


def generate_random_string(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))


_SCAN_LOGGED_NODES = set()
_PARAM_VARIANTS_CACHE = None


def _load_param_variants():
    global _PARAM_VARIANTS_CACHE
    if _PARAM_VARIANTS_CACHE is None:
        _PARAM_VARIANTS_CACHE = _core_load_param_variants()
    return _PARAM_VARIANTS_CACHE


def _save_param_variants(data):
    global _PARAM_VARIANTS_CACHE
    _core_save_param_variants(data)
    _PARAM_VARIANTS_CACHE = data


def _is_html_shell_failure(response, req_url):
    return _core_is_html_shell_failure(response, req_url)


def _is_failure_response(response, req_url=None):
    return _core_is_failure_response(response, req_url)


def _scan_header(node, progress=None):
    if node not in _SCAN_LOGGED_NODES:
        if _SCAN_LOGGED_NODES:
            print("")
        if progress:
            print(f"[vuln] {progress} {node}")
        else:
            print(f"[vuln] {node}")
        _SCAN_LOGGED_NODES.add(node)


def _scan_subblock(title, lines=None, response=None):
    print(f"  - {title}")
    if lines:
        for line in lines:
            print(f"    - {line}")
    if response is not None:
        print("    - response:")
        print(textwrap.indent(str(response), "      "))


def _format_param_config(config):
    if not isinstance(config, dict):
        return str(config)
    data = {}
    path = config.get("path")
    query = config.get("query")
    body = config.get("body")
    if path:
        data["path"] = path
    if query:
        data["get"] = query
    if body not in (None, ""):
        data["post"] = body
    if not data:
        return "{}"
    return json.dumps(data, ensure_ascii=True)


async def _replace_select_with_variants(info, victim_cookie, attacker_cookie, node_key=None):
    variants_map = _load_param_variants()
    key = node_key or info.get("signature") or info.get("es_id")
    if not key:
        return None
    variants = list(variants_map.get(key, []))
    if not variants:
        return None
    dirty = False
    for config in variants:
        candidate = _apply_param_config(info, config)
        victim_response = await get_html(candidate, victim_cookie)
        attacker_response = await get_html(candidate, attacker_cookie)
        success = not _is_failure_response(victim_response, candidate.get("req_url")) and not _is_failure_response(
            attacker_response, candidate.get("req_url")
        )
        if config in variants_map.get(key, []):
            variants_map[key].remove(config)
            dirty = True
            if not variants_map[key]:
                variants_map.pop(key, None)
        response_text = (
            f"victim={_format_response_text(victim_response)}\n"
            f"attacker={_format_response_text(attacker_response)}"
        )
        _scan_subblock(
            "Replace select",
            [
                f"params={_format_param_config(config)}",
            ],
            response=response_text,
        )
        if success:
            if dirty:
                _save_param_variants(variants_map)
            return candidate, victim_response, attacker_response
    if dirty:
        _save_param_variants(variants_map)
    return None

async def _replace_operate_with_variants(info, attacker_cookie, node_key=None, prepare_info=None):
    variants_map = _load_param_variants()
    key = node_key or info.get("signature") or info.get("es_id")
    if not key:
        return None
    variants = list(variants_map.get(key, []))
    if not variants:
        return None
    dirty = False
    for config in variants:
        candidate = _apply_param_config(info, config)
        if prepare_info:
            candidate = prepare_info(candidate)
        response = await get_html(candidate, attacker_cookie)
        if config in variants_map.get(key, []):
            variants_map[key].remove(config)
            dirty = True
            if not variants_map[key]:
                variants_map.pop(key, None)
        _scan_subblock(
            "Replace operate",
            [
                f"params={_format_param_config(config)}",
            ],
            response=_format_response_text(response),
        )
        if not _is_failure_response(response, candidate.get("req_url")):
            if dirty:
                _save_param_variants(variants_map)
            return response, candidate
    if dirty:
        _save_param_variants(variants_map)
    return None


def _truncate_text(value, limit=300):
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _format_request_line(info):
    method = (info.get("method") or "").upper()
    url = info.get("req_url") or ""
    if url:
        return f"{method} {url}".strip()
    return method


def _format_route(info):
    url = info.get("req_url") or ""
    parsed = urlparse(url)
    return parsed.path or "/"


def _normalize_qs(qs):
    result = {}
    for key, values in qs.items():
        if len(values) == 1:
            result[key] = values[0]
        else:
            result[key] = values
    return result


def _parse_post_params(info):
    body = info.get("post_params")
    if body in (None, ""):
        return None
    headers = info.get("headers") or {}
    content_type = headers.get("content-type") or headers.get("Content-Type") or ""
    if any(content_type.startswith(ct) for ct in vuln_scan_config.JSON_POST_DATA_TYPE):
        try:
            return json.loads(body) if isinstance(body, str) else body
        except Exception:
            return body
    if any(content_type.startswith(ct) for ct in vuln_scan_config.URLENCODED_POST_DATA_TYPE):
        return _normalize_qs(parse_qs(str(body), keep_blank_values=True))
    if isinstance(body, str):
        stripped = body.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(stripped)
            except Exception:
                return body
    return body


def _format_params(info):
    params = {}
    url = info.get("req_url") or ""
    parsed = urlparse(url)
    query_str = parsed.query or info.get("get_params") or ""
    query = parse_qs(query_str, keep_blank_values=True)
    if query:
        params["get"] = _normalize_qs(query)
    post = _parse_post_params(info)
    if post not in (None, "", {}):
        params["post"] = post
    if not params:
        return None
    return json.dumps(params, ensure_ascii=True)


def _format_response_text(response):
    if response is None:
        return ""
    return _truncate_text(response)


def _scan_request_response(title, info, response=None, extra_lines=None):
    lines = [
        f"request={_format_request_line(info)}",
        f"method={(info.get('method') or '').upper()}",
        f"route={_format_route(info)}",
    ]
    params_text = _format_params(info)
    if params_text:
        lines.append(f"params={params_text}")
    if extra_lines:
        lines.extend(extra_lines)
    if response is None:
        _scan_subblock(title, lines)
        return
    lines.append(f"response_len={len(str(response))}")
    _scan_subblock(title, lines, response=_format_response_text(response))


def _cookie_domain_matches(cookie_path, url):
    if not cookie_path:
        return None
    try:
        with open(cookie_path, "r") as f:
            cookie_dict = json.load(f)
    except Exception:
        return None
    host = urlparse(url).hostname or ""
    for cookie in cookie_dict.get("cookies", []):
        domain = str(cookie.get("domain", "")).lstrip(".")
        if not domain:
            continue
        if host == domain or host.endswith("." + domain):
            return True
    return False


def replace_after_equal(original_string, replacement_string):
    match = re.search(r'=(.*)', original_string)
    if match:
        prefix = original_string[:match.start()]
        new_string = prefix + "=" + replacement_string
        return new_string
    else:
        return original_string


async def get_html(info, cookie_path):
    return await _core_get_html(info, cookie_path)


def _clone_request_info(info):
    return _core_clone_request_info(info)


def _apply_param_config(info, config):
    return _core_apply_param_config(info, config, apply_method=True)


async def _replay_with_param_variants(info, cookie_path, node_key=None, prepare_info=None, base_response=None, base_info=None):
    return await _core_replay_with_param_variants(
        info,
        cookie_path,
        node_key=node_key,
        prepare_info=prepare_info,
        base_response=base_response,
        base_info=base_info,
    )


async def _replay_with_param_fallback(info, cookie_path, node_key=None, prepare_info=None):
    return await _core_replay_with_param_fallback(
        info,
        cookie_path,
        node_key=node_key,
        prepare_info=prepare_info,
    )


async def _get_html_with_session(info, cookie_path, node_key=None):
    response, _, _ = await _replay_with_param_fallback(_clone_request_info(info), cookie_path, node_key=node_key)
    return response


def is_similar(user_html, attacker_html):

    return get_dom_similarity(user_html, attacker_html) or get_json_similarity(user_html, attacker_html)

    # return SequenceMatcher(None, user_html, attacker_html).ratio() > 0.8


def get_session_by_role(role):
    return _core_get_session_by_role(role)


async def get_normal_response(target):
    return await _core_get_normal_response(target)


async def get_attack_response(target, current_role):
    current_session = get_session_by_role(current_role)
    attacker_html = await get_html(target, current_session)
    return attacker_html


def get_target(graph: Dict):
    target = []
    for node, info in graph.items():
        role = extract_node_role(node, info)
        if not role:
            continue
        if bool(info.get("public", False)):
            continue
        req_url = info.get("req_url") or ""
        if any(i in req_url for i in ["html"]):
            continue
        target.append(info)
    return target


def _normalize_role_for_vuln_type(role):
    role_text = str(role or "").lower()
    if role_text == vuln_scan_config.DET_USER_ROLE:
        return vuln_scan_config.USER_ROLE
    return role_text


def _classify_vuln_type(attacker_role, victim_role):
    attacker = _normalize_role_for_vuln_type(attacker_role)
    victim = _normalize_role_for_vuln_type(victim_role)
    return "horizontal" if attacker == victim else "vertical"


def replace_url_segment(url, segment, new_number):
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.split('/')
    try:
        segment_index = path_parts.index(segment)
        path_parts[segment_index + 1] = str(new_number)
    except ValueError:
        return url
    new_path = '/'.join(path_parts)
    new_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        new_path,
        parsed_url.params,
        parsed_url.query,
        parsed_url.fragment
    ))

    return new_url


def replace_delete_id(info):
    path = getattr(vuln_scan_config, "CONTROLLABLE_ID_PATH", None)
    if not path or not os.path.exists(path):
        return info
    try:
        with open(path, "r") as f:
            controllable_ids = json.load(f)
    except Exception:
        return info
    if not isinstance(controllable_ids, dict):
        return info

    headers = info["headers"]
    if "content-length" not in headers or headers["content-length"] == "0":
        # url parameter ??
        if "?" in info["req_url"]:
            parsed_url = urlparse(info["req_url"])
            url_query_params = parse_qs(parsed_url.query)
            for k, v in controllable_ids.items():
                if k in url_query_params:
                    url_query_params[k] = [str(v[0])]
            new_query_string = urlencode(url_query_params, doseq=True)
            info["req_url"] = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params,
                                          new_query_string, parsed_url.fragment))
        #path??
        else:
            for k, v in controllable_ids.items():
                if k in info["req_url"]:
                    info["req_url"] = replace_url_segment(info["req_url"], k, v[0])

    elif headers['content-type'] in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
        data = str(info["post_params"])
        url = "?" + data
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for k, v in controllable_ids.items():
            if k in query_params:
                query_params[k] = [str(v[0])]
        new_query_string = urlencode(query_params, doseq=True)
        info["post_params"] = new_query_string

    elif headers['content-type'] in vuln_scan_config.JSON_POST_DATA_TYPE:
        data = json.loads(info["post_params"])
        for k, v in controllable_ids.items():
            if k in data:
                try:
                    data[k] = int(v[0])
                except Exception:
                    print(f"{k} isn't resouce id!")
                    continue
        info["post_params"] = json.dumps(data)

    return info


def _is_json_content_type(headers):
    if not headers:
        return False
    content_type = headers.get("content-type") or headers.get("Content-Type") or ""
    return any(content_type.startswith(ct) for ct in vuln_scan_config.JSON_POST_DATA_TYPE)


def _is_urlencoded_content_type(headers):
    if not headers:
        return False
    content_type = headers.get("content-type") or headers.get("Content-Type") or ""
    return any(content_type.startswith(ct) for ct in vuln_scan_config.URLENCODED_POST_DATA_TYPE)


def _is_email_key(key):
    key_lower = str(key).lower()
    return any(k in key_lower for k in vuln_scan_config.EMAIL_FIELD_KEYWORDS)


def _is_insertable_key(key):
    key_lower = str(key).lower()
    if any(k in key_lower for k in vuln_scan_config.INPUT_STRING_LIST):
        return True
    return _is_email_key(key_lower)


def _token_value_for_key(key, token):
    if _is_email_key(key):
        return f"{token}@{vuln_scan_config.EMAIL_DOMAIN}"
    return token


def _insert_token_into_request(info, token=None):
    if token is None:
        token = generate_random_string()
    insertable_fields = []
    token_inserted = False
    headers = info.get("headers") or {}
    post_params = info.get("post_params")
    if post_params is None:
        return info, token, insertable_fields, token_inserted

    if _is_urlencoded_content_type(headers):
        params = parse_qs(str(post_params))
        for key in list(params.keys()):
            if _is_insertable_key(key):
                params[key] = [_token_value_for_key(key, token)]
                insertable_fields.append(key)
        if insertable_fields:
            info["post_params"] = urlencode(params, doseq=True)
            token_inserted = True
    elif _is_json_content_type(headers):
        try:
            data = json.loads(post_params)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for key in list(data.keys()):
                if _is_insertable_key(key):
                    data[key] = _token_value_for_key(key, token)
                    insertable_fields.append(key)
            if insertable_fields:
                info["post_params"] = json.dumps(data)
                token_inserted = True

    return info, token, insertable_fields, token_inserted


def _extract_id_candidates(info):
    candidates = []
    id_keys = {k.lower() for k in vuln_scan_config.SIGNATURE_ID_QUERY_KEYS}
    url = info.get("req_url") or ""
    parsed_url = urlparse(url)
    for key, values in parse_qs(parsed_url.query).items():
        if key.lower() in id_keys:
            for value in values:
                candidates.append(str(value))
    path_segments = [seg for seg in parsed_url.path.split("/") if seg]
    for seg in path_segments:
        for regex in vuln_scan_config.SIGNATURE_ID_REGEX:
            if re.fullmatch(regex, seg):
                candidates.append(seg)
                break
    headers = info.get("headers") or {}
    post_params = info.get("post_params")
    if post_params:
        if _is_urlencoded_content_type(headers):
            params = parse_qs(str(post_params))
            for key, values in params.items():
                if key.lower() in id_keys:
                    for value in values:
                        candidates.append(str(value))
        elif _is_json_content_type(headers):
            try:
                data = json.loads(post_params)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict):
                for key, value in data.items():
                    if key.lower() in id_keys:
                        candidates.append(str(value))
    return candidates


def _collect_ids_from_obj(obj, key_set, out):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in key_set:
                if isinstance(value, (str, int)):
                    out.add(str(value))
            _collect_ids_from_obj(value, key_set, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_ids_from_obj(item, key_set, out)


def _extract_ids_from_response(response):
    if response is None:
        return None
    obj = response
    if isinstance(response, str):
        stripped = response.strip()
        if not stripped:
            return None
        if stripped[0] not in ("{", "["):
            return None
        try:
            obj = json.loads(stripped)
        except Exception:
            return None
    if not isinstance(obj, (dict, list)):
        return None
    key_set = {k.lower() for k in vuln_scan_config.SIGNATURE_ID_QUERY_KEYS}
    ids = set()
    _collect_ids_from_obj(obj, key_set, ids)
    return ids or None


async def _detect_select_vuln(node_key, info, attacker_role):
    victim_cookie = None
    attacker_cookie = get_session_by_role(attacker_role)
    victim_info = _clone_request_info(info)
    victim_response = await get_html(victim_info, victim_cookie)
    attacker_info = _clone_request_info(victim_info)
    attacker_response = await get_html(attacker_info, attacker_cookie)

    if _is_failure_response(victim_response, victim_info.get("req_url")) or _is_failure_response(
        attacker_response, attacker_info.get("req_url")
    ):
        replace_result = await _replace_select_with_variants(info, victim_cookie, attacker_cookie, node_key=node_key)
        if replace_result:
            candidate_info, victim_response, attacker_response = replace_result
            victim_info = candidate_info
            attacker_info = _clone_request_info(candidate_info)

    invalid_response = _is_failure_response(victim_response, victim_info.get("req_url")) or _is_failure_response(
        attacker_response, victim_info.get("req_url")
    )
    similar = False if invalid_response else is_similar(victim_response, attacker_response)
    detected = bool(similar)
    return {
        "detected": detected,
        "invalid_response": invalid_response,
        "similar": similar,
        "victim_response": victim_response,
        "attacker_response": attacker_response,
        "info": victim_info,
    }


async def _detect_modify_vuln(node_key, info, graph, attacker_role, dependence_map):
    dependence_list = get_data_dependence_list(node_key, dependence_map)
    if not dependence_list:
        _scan_subblock("Modify check", ["dependence_list=empty"])
        return False

    op_info = _clone_request_info(info)

    token = generate_random_string()
    insertable_fields = []
    token_inserted = False

    def prepare(candidate):
        nonlocal insertable_fields, token_inserted
        prepared = _clone_request_info(candidate)
        prepared, _, fields, inserted = _insert_token_into_request(prepared, token=token)
        if fields and not insertable_fields:
            insertable_fields = fields
        if inserted:
            token_inserted = True
        return prepared

    victim_cookie = None
    attacker_cookie = get_session_by_role(attacker_role)

    baselines = []
    for data_node in dependence_list:
        target_info = graph.get(data_node)
        if not target_info:
            continue
        target_info_used = _clone_request_info(target_info)
        before_response = await get_html(target_info_used, victim_cookie)
        if before_response is None:
            before_response = ""
        signature = target_info_used.get("signature") or target_info_used.get("es_id") or target_info_used.get("req_url")
        _scan_request_response(
            "Dependence baseline",
            target_info_used,
            before_response,
            extra_lines=[f"signature={signature}"],
        )
        baselines.append((target_info_used, before_response))

    if not baselines:
        _scan_subblock("Modify check", ["dependence_targets=empty"])
        return False

    base_op_info = prepare(op_info)
    op_response = await get_html(base_op_info, attacker_cookie)
    op_info_used = base_op_info
    if _is_failure_response(op_response, op_info_used.get("req_url")):
        replace_result = await _replace_operate_with_variants(
            op_info,
            attacker_cookie,
            node_key=node_key,
            prepare_info=prepare,
        )
        if replace_result:
            op_response, op_info_used = replace_result
    if _is_failure_response(op_response, op_info_used.get("req_url")):
        _scan_subblock("Modify check", ["operate_request_failed"])
        return False
    if op_response is None:
        op_response = ""
    _scan_request_response(
        "Operate request",
        op_info_used,
        op_response,
        extra_lines=[
            f"attacker_role={attacker_role}",
            f"token_inserted={token_inserted}",
            f"insertable_fields={insertable_fields}",
        ],
    )
    op_info = op_info_used

    for target_info, before_response in baselines:
        after_response = await get_html(_clone_request_info(target_info), victim_cookie)
        if after_response is None:
            after_response = ""
        signature = target_info.get("signature") or target_info.get("es_id") or target_info.get("req_url")
        _scan_request_response(
            "Dependence after operate",
            target_info,
            after_response,
            extra_lines=[f"signature={signature}"],
        )

        if token_inserted:
            before_has = token in before_response
            after_has = token in after_response
            detected = (not before_has and after_has)
            _scan_subblock(
                "Dependence check",
                [
                    json.dumps(
                        {
                            "signature": signature,
                            "mode": "token",
                            "token": token,
                            "before_has_token": before_has,
                            "after_has_token": after_has,
                            "detected": detected,
                        },
                        ensure_ascii=True,
                    ),
                ],
            )
            if detected:
                return True

        if not token_inserted:
            candidates = _extract_id_candidates(op_info)
            before_ids = _extract_ids_from_response(before_response)
            after_ids = _extract_ids_from_response(after_response)
            detected = False
            for candidate in candidates:
                if not candidate:
                    continue
                before_has = candidate in before_ids if before_ids is not None else candidate in before_response
                after_has = candidate in after_ids if after_ids is not None else candidate in after_response
                if before_has and not after_has:
                    detected = True
                    break
            _scan_subblock(
                "Dependence check",
                [
                    json.dumps(
                        {
                            "signature": signature,
                            "mode": "id",
                            "candidates": candidates,
                            "before_ids": sorted(list(before_ids)) if before_ids else None,
                            "after_ids": sorted(list(after_ids)) if after_ids else None,
                            "detected": detected,
                        },
                        ensure_ascii=True,
                    ),
                ],
            )
            if detected:
                return True

    return False


async def vuln_detect(graph, attacker_role, desc="Vuln Detection", dependence_map=None):
    global _SCAN_LOGGED_NODES
    _SCAN_LOGGED_NODES = set()
    vuln_dict = dict()
    targets = get_target(graph)
    if dependence_map is None:
        dependence_map = load_data_dependence_map()

    # 使用 tqdm 创建进度条
    total = len(targets)
    for idx, t in enumerate(targets, start=1):
        url = t["req_url"]
        # if url != "http://127.0.0.1:5230/api/shortcut/1":
        #     continue
        try:
            node = t["es_id"]
            victim_role = extract_node_role(node, t)
            vuln_type = _classify_vuln_type(attacker_role, victim_role)
            operation = t.get("operation")
            _scan_header(node, progress=f"{idx}/{total}")
            if operation == "SELECT":
                result = await _detect_select_vuln(node, t, attacker_role)
                used_info = result.get("info") or t
                target_lines = [
                    f"request={_format_request_line(used_info)}",
                    f"operation={operation}",
                    f"method={(used_info.get('method') or '').upper()}",
                    f"route={_format_route(used_info)}",
                ]
                params_text = _format_params(used_info)
                if params_text:
                    target_lines.append(f"params={params_text}")
                _scan_subblock(
                    "Target request",
                    target_lines,
                )
                _scan_subblock(
                    "Response",
                    [
                        f"victim={_format_response_text(result.get('victim_response'))}",
                        f"attacker={_format_response_text(result.get('attacker_response'))}",
                    ],
                )
                _scan_subblock(
                    "Vuln analysis",
                    [
                        f"invalid_response={result.get('invalid_response')}",
                        f"similar={result.get('similar')}",
                        f"vuln_type={vuln_type}",
                        f"detected={result.get('detected')}",
                    ],
                )
                if result.get("detected"):
                    if any(i in node for i in Black_list):
                        _scan_subblock("Skip blacklist", [f"node={node}"])
                        continue
                    record = _clone_request_info(t)
                    record["attacker_role"] = attacker_role
                    record["victim_role"] = victim_role
                    record["vuln_type"] = vuln_type
                    vuln_dict[node] = record
            elif operation in ("INSERT", "UPDATE", "DELETE"):
                target_lines = [
                    f"request={_format_request_line(t)}",
                    f"operation={operation}",
                    f"method={(t.get('method') or '').upper()}",
                    f"route={_format_route(t)}",
                ]
                params_text = _format_params(t)
                if params_text:
                    target_lines.append(f"params={params_text}")
                _scan_subblock(
                    "Target request",
                    target_lines,
                )
                if await _detect_modify_vuln(node, t, graph, attacker_role, dependence_map):
                    _scan_subblock("Vuln result", [f"detected=True", f"vuln_type={vuln_type}"])
                    record = _clone_request_info(t)
                    record["attacker_role"] = attacker_role
                    record["victim_role"] = victim_role
                    record["vuln_type"] = vuln_type
                    vuln_dict[node] = record
                else:
                    _scan_subblock("Vuln result", ["detected=False"])


        except Exception as e:
            logging.error(f"[-] Error in vuln detection: {repr(e)}")

    return vuln_dict


