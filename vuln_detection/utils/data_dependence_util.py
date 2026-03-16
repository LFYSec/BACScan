import asyncio
import json
import random
import string
import logging
import os
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import Levenshtein
from bs4 import BeautifulSoup
from vuln_detection.similarity.json_similarity import is_valid_json
from vuln_detection.utils.es_util import ElasticsearchClient
from config import vuln_scan_config
from vuln_detection.core.failure import is_failure_response
from vuln_detection.core.http_client import get_html
from vuln_detection.core.param_variants import load_param_variants as _core_load_param_variants, save_param_variants as _core_save_param_variants
from vuln_detection.core.response_store import get_normal_response
from vuln_detection.utils.graph_util import extract_node_role
from lxml import html
import textwrap

# Constants

_PARAM_VARIANTS_CACHE = None


def _clone_request_info(info):
    cloned = dict(info)
    headers = info.get("headers")
    if isinstance(headers, dict):
        cloned["headers"] = dict(headers)
    return cloned


def _load_param_variants():
    global _PARAM_VARIANTS_CACHE
    if _PARAM_VARIANTS_CACHE is None:
        _PARAM_VARIANTS_CACHE = _core_load_param_variants()
    return _PARAM_VARIANTS_CACHE


def _save_param_variants(data):
    global _PARAM_VARIANTS_CACHE
    _core_save_param_variants(data)
    _PARAM_VARIANTS_CACHE = data



def _find_param_variants(node, variants_map):
    variants = variants_map.get(node)
    if variants:
        return node, list(variants)
    return None, []


def _normalize_param_dict(data):
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


def _normalize_body_value(value):
    if value is None or value == "":
        return None
    if isinstance(value, dict):
        return _normalize_param_dict(value)
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(value)


def _config_matches_info(info, config):
    parsed = urlparse(info.get("req_url") or "")
    info_path = parsed.path
    info_query = _normalize_param_dict(parse_qs(parsed.query, keep_blank_values=True))

    config_path = config.get("path") or info_path
    config_query = _normalize_param_dict(config.get("query") or {})

    if config_path != info_path:
        return False
    if config_query != info_query:
        return False

    info_body = None
    post_params = info.get("post_params")
    headers = info.get("headers") or {}
    content_type = headers.get(vuln_scan_config.CONTENT_TYPE_HEADER, "")
    if post_params:
        if content_type in vuln_scan_config.JSON_POST_DATA_TYPE:
            info_body = _try_load_json(post_params, log_error=False)
        elif content_type in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
            info_body = parse_qs(str(post_params), keep_blank_values=True)
        else:
            info_body = str(post_params)

    return _normalize_body_value(info_body) == _normalize_body_value(config.get("body"))


def _apply_param_config(info, config):
    updated = _clone_request_info(info)
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

    return updated


async def _classify_delete_or_update(node, base_info, cookie_path, replay_response, token, token_inserted):
    if not is_failure_response(replay_response, base_info.get("req_url")):
        return None, None, False, None
    variants_map = _load_param_variants()
    variant_key, _ = _find_param_variants(node, variants_map)
    if not variant_key:
        return None, None, True, {"params": None, "response": None, "result": "INVALID", "replace_success": False}

    existing = list(variants_map.get(variant_key, []))
    dirty = False
    for config in existing:
        if _config_matches_info(base_info, config):
            variants_map[variant_key].remove(config)
            dirty = True
    if dirty:
        if not variants_map.get(variant_key):
            variants_map.pop(variant_key, None)
        _save_param_variants(variants_map)

    variants = list(variants_map.get(variant_key, []))
    if not variants:
        return None, None, True, {"params": None, "response": None, "result": "INVALID", "replace_success": False}

    dirty = False
    for config in variants:
        candidate = _apply_param_config(base_info, config)
        candidate_insertable_fields = []
        candidate_token_inserted = False
        if token_inserted and token:
            candidate, _, candidate_insertable_fields, candidate_token_inserted = insert_str_token(
                candidate, token=token
            )
        first = await get_html(candidate, cookie_path)
        if config in variants_map.get(variant_key, []):
            variants_map[variant_key].remove(config)
            dirty = True
            if not variants_map[variant_key]:
                variants_map.pop(variant_key, None)
        if is_failure_response(first, candidate.get("req_url")):
            continue
        second = await get_html(candidate, cookie_path)
        if is_failure_response(second, candidate.get("req_url")):
            if dirty:
                _save_param_variants(variants_map)
            return "DELETE", candidate, False, {
                "params": {"get": candidate.get("get_params"), "post": candidate.get("post_params")},
                "response": first,
                "result": "DELETE",
                "replace_success": True,
                "token_inserted": False,
                "insertable_fields": [],
            }
        if dirty:
            _save_param_variants(variants_map)
        token_seen = candidate_token_inserted and token and token in str(first)
        if token_seen:
            result = "UPDATE"
        else:
            result = None
        return result, candidate, False, {
            "params": {"get": candidate.get("get_params"), "post": candidate.get("post_params")},
            "response": first,
            "result": result,
            "replace_success": True,
            "token_inserted": bool(candidate_token_inserted),
            "insertable_fields": candidate_insertable_fields,
        }

    if dirty:
        _save_param_variants(variants_map)
    return None, None, True, {"params": None, "response": None, "result": "INVALID", "replace_success": False}


# Utility Functions
def generate_random_string(length=10):
    """
    Generates a random alphanumeric string.

    Args:
        length (int): Length of the generated string. Default is 10.

    Returns:
        str: A random alphanumeric string.
    """
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))


def parse_query_params(data):
    """
    Parses query parameters from a given URL or POST data string.

    Args:
        data (str): String containing URL or POST data.

    Returns:
        dict: Parsed query parameters as key-value pairs.
    """
    url = "?" + data
    parsed_url = urlparse(url)
    return parse_qs(parsed_url.query)


def extract_redirect_url(headers):
    """
    Extracts the redirect URL from HTTP headers.

    Args:
        headers (dict): HTTP headers.

    Returns:
        str or None: The redirect URL if present, otherwise None.
    """
    if isinstance(headers, dict):  # Ensure headers is a dictionary
        return headers.get('Location')
    else:
        logging.error(f"Expected headers to be a dictionary, but got {type(headers)}")
        return None


def calculate_similarity(str1, str2):
    """
    Calculates similarity between two strings using Levenshtein ratio.

    Args:
        str1 (str): First string to compare.
        str2 (str): Second string to compare.

    Returns:
        float: Similarity score between 0 and 1.
    """
    if not str1 or not str2:
        return 0.0
    return Levenshtein.ratio(str1, str2)


def update_json_data(data, key_list, value):
    """
    Updates specific keys in a JSON object with a given value.

    Args:
        data (dict): JSON object to update.
        key_list (list): List of keys to update.
        value (any): Value to assign to the keys.

    Returns:
        dict: Updated JSON object.
    """
    for key, val in data.items():
        if any(k in key.lower() for k in key_list):
            data[key] = value
    return data


def update_query_params(params, key_list, value):
    """
    Updates query parameters matching specific keys with a given value.

    Args:
        params (dict): Query parameters as key-value pairs.
        key_list (list): List of keys to update.
        value (any): Value to assign to the keys.

    Returns:
        dict: Updated query parameters.
    """
    for key in params:
        if any(k in key.lower() for k in key_list):
            params[key] = [value]
    return params


def _try_load_json(value, log_error=False):
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        if log_error:
            logging.error(f"Failed to decode JSON: {e}")
        return None


# Core Functions
_DEP_LOGGED_NODES = set()
_DEP_DETECTED = {}


def _ensure_node_header(node):
    if node not in _DEP_LOGGED_NODES:
        if _DEP_LOGGED_NODES:
            print("")
        print(f"[dependence] {node}")
        _DEP_LOGGED_NODES.add(node)


def _print_subblock(title, lines=None, response=None):
    print(f"  - {title}")
    if lines:
        for line in lines:
            print(f"    - {line}")
    if response is not None:
        print("    - response:")
        print(textwrap.indent(str(response), "      "))


def _flush_detected_dependence(node):
    signatures = _DEP_DETECTED.pop(node, [])
    if not signatures:
        return
    _ensure_node_header(node)
    print("  - Detected dependence")
    for idx, signature in enumerate(signatures):
        print(f"    {signature}")
        if idx != len(signatures) - 1:
            print("")


def _set_operation(graph, node, operation):
    node_info = graph.get(node)
    if isinstance(node_info, dict):
        node_info["operation"] = operation


def _reset_operations(graph):
    for info in graph.values():
        if isinstance(info, dict):
            method = (info.get("method") or "").upper()
            info["operation"] = "SELECT" if method == "GET" else None


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


def _get_insertable_fields(params):
    return [key for key in params.keys() if _is_insertable_key(key)]


def _extract_param_keys(info):
    headers = info.get("headers") or {}
    content_type = headers.get(vuln_scan_config.CONTENT_TYPE_HEADER, "")
    post_params = info.get("post_params")
    if not post_params:
        return []
    if content_type in vuln_scan_config.JSON_POST_DATA_TYPE:
        data = _try_load_json(post_params, log_error=False)
        if isinstance(data, dict):
            return [str(k) for k in data.keys()]
        return []
    if content_type in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
        params = parse_query_params(str(post_params))
        return [str(k) for k in params.keys()]
    if isinstance(post_params, str) and "=" in post_params:
        params = parse_query_params(str(post_params))
        return [str(k) for k in params.keys()]
    return []


def _is_auth_like_request(info):
    url = str(info.get("req_url") or "").lower()
    if any(keyword in url for keyword in vuln_scan_config.AUTH_URL_KEYWORDS):
        return True
    param_keys = _extract_param_keys(info)
    for key in param_keys:
        key_lower = key.lower()
        if any(k in key_lower for k in vuln_scan_config.AUTH_PARAM_KEYWORDS):
            return True
    return False


def insert_str_token(info, token=None):
    """
    Inserts a random string token into request parameters.

    Args:
        info (dict): Request information, including headers and parameters.

    Returns:
        tuple: Updated request information and the inserted token.
    """
    if token is None:
        token = generate_random_string()
    headers = info["headers"]
    insertable_fields = []
    token_inserted = False

    if headers.get(vuln_scan_config.CONTENT_TYPE_HEADER) in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
        params = parse_query_params(str(info["post_params"]))
        insertable_fields = _get_insertable_fields(params)
        for key in insertable_fields:
            params[key] = [_token_value_for_key(key, token)]
        if insertable_fields:
            info["post_params"] = urlencode(params, doseq=True)
            token_inserted = True

    elif headers.get(vuln_scan_config.CONTENT_TYPE_HEADER) in vuln_scan_config.JSON_POST_DATA_TYPE:
        data = _try_load_json(info["post_params"], log_error=True)
        if isinstance(data, dict):
            insertable_fields = _get_insertable_fields(data)
            for key in insertable_fields:
                data[key] = _token_value_for_key(key, token)
            if insertable_fields:
                info["post_params"] = json.dumps(data)
                token_inserted = True

    return info, token, insertable_fields, token_inserted


def update_num_token(info):
    """
    Inserts a random numeric token into request parameters.

    Args:
        info (dict): Request information, including headers and parameters.

    Returns:
        tuple: Updated request information and the inserted token.
    """
    token = random.randint(1, 10)
    headers = info["headers"]

    if headers.get(vuln_scan_config.CONTENT_TYPE_HEADER) in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
        params = parse_query_params(str(info["post_params"]))
        info["post_params"] = urlencode(update_query_params(params, vuln_scan_config.INPUT_NUM_LIST, str(token)),
                                        doseq=True)

    elif headers.get(vuln_scan_config.CONTENT_TYPE_HEADER) in vuln_scan_config.JSON_POST_DATA_TYPE:
        data = _try_load_json(info["post_params"], log_error=True)
        if isinstance(data, dict):
            info["post_params"] = json.dumps(update_json_data(data, vuln_scan_config.INPUT_NUM_LIST, token))

    return info, token


def get_param_list(info):
    """
    Extracts parameters from a request based on the method and content type.

    Args:
        info (dict): Request information, including headers and method.

    Returns:
        list: List of parameters extracted from the request.
    """
    headers = info["headers"]
    method = info["method"]

    if method == "GET" or vuln_scan_config.CONTENT_TYPE_HEADER not in headers:
        return parse_query_params(str(info["get_params"]))

    if method in vuln_scan_config.OPERATE_METHOD_LIST and info.get("post_params"):
        content_type = headers.get(vuln_scan_config.CONTENT_TYPE_HEADER)

        if content_type in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
            return parse_query_params(str(info["post_params"]))

        if content_type in vuln_scan_config.JSON_POST_DATA_TYPE:
            data = _try_load_json(info["post_params"], log_error=True)
            if isinstance(data, dict):
                return list(data.keys())

    return []


async def count_score(node, get_node, info, get_info):
    """
    Calculates a score to rank dependency relationships between nodes.

    Args:
        node (str): The current node.
        get_node (str): The target node to evaluate.
        info (dict): Information about the current node.
        get_info (dict): Information about the target node.

    Returns:
        float: Calculated dependency score.
    """
    node_param_list = get_param_list(info)
    get_response = await get_normal_response(get_info)

    headers_redirect_url = extract_redirect_url(info["headers"])
    post_response = await get_normal_response(info)

    if "body" in post_response:
        soup = BeautifulSoup(post_response, 'html.parser')
        json_data = soup.find('body').get_text()
    else:
        json_data = post_response

    redirect_url = extract_redirect_url(json.loads(json_data)) if is_valid_json(json_data) else None

    score = 1 / (
            1 + calculate_similarity(headers_redirect_url, get_node) + calculate_similarity(redirect_url, get_node)
    )

    if node_param_list:
        score += len([param for param in node_param_list if param in get_response]) / len(node_param_list)

    return score


async def sort_by_score(node, info, graph):
    """
    Sorts nodes in a graph by dependency scores.

    Args:
        node (str): The current node.
        info (dict): Information about the current node.
        graph (dict): The dependency graph.

    Returns:
        dict: Sorted nodes by their dependency scores.
    """
    source_role = extract_node_role(node, info)
    tasks = {
        get_node: count_score(node, get_node, info, get_info)
        for get_node, get_info in graph.items()
        if get_info["method"] == "GET"
        and get_node != node
        and extract_node_role(get_node, get_info) == source_role
    }
    scores = await asyncio.gather(*tasks.values())
    return dict(sorted(zip(tasks.keys(), scores), key=lambda item: item[1]))


def get_xpath_for_token(token, content):
    try:
        json_data = json.loads(content)
        return [token]
    except json.JSONDecodeError:
        pass

    try:
        tree = html.fromstring(content)
        result = tree.xpath(f"//*[contains(text(), '{token}')]")
        if result:
            xpaths = []
            for elem in result:
                xpath = tree.getpath(elem)
                xpaths.append(xpath)
            return xpaths
    except Exception as e:
        print(f"Error while parsing HTML content: {e}")
        return [token]
    return [token]


def _extract_records(payload):
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        if "data" in payload:
            return _extract_records(payload.get("data"))
        if "result" in payload:
            return _extract_records(payload.get("result"))
        for value in payload.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
        return [payload]
    return []


def _record_contains_token(record, token):
    try:
        return token in json.dumps(record)
    except Exception:
        return False


def _get_record_id(record):
    id_keys = {k.lower() for k in vuln_scan_config.SIGNATURE_ID_QUERY_KEYS}
    id_keys.add("id")
    for key, value in record.items():
        if str(key).lower() in id_keys:
            return str(value)
    return None


def _classify_token_change(token, baseline_html, current_html):
    if token is None or token not in current_html:
        return None
    baseline_json = _try_load_json(baseline_html, log_error=False)
    current_json = _try_load_json(current_html, log_error=False)
    if baseline_json is None or current_json is None:
        return "INSERT"
    baseline_records = _extract_records(baseline_json)
    current_records = _extract_records(current_json)
    if not current_records:
        return "INSERT"
    baseline_ids = set()
    for record in baseline_records:
        record_id = _get_record_id(record)
        if record_id is not None:
            baseline_ids.add(record_id)
    for record in current_records:
        if not _record_contains_token(record, token):
            continue
        record_id = _get_record_id(record)
        if record_id is not None and record_id in baseline_ids:
            return "UPDATE"
        return "INSERT"
    return "INSERT"


def _extract_id_candidates_from_request(info):
    candidates = []
    id_keys = {k.lower() for k in vuln_scan_config.SIGNATURE_ID_QUERY_KEYS}
    url = info.get("req_url") or ""
    parsed = urlparse(url)
    for key, values in parse_qs(parsed.query).items():
        if key.lower() in id_keys:
            for value in values:
                candidates.append(str(value))
    path_segments = [seg for seg in parsed.path.split("/") if seg]
    for seg in path_segments:
        for regex in vuln_scan_config.SIGNATURE_ID_REGEX:
            if re.fullmatch(regex, seg):
                candidates.append(seg)
                break
    headers = info.get("headers") or {}
    post_params = info.get("post_params")
    if post_params:
        if headers.get(vuln_scan_config.CONTENT_TYPE_HEADER) in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
            params = parse_query_params(str(post_params))
            for key, values in params.items():
                if key.lower() in id_keys:
                    for value in values:
                        candidates.append(str(value))
        elif headers.get(vuln_scan_config.CONTENT_TYPE_HEADER) in vuln_scan_config.JSON_POST_DATA_TYPE:
            data = _try_load_json(post_params, log_error=False)
            if isinstance(data, dict):
                for key, value in data.items():
                    if key.lower() in id_keys:
                        candidates.append(str(value))
    return candidates


def _is_delete_by_id(baseline_html, current_html, candidates):
    if not candidates:
        return False
    if baseline_html is None:
        return False
    for candidate in candidates:
        if candidate and candidate in baseline_html and candidate not in current_html:
            return True
    return False


def _find_missing_token(token_map, target_node, html):
    token_list = token_map.get(target_node, [])
    missing = None
    for t in token_list:
        if t not in html:
            token_map[target_node].remove(t)
            missing = t
    return missing


def _record_dependence(node, target_node, target_info, token, operation, token_xpath, html,
                       data_dependence_dict, xpath_cluster, graph):
    operate = {operation: node}
    xpath_cluster.setdefault(token_xpath, []).append(operate)
    data_dependence_dict.setdefault(node, []).append(target_node)
    _DEP_DETECTED.setdefault(node, [])
    if target_node not in _DEP_DETECTED[node]:
        _DEP_DETECTED[node].append(target_node)
    _set_operation(graph, node, operation)
    store_html_in_es(target_node, html)


def _log_replay(node, token, insertable_fields, token_inserted, info, pre_get_params, pre_post_params,
                cookie_path, replay_response):
    _ensure_node_header(node)
    lines = [
        f"token={token}",
        f"insertable_fields={insertable_fields}",
        f"get_params(before)={pre_get_params}",
        f"post_params(before)={pre_post_params}",
        f"get_params(after)={info.get('get_params')}",
        f"post_params(after)={info.get('post_params')}",
        f"cookie_path={cookie_path}",
    ]
    if is_failure_response(replay_response, info.get("req_url")):
        lines.append("response=failed")
        _print_subblock("Replay request", lines)
        return
    _print_subblock("Replay request", lines, replay_response)


def _log_skip_auth(node, url):
    _ensure_node_header(node)
    _print_subblock("Skip auth node", [f"url={url}"])


async def get_html_response_and_dependencies(node, target_node, target_info, token, token_inserted, token_map,
                                             data_dependence_dict, xpath_cluster, token_xpaths, graph, op_info=None):
    """
    Handles the process of checking token dependencies and storing HTML responses in Elasticsearch.
    Args:
        node (str): The node name.
        target_node (str): The target node name.
        target_info (dict): The information of the target node.
        token (str): The token associated with the node.
        token_map (dict): A dictionary of nodes and their associated tokens.
        data_dependence_dict (dict): A dictionary that stores node dependencies.
        xpath_cluster (dict): A dictionary of operate and their associated tokens.
        token_xpaths (dict): A dictionary of xpath and their associated tokens.
    Returns:
        tuple: A boolean indicating if the target node was successfully processed,
               and an updated data_dependence_dict.
    """
    html = await get_html(target_info, None)
    baseline_html = await get_normal_response(target_info)
    if html is None:
        html = ""
    if baseline_html is None:
        baseline_html = ""
    operation = None
    if token_inserted and token is not None and str(token) in html:
        xpaths = get_xpath_for_token(token, html)
        token_xpaths.setdefault(token, []).extend(xpaths)
        operation = _classify_token_change(token, baseline_html, html) or "INSERT"
        _record_dependence(
            node,
            target_node,
            target_info,
            token,
            operation,
            token_xpaths[token][0],
            html,
            data_dependence_dict,
            xpath_cluster,
            graph,
        )
        return True, data_dependence_dict

    if not token_inserted:
        source_info = op_info if op_info is not None else graph.get(node, {})
        candidates = _extract_id_candidates_from_request(source_info)
        if _is_delete_by_id(baseline_html, html, candidates):
            operation = "DELETE"
            token_xpaths.setdefault(token, [token])
            _record_dependence(
                node,
                target_node,
                target_info,
                token,
                operation,
                token_xpaths[token][0],
                html,
                data_dependence_dict,
                xpath_cluster,
                graph,
            )
            return True, data_dependence_dict

    return False, data_dependence_dict


def store_html_in_es(target_node, html):
    """
    Stores the HTML response in Elasticsearch.
    Args:
        target_node (str): The target node ID.
        html (str): The HTML response to store.
    """
    es_client = ElasticsearchClient().get_client()
    es_doc = {"response": html}
    try:
        es_client.index(index="node_info", id=target_node, body=es_doc)
    except Exception as e:
        logging.error(f"Failed to index document in Elasticsearch: {e}")


async def process_node_dependencies(node, info, graph, token_map, data_dependence_dict,
                                    xpath_cluster, token_xpaths):
    """
    Process dependencies for a given node.
    Args:
        node (str): The node name.
        info (dict): The node's metadata.
        graph (dict): The graph of nodes.
        token_map (dict): A dictionary of nodes and their associated tokens.
        data_dependence_dict (dict): A dictionary that stores node dependencies.
        xpath_cluster (dict): A dictionary of operate and their associated tokens.
        token_xpaths (dict): A dictionary of xpath and their associated tokens.
    Returns:
        dict: Updated data_dependence_dict after processing the node dependencies.
    """
    if info["method"] in vuln_scan_config.OPERATE_METHOD_LIST:
        if _is_auth_like_request(info):
            _log_skip_auth(node, info.get("req_url"))
            _flush_detected_dependence(node)
            return data_dependence_dict
        op_info = _clone_request_info(info)
        pre_get_params = op_info.get("get_params")
        pre_post_params = op_info.get("post_params")
        op_info, token, insertable_fields, token_inserted = insert_str_token(op_info)

        # Get session info and make operation requests
        cookie_path = None
        replay_response = await get_html(op_info, cookie_path)
        _log_replay(node, token, insertable_fields, token_inserted, op_info, pre_get_params, pre_post_params,
                    cookie_path, replay_response)

        operation_override, override_info, skip_invalid, probe_info = await _classify_delete_or_update(
            node, info, cookie_path, replay_response, token, token_inserted
        )
        if probe_info:
            lines = [
                f"result={probe_info.get('result')}",
            ]
            replace_success = probe_info.get('replace_success')
            if replace_success is not None:
                lines.append(f"replace_success={replace_success}")
            if "token_inserted" in probe_info:
                lines.append(f"token_inserted={probe_info.get('token_inserted')}")
            response = probe_info.get('response') if replace_success else None
            _print_subblock("Operation probe", lines, response)
        if skip_invalid:
            _flush_detected_dependence(node)
            return data_dependence_dict
        if override_info is not None:
            if operation_override:
                _set_operation(graph, node, operation_override)
            op_info = override_info
            info["req_url"] = op_info.get("req_url")
            info["get_params"] = op_info.get("get_params")
            info["post_params"] = op_info.get("post_params")
            if op_info.get("method"):
                info["method"] = op_info.get("method")
            if probe_info and probe_info.get("insertable_fields"):
                insertable_fields = list(probe_info.get("insertable_fields"))
            if operation_override == "DELETE":
                token = None
                insertable_fields = []
                token_inserted = False
            elif probe_info and "token_inserted" in probe_info:
                token_inserted = bool(probe_info.get("token_inserted"))
                if not token_inserted:
                    token = None
                    insertable_fields = []

        # Sort the graph by score
        sorted_graph = await sort_by_score(node, op_info, graph)
        # sorted_graph = graph
        for target_node in sorted_graph.keys():
            target_info = graph[target_node]

            if target_info["method"] == "GET" and target_node != node:
                # Process target node dependencies
                success, data_dependence_dict = await get_html_response_and_dependencies(
                    node, target_node, target_info, token, token_inserted, token_map, data_dependence_dict,
                    xpath_cluster, token_xpaths, graph, op_info=op_info
                )
                if success:
                    continue

    _flush_detected_dependence(node)
    return data_dependence_dict


async def build_dependence(graph):
    """
    Builds data dependency relationships between nodes in a graph.
    Args:
        graph (dict): A dictionary representing the graph, where keys are node names
                      and values are dictionaries containing node metadata.

    Raises:
        Exception: Logs and raises an error if indexing into Elasticsearch fails.
    Returns:
        None
    """
    global _DEP_LOGGED_NODES
    _DEP_LOGGED_NODES = set()
    xpath_cluster = {}
    data_dependence_dict = {}
    token_xpaths = {}
    token_map = {}
    _reset_operations(graph)

    for node, info in graph.items():
        data_dependence_dict = await process_node_dependencies(node, info, graph, token_map, data_dependence_dict,
                                                               xpath_cluster, token_xpaths)

    with open(vuln_scan_config.DATA_DEPENDENCE_PATH, "w") as f:
        json.dump(data_dependence_dict, f, indent=4)

    with open(vuln_scan_config.XPATH_CLUSTER_PATH, "w") as f:
        json.dump(xpath_cluster, f, indent=4)

    with open(vuln_scan_config.MERGE_NAVIGRAPH_PATH, "w") as f:
        json.dump(graph, f, indent=4)
