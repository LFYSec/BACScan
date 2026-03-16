#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   utils.py
@Time    :   2024/07/17 14:56:36
@Author  :   LFY
'''

# here put the import lib

import base64
import hashlib
import json
import logging
import os
import re
import string
import random
from html import unescape
from typing import Union, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlsplit, urljoin, urlunparse, urlunsplit
from config.crawl_config import *
import asyncio
from functools import wraps
from playwright.async_api import Locator
from vuln_detection.utils.es_util import ElasticsearchClient
from config import *


def gen_random_str(length):
    return ''.join(random.sample(string.ascii_letters + string.digits, length))


def format_url(url: str, main_url: str) -> Optional[str]:
    __split = urlsplit(main_url)
    url = url.strip()
    if any(x in url.lower() for x in CONTENT_TYPE):
        return None
    if url == "/":
        return None
    if url.startswith("undefined") or url.startswith("null"):
        return None
    if url.startswith("http"):
        path = urlsplit(url).path.strip("/")
        if path == "undefined" or path == "null" or path.startswith("undefined/") or path.startswith("null/"):
            return None
        formated_url = url
    elif url.startswith("./") or url.startswith("/") or url.startswith("#"):
        formated_url = urljoin(main_url, url)
    elif url.startswith("?"):
        formated_url = urlunsplit((__split.scheme, __split.netloc, __split.path, url[1:], __split.fragment))
    else:
        formated_url = urljoin(__split.scheme + "://" + __split.netloc + __split.path, url)
    while any(x in formated_url for x in ("&amp;", "&lt;", "&gt;", "&#39;", "&quot;")):
        formated_url = unescape(formated_url)

    try:
        urlsplit(formated_url)
    except Exception as e:
        logging.error(e)
        return

    return formated_url.rstrip("\\").rstrip("#")


def is_same_host(main_frame: str, req_url: str):
    p1 = urlsplit(main_frame)
    p2 = urlsplit(req_url)
    if p1.netloc.strip(":80").strip(":443") != p2.netloc.strip(":80").strip(":443"):
        return False
    return True


def is_same_host_without_port(main_frame: str, req_url: str):
    p1 = urlsplit(main_frame)
    p2 = urlsplit(req_url)
    if p1.netloc.split(":")[0] != p2.netloc.split(":")[0]:
        return False
    return True


def is_same_url(main_frame: str, req_url: str) -> bool:
    p1 = urlsplit(main_frame)
    p2 = urlsplit(req_url)
    if p1.scheme != p2.scheme:
        return False
    if p1.netloc.strip(":80").strip(":443") != p2.netloc.strip(":80").strip(":443"):
        return False
    if p1.path.strip("/") != p2.path.strip("/"):
        return False
    if p1.query != p2.query:
        return False
    return True


def is_same_url_with_fragment(main_frame: str, req_url: str) -> bool:
    if not is_same_url(main_frame, req_url):
        return False
    p1 = urlsplit(main_frame)
    p2 = urlsplit(req_url)
    if p1.fragment != p2.fragment:
        return False
    return True


def is_ignored_by_keywords(url: str) -> bool:
    if any(x in url.lower() for x in crawler_config.URL_BLACKLIST_WORDS):
        logging.debug(f"[+] Ignore request: {url}")
        return True
    path = urlparse(url).path
    pattern = re.compile(r'/([^/_-]{20,})')
    if pattern.search(path):
        logging.debug(f"[+] Ignore request: {url}")
        return True
    return False


def get_minimal_img():
    return base64.b64decode("R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=")


def get_md5_str(param: str):
    md5 = hashlib.md5()
    md5.update(param.encode('utf-8'))
    return md5.hexdigest()


def form_value_parser(value: Union[str, List]):
    if isinstance(value, str):
        pair = value.split("=")
        config.CUSTOM_FORM_KEYWORD[pair[0]] = pair[1]
    elif isinstance(value, list):
        for v in value:
            form_value_parser(v)


def ignore_parser(value: Union[str, List]):
    for v in value:
        config.URL_BLACKLIST_WORDS.add(v)
        if v.lower() not in crawler_config.DANGEROUS_ELEMENT_KEYWORDS:
            crawler_config.DANGEROUS_ELEMENT_KEYWORDS.append(v.lower())


async def is_dangerous_element(locator: Locator) -> bool:
    try:
        text = (await locator.inner_text()).strip().lower()
        for keyword in crawler_config.DANGEROUS_ELEMENT_KEYWORDS:
            if keyword in text:
                logging.debug(f"[+] Skipping dangerous element: '{text}'")
                return True
    except Exception:
        pass
    return False


def init_logging(log_level: str):
    if log_level == "debug":
        level = logging.DEBUG
    else:
        level = logging.INFO
    log_dir = "./logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    logging.basicConfig(level=level,
                        format="%(asctime)s %(levelname)-5s %(filename)-14s:%(lineno)-4s - %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S",
                        filename=f'{log_dir}/run.log',
                        filemode='w')
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(levelname)-5s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)


class Singleton(object):
    def __init__(self, cls):
        self._cls = cls
        self._instance = {}

    def __call__(self, *args, **kwargs):
        if self._cls not in self._instance:
            self._instance[self._cls] = self._cls(*args, **kwargs)
        return self._instance[self._cls]


def check_error_request(req):
    response_markers = [
        "invalid token",
        "jwt token required!",
        "<title>404",
        "\"status\":404",
        "\"code\":404",
        "\"status\":500",
        "\"code\":500",
    ]
    url_markers = [
        "plugin-install",
        "wp-includes",
        "conf",
        "del",
        "remove",
        "http://10.176.36.21:5230/auth",
    ]

    url = getattr(req, "url", "") or ""
    if any(marker in url.lower() for marker in url_markers):
        return True

    response = getattr(req, "response", None)
    if response:
        if isinstance(response, (list, tuple)):
            response_text = " ".join(str(item) for item in response)
        else:
            response_text = str(response)
        response_lower = response_text.lower()
        if any(marker in response_lower for marker in response_markers):
            return True

    return False


def timeout(seconds, error_message="Function call timed out"):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # 创建一个任务来运行原始的异步函数
            task = asyncio.create_task(func(*args, **kwargs))
            # 等待任务完成或者超时
            try:
                return await asyncio.wait_for(task, seconds)
            except asyncio.TimeoutError:
                raise TimeoutError(error_message)

        return wrapper

    return decorator


def replace_query_values_with_param(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for key, value in query_params.items():
        query_params[key] = ['PARAM']

    new_query_string = urlencode(query_params, doseq=True)

    new_url = parsed_url._replace(query=new_query_string)
    return urlunparse(new_url)


def normalization_url(url):
    parsed_url = urlparse(url)
    new_url = re.sub(r'\d+', 'INT', parsed_url.path)
    new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{new_url}"
    return new_url


async def get_html(info, cookie_path):
    html = ""
    try:
        conf.config.COOKIE_PATH = cookie_path
        crawler = await Crawler.create()

        url = info["req_url"]

        req = Request(url, base_url=url)
        req.method = info["method"]
        # req.headers = headers_dict
        encoded_data = {k: v[0] if v else '' for k, v in info["post_params"].items()}
        req.post_data = urlencode(encoded_data)
        html = await crawler.get_content(req)
        await crawler.browser_handler.safe_close_browser()

    except Exception as e:
        print(e)
        logging.error(f"[-] Failed to get html content for {url}")
        return ""
    return html


async def get_normal_response(target):
    es = ElasticsearchClient().get_client()
    es_data = es.get(index="node_info", id=target["es_id"])
    normal_html = es_data["_source"]["response"]
    return normal_html


async def should_abort(request):
    response = await request.response()
    status = response.status
    print(status)
    error_status_codes = [404, 304]
    return status in error_status_codes


def parse_http_request_to_dict(request_text, role="visitor"):
    global host
    lines = request_text.strip().split('\n')

    request_line = lines[0].split()
    method = request_line[0]
    request_path = request_line[1]
    http_version = request_line[2]

    headers = {}
    for line in lines[1:]:
        if ':' in line:
            header_key, header_value = line.split(':', 1)
            header_key = header_key.strip()
            header_value = header_value.strip()
            if header_key.lower() == 'host':
                host = header_value
                break
        else:
            break

    # query_string = ''
    # if '?' in request_path:
    #     request_path, query_string = request_path.split('?', 1)

    url = f"http://{host}{request_path}"

    parsed_url = urlparse(url)
    get_params = str(parsed_url.query)
    role_text = str(role or vuln_scan_config.VISITOR).strip().lower()
    signature = f"{role_text.upper()}|{method.upper()}|{url}"
    request_dict = {
        "req_url": url,
        "method": method.upper(),
        "headers": headers,
        "get_params": get_params,
        "post_params": "None",
        "edges": [],
        "role": role_text,
        "public": role_text == vuln_scan_config.VISITOR,
        "es_id": signature,
        "signature": signature,
        "operation": "SELECT",
    }

    # 解析剩余的请求头
    for line in lines[1:]:
        if line.strip() == "":
            break
        header_key, header_value = line.split(':', 1)
        # if header_key.lower() in ["user-agent"]:
        #     continue
        headers[header_key.strip().lower()] = header_value.strip()

    if method.upper() in ['POST', "PATCH"]:
        content_type = headers.get('content-type', '')
        if content_type:
            post_data_lines = lines[lines.index("") + 1:][0]
            request_dict["post_params"] = post_data_lines if post_data_lines else "None"

    return url, request_dict


def insert_graph_node(navi_graph_path, request_text, response_text, role):
    es = ElasticsearchClient().get_client()
    # 存节点
    navi_graph_dict = json.loads(open(navi_graph_path).read())
    node, node_info = parse_http_request_to_dict(request_text, role)
    node = normalization_url(node)

    i = 0
    while node + "_" + str(i) in navi_graph_dict:
        i += 1
    node = node + "_" + str(i)
    navi_graph_dict[node] = node_info
    # 存响应
    doc = {
        'response': response_text
    }
    try:
        node_info["es_id"] = node
        es.index(index="node_info", id=node, body=doc)
    except Exception as e:
        logging.error(f"[-] ES error: {repr(e)}")

    with open(navi_graph_path, 'w') as f:
        json.dump(navi_graph_dict, f, indent=4)


def init_post_data(req):
    if req.post_data is None:
        return None
    headers = req.headers or {}
    content_type = ""
    for k, v in headers.items():
        if str(k).lower() == "content-type":
            content_type = str(v)
            break
    if any(content_type.startswith(ct) for ct in vuln_scan_config.URLENCODED_POST_DATA_TYPE):
        return str(req.post_data)
    if any(content_type.startswith(ct) for ct in vuln_scan_config.JSON_POST_DATA_TYPE):
        if isinstance(req.post_data, (bytes, bytearray)):
            return req.post_data
        if isinstance(req.post_data, str):
            return req.post_data
        try:
            return json.dumps(req.post_data)
        except Exception:
            return str(req.post_data)
    return req.post_data
