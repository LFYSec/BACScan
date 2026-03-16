#!/user/bin/env python
"""
@Time   : 2022-02-24 11:12
@Author : LFY
@File   : route_handler.py
"""

# here put the import lib
import json
import logging
from urllib.parse import parse_qs, urljoin, urlparse

import playwright.async_api

from config.crawl_config import *
from crawler.models.nav_graph import NavigationGraph
from crawler.models.request import Request
from crawler.models.url import URL
from crawler.utils import *

_METHOD_OVERRIDE_KEYS = {"_method"}
_METHOD_OVERRIDE_HEADERS = {"x-http-method-override", "x-http-method", "x-method-override"}
_SUPPORTED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "FETCH", "TRACE"}


def _should_continue_duplicate_runtime_request(
    request: playwright.async_api.Request,
    req_obj: Request,
) -> bool:
    method = (req_obj.method or request.method or "").upper()
    return not request.is_navigation_request() and method == "GET" and request.resource_type in {"xhr", "fetch"}


def _get_method_override(method: str, headers, post_data, url: str) -> str:
    if not method:
        return method
    if not headers and not post_data and not url:
        return method

    override = None
    if isinstance(headers, dict):
        for k, v in headers.items():
            if k.lower() in _METHOD_OVERRIDE_HEADERS:
                override = v
                break

    if override is None and url:
        try:
            query_params = parse_qs(urlparse(url).query, keep_blank_values=True)
        except Exception:
            query_params = {}
        for key in _METHOD_OVERRIDE_KEYS:
            if key in query_params:
                values = query_params.get(key)
                if values:
                    override = values[0]
                break

    if override is None and post_data:
        try:
            if isinstance(post_data, (bytes, bytearray)):
                body = post_data.decode(errors="ignore")
            else:
                body = str(post_data)
        except Exception:
            body = ""

        if body:
            content_type = ""
            if isinstance(headers, dict):
                for k, v in headers.items():
                    if k.lower() == "content-type":
                        content_type = v
                        break
            if "application/json" in content_type:
                try:
                    data = json.loads(body)
                except Exception:
                    data = None
                if isinstance(data, dict):
                    for key in _METHOD_OVERRIDE_KEYS:
                        if key in data:
                            override = data.get(key)
                            break
            else:
                params = parse_qs(body, keep_blank_values=True)
                for key in _METHOD_OVERRIDE_KEYS:
                    if key in params:
                        values = params.get(key)
                        if values:
                            override = values[0]
                        break

    if override:
        override = str(override).strip().upper()
        if override in _SUPPORTED_METHODS:
            return override
    return method


async def vuln_route_handler(route: playwright.async_api.Route, main_req: Request):

    await route.continue_(
        method=main_req.method.upper(),
        headers=main_req.headers,
        post_data=bytes(main_req.post_data, "utf-8") if main_req.post_data else None,
    )
    req = route.request
    print(type(main_req.headers))
    logging.debug(f"Request continued with main request info: {main_req.url}")


async def route_handler(
    route: playwright.async_api.Route, main_req: Request, collected_urls: set[Request], navgraph: NavigationGraph = None
):
    """
    Deal with every request

    1. backend 302 - with content
        - request target and add Request object to filter with response

    2. backend 302 - without content
        - request target and add Request object to filter without response

    3. frontend navigation
        - return 204 and add navigation's Request object to filter

    :param main_req: main_frame req
    :param route: interceptor
    :param collected_urls: collected_urls
    :return:
    """
    # 对不同host的请求直接abort
    request = route.request
    if not is_same_host_without_port(main_req.url, request.url):
        logging.debug(f"[+] Abort by host rule: {request.url}")
        if request.is_navigation_request():
            await route.fulfill(status=204)
        else:
            await route.abort()
        return
    # 对url中包含一下关键的请求abort
    if check_error_request(request):
        logging.debug(f"[+] Abort by url'key: {request.url}")
        await route.abort()
        return

    # TODO
    #  https://github.com/microsoft/playwright/issues/9648
    #  chromium can not identify the post_data of multipart/form-data
    original_method = request.method.upper() if request.method else request.method
    req_obj = get_request_object(request, main_req.url, main_req.redirect_flag)
    if req_obj.url is None:
        await route.abort()
        return
    if req_obj.url != main_req.url:
        req_obj.from_url = main_req.url

    seq_display = "-"
    if getattr(main_req, "seq", None) is not None:
        seq_display = main_req.seq
    seq_prefix = "[#%s] " % seq_display

    req_label = f"{req_obj.method} {req_obj.url}"
    if navgraph is not None:
        try:
            req_label = navgraph.get_signature(req_obj)
        except Exception:
            req_label = req_label
    if req_obj.method:
        mapped_method = req_obj.method.upper()
        if original_method and mapped_method != original_method:
            logging.info(f"[+] Method override: {original_method} -> {mapped_method} {req_label}")

    # 忽略黑名单关键字请求
    if is_ignored_by_keywords(req_obj.url) and request.resource_type not in crawler_config.RESOURCE_SKIP_TYPES:
        logging.debug(f"[+] Abort by ignore rule: {request.url}")
        await route.abort()
        return

    # 处理所有静态资源请求
    if await resource_handler(route, req_obj):
        logging.debug(f"[+] Abort by media rule: {req_obj.url}")
        return

    if navgraph is not None:
        if request.resource_type not in crawler_config.RESOURCE_SKIP_TYPES:
            ext = URL(req_obj.url).file_ext()
            if ext not in crawler_config.RESOURCE_SKIP_EXTS:
                is_main_doc = request.resource_type == "document" and request.frame.parent_frame is None
                navgraph.record_param_variant(req_obj)
                should_execute = True
                if not is_main_doc:
                    should_execute = navgraph.should_execute_request(req_obj)
                if not should_execute:
                    logging.info(f"[+] Param collect {req_label}")
                    if _should_continue_duplicate_runtime_request(request, req_obj):
                        logging.debug(f"[+] Allow duplicate runtime request: {req_label}")
                        await route.continue_()
                        return
                    await route.fulfill(status=204)
                    return
                if req_obj.method and req_obj.method.upper() != "GET":
                    logging.info(f"[+] Intercepted {req_label}")
                navgraph.add_link(req_obj)

    # TODO HandleHostBinding()

    # 处理前后端跳转请求
    if request.is_navigation_request():
        if (
            request.resource_type == "document"
            and request.frame.parent_frame is None
            and is_same_url_with_fragment(main_req.url, req_obj.url)
        ):
            await main_frame_handler(route, main_req)
            return
        elif request.method == RequestMethod.POST.value and request.frame.parent_frame is not None:
            collected_urls.add(req_obj)
            await route.continue_()
            return
        else:
            logging.debug(
                f"[+] Frontend navigate:{req_obj.url} {req_obj.method} main_frame:{main_req.url} resource:{request.resource_type}"
            )
            collected_urls.add(req_obj)
            await route.fulfill(status=204)
            return

    # 默认continue_发出请求
    logging.debug(f"[+] Continue_: {req_obj.url} resource:{request.resource_type}")
    collected_urls.add(req_obj)
    await route.continue_()


async def main_frame_handler(route: playwright.async_api.Route, main_req: Request):
    if main_req.redirect_flag is True:
        response = main_req.request()
        await route.fulfill(
            status=200,
            body=response,
        )
    elif route.request.method.upper() == RequestMethod.GET.value and main_req.method.upper() != RequestMethod.GET.value:
        await route.continue_(method=main_req.method.upper(), headers=main_req.headers, post_data=main_req.post_data)
    else:
        await route.continue_()


def get_request_object(request: playwright.async_api.Request, base_url: str, redirect_flag: bool = False) -> Request:
    """
    Assemble the request object by main_req and current request.
    If current request is main frame navigation, we should add main_req's data into req_obj

    :param redirect_flag:
    :param request:
    :param base_url:
    :return:
    """
    post_data = None
    if request.post_data_buffer is not None:
        post_data = request.post_data_buffer
    elif post_data is not None:
        post_data = request.post_data
    url = format_url(request.url, base_url)
    main_url = urlparse(base_url)
    if is_same_url(url, base_url) and main_url.fragment != "":
        logging.debug(f"[+] Combine with #: url {url} main_url {base_url}")
        url = urljoin(url, "#" + main_url.fragment)
    method = _get_method_override(request.method, request.headers, post_data, request.url)
    return Request(
        url, method=method, headers=request.headers, post_data=post_data, redirect_flag=redirect_flag, base_url=base_url
    )


async def resource_handler(route: playwright.async_api.Route, req_obj: Request) -> bool:
    """
    Intercept all resource request

    :param route:
    :param req_obj:
    :return:
    """
    if route.request.resource_type == "image":
        await route.fulfill(status=200, content_type="image/png", body=get_minimal_img())
        return True
    if URL(req_obj.url).file_ext().endswith(tuple(STATIC_SUFFIX)) or route.request.resource_type == "media":
        await route.abort()
        return True
    return False


async def request_handler(request: playwright.async_api.Request, collected_urls: set):
    """
    For backend navigation

    :param request:
    :param collected_urls:
    :return:
    """
    # if any(f in request.url for f in config.FORBIDDEN_URL):
    #     return

    if request.redirected_from is not None:
        req_obj = get_request_object(request.redirected_from, request.redirected_from.url, redirect_flag=True)
        if req_obj.url is not None:
            collected_urls.add(req_obj)
        nav_req_repeat = get_request_object(request, request.url)
        if nav_req_repeat.url is not None:
            collected_urls.add(nav_req_repeat)
