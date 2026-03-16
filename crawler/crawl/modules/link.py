#!/user/bin/env python
"""
@Time   : 2022-02-25 17:04
@Author : LFY
@File   : response.py
"""

# here put the import lib
import logging
import re

import playwright.async_api

from config.crawl_config import crawler_config
from crawler.browser.js.js_crawlergo import GetCommentByXpath
from crawler.browser.page import PageHandler
from crawler.crawl.modules.route import get_request_object
from crawler.models.nav_graph import NavigationGraph
from crawler.models.request import Request


async def vuln_response_handler(response):
    url = response.url
    status = response.status
    headers = response.headers
    body = await response.text()

    print(f"URL: {url}")
    print(f"Status: {status}")
    print(f"Headers: {headers}")
    print(f"Body: {body}")


async def response_handler(
    response: playwright.async_api.Response,
    page: playwright.async_api.Page,
    collected_urls: set[Request],
    navgraph: NavigationGraph,
    base_url,
    browser_context,
):
    """
    Parse URLs from js/html response

    :param response:
    :param page:
    :param collected_urls:
    :return:
    """
    try:
        response_text = await response.text()
    except Exception as e:
        logging.debug(f"[-] Get response error at {page.url} for {response.request.url}: {repr(e)}")
        return
    request = response.request
    req = get_request_object(request, base_url, redirect_flag=False)
    req.from_url = base_url

    if response.status >= 300 and response.status <= 600:
        return
    # 根据需要选择是否注释
    # if not Filter().do_filter(req) and all(key not in response.url for key in ["wordpress"]):
    #     # new page
    #     try:
    #         page = await PageHandler(browser_context).get_new_page()
    #         await page.set_content(response_text)
    #         req.response = await page.content()
    #         navgraph.add_link(req)
    #     except Exception as e:
    #         print(f"{response.url}: {repr(e)}")

    content_type = await response.header_value("content-type")
    if content_type is None:
        return

    if navgraph is not None:
        if "text/html" in content_type or "application/json" in content_type:
            req.response = response_text
            navgraph.add_page(req)

    if "application/javascript" in content_type or "text/html" in content_type or "application/json" in content_type:
        all_suspect_url = re.findall(crawler_config.URL_REGEX, response_text)
        for u in all_suspect_url:
            url = u[0]
            collected_urls.add(Request(url, from_url=page.url))


async def collect_href_links(page: playwright.async_api.Page, collected_urls: set[Request]):
    attrs = ["src", "href", "data-url", "data-href"]
    for attr in attrs:
        css_selector = "[" + attr + "]"
        nodes = await PageHandler.safe_locator_get_all(page, css_selector)
        for n in nodes:
            try:
                url = await n.get_attribute(attr)
                collected_urls.add(Request(url, from_url=page.url))
            except Exception as e:
                logging.debug(f"[-] Get href error at {page.url}: {repr(e)}")


async def collect_obj_links(page: playwright.async_api.Page, collected_urls: set[Request]):
    css_selector = "object[data]"
    nodes = await PageHandler.safe_locator_get_all(page, css_selector)
    for n in nodes:
        try:
            url = await PageHandler.safe_get_attribute(n, "data")
            collected_urls.add(Request(url, from_url=page.url))
        except Exception as e:
            logging.debug(f"[-] Get obj_link error at {page.url}: {repr(e)}")


async def collect_comment_links(page: playwright.async_api.Page, collected_urls: set[Request]):
    comments = await PageHandler.safe_evaluate(page, GetCommentByXpath)
    if comments is not None and comments != "":
        try:
            comment_urls = re.findall(crawler_config.URL_REGEX, comments)
        except Exception as e:
            logging.debug(f"[-] Get comment_link error at {page.url}: {repr(e)}")
            return
        for u in comment_urls:
            collected_urls.add(Request(u[0], from_url=page.url))


# async def click_all_buttons(page: playwright.async_api.Page):
#     url = page.url
#     urllist = [
#         "http://10.176.36.21:8888/shop",
#         "http://10.176.36.21:8888/dashboard",
#         # "http://10.176.36.21:8888/forum",
#     ]
#     if url not in urllist:
#         return
#     buttons = await page.query_selector_all('button')
#     for button in buttons:
#         try:
#             await button.click()
#             await page.wait_for_navigation(timeout=3000)
#             await page.go_back()
#         except Exception as e:
#             try:
#                 await page.wait_for_selector('div[role="document"].ant-modal', timeout=3000)
#                 close_button = await page.query_selector('button.ant-modal-close')
#                 if close_button:
#                     await close_button.click()
#             except Exception as e:
#                 continue
