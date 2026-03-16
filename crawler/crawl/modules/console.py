#!/user/bin/env python
"""
@Time   : 2022-02-24 15:24
@Author : LFY
@File   : console_handler.py
"""

# here put the import lib

import playwright.async_api

from crawler.models.request import Request


async def console_handler(
    console: playwright.async_api.ConsoleMessage, page: playwright.async_api.Page, collected_urls: set[Request]
):
    """
    Deal with console message for JS-Python communication

    :param page:
    :param console: console output messages
    :param collected_urls:
    :return:
    """
    recv_navigation_msg = "getNavigationUrl:"
    if console.text.startswith(recv_navigation_msg):
        url = console.text.split(recv_navigation_msg)[1]
        if url:
            collected_urls.add(Request(url, from_url=page.url))
