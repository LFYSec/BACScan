#!/user/bin/env python
"""
@Time   : 2022-01-23 15:25
@Author : LFY
@File   : page.py
"""

# here put the import lib
import logging
from typing import Any

import playwright.async_api


class PageHandler:
    def __init__(self, context):
        self.context = context

    async def get_new_page(self) -> playwright.async_api.Page:
        """
        Init a page for crawler.

        :return:
        """
        return await self.context.new_page()

    @staticmethod
    async def safe_evaluate(page: playwright.async_api.Page, stmts: str, param: Any = None):
        """
        Eval js in current page

        :param stmts:
        :param page:
        :param param:
        :return:
        """
        try:
            return await page.evaluate(stmts, param)
        except Exception as e:
            logging.debug(f"[-] Error at safe_evaluate: {repr(e)}")

    @staticmethod
    async def safe_locator_evaluate_all(located: playwright.async_api.Locator, stmts: str, param: Any = None) -> list:
        """
        Eval js in all selected elements

        :param located:
        :param stmts:
        :param param:
        :return:
        """
        result = []
        count = await located.count()
        for i in range(count):
            try:
                current_element = located.nth(i)
                evaluate_result = await PageHandler.safe_locator_evaluate(current_element, stmts, param)
                result.append(evaluate_result)
            except Exception as e:
                logging.debug(f"[-] Error at safe_locator_evaluate_all: {repr(e)}")
        return result

    @staticmethod
    async def safe_locator_evaluate(located: playwright.async_api.Locator, stmts: str, param: Any = None):
        """
        Eval js in a single selected element

        :param located:
        :param stmts:
        :param param:
        :return:
        """
        try:
            return await located.evaluate(stmts, param)
        except Exception as e:
            logging.debug(f"[-] Error at safe_locator_evaluate: {repr(e)}")

    @staticmethod
    def safe_locator(page: playwright.async_api.Page, css_selector: str) -> playwright.async_api.Locator | None:
        """
        Find elements which match css_selector

        :param page: page object
        :param css_selector: the css selector to select elements
        :return:
        """
        try:
            return page.locator(css_selector)
        except Exception as e:
            logging.debug(f"[-] Error at safe_locator: {repr(e)}")

    @staticmethod
    async def safe_fill(located: playwright.async_api.Locator, input_value: str):
        """
        Fill the located input

        :param located:
        :param input_value:
        :return:
        """
        try:
            await located.fill(input_value, force=True, no_wait_after=True)
        except Exception as e:
            logging.debug(f"[-] Error at safe_fill: {repr(e)}")

    @staticmethod
    async def safe_check(located: playwright.async_api.Locator):
        """
        Fill the located input

        :param located:
        :return:
        """
        try:
            await located.check(force=True)
        except Exception as e:
            logging.debug(f"[-] Error at safe_check: {repr(e)}")

    @staticmethod
    async def safe_locator_get_all(
        page: playwright.async_api.Page, css_selector: str
    ) -> list[playwright.async_api.Locator]:
        """
        Eval js in all selected elements

        :param css_selector:
        :param page:
        :return:
        """
        result = []
        located = PageHandler.safe_locator(page, css_selector)
        try:
            count = await located.count()
            for i in range(count):
                current_element = located.nth(i)
                result.append(current_element)
        except Exception as e:
            logging.debug(f"[-] Error at safe_locator_get_all: {repr(e)}")
        return result

    @staticmethod
    async def safe_locator_inner_get_all(
        locator: playwright.async_api.Locator, css_selector: str
    ) -> list[playwright.async_api.Locator]:
        """
        Eval js in all selected elements

        :param locator:
        :param css_selector:
        :return:
        """
        result = []
        located = PageHandler.safe_inner_locator(locator, css_selector)
        try:
            count = await located.count()
            for i in range(count):
                current_element = located.nth(i)
                result.append(current_element)
        except Exception as e:
            logging.debug(f"[-] Error at safe_locator_get_all: {repr(e)}")
        return result

    @staticmethod
    def safe_inner_locator(
        locator: playwright.async_api.Locator, css_selector: str
    ) -> playwright.async_api.Locator | None:
        """
        Find elements which match css_selector

        :param locator: located object
        :param css_selector: the css selector to select elements
        :return:
        """
        try:
            return locator.locator(css_selector)
        except Exception as e:
            logging.debug(f"[-] Error at safe_locator: {repr(e)}")

    @staticmethod
    async def safe_get_attribute(located: playwright.async_api.Locator, attr: str) -> str:
        value = None
        try:
            value = await located.get_attribute(attr)
        except Exception as e:
            logging.debug(f"[-] Error at safe_get_attribute: {repr(e)}")
        return "" if value is None else value

    @staticmethod
    async def safe_goto(page: playwright.async_api.Page, url: str) -> bool:
        try:
            await page.goto(url, timeout=30 * 1000)
            return True
        except Exception as e:
            if isinstance(e, playwright.async_api.TimeoutError):
                logging.error(f"[-] Error at page.goto {page.url}: timeout, continue")
                return True
            else:
                logging.error(f"[-] Error at page.goto: {repr(e)}")
            await page.close()
        return False

    @staticmethod
    async def safe_close(page: playwright.async_api.Page) -> bool:
        try:
            await page.close()
            return True
        except Exception as e:
            logging.error(f"[-] Error at page.close {page.url}: {repr(e)}")
            return False
