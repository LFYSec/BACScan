#!/user/bin/env python
"""
@Time   : 2022-02-24 15:41
@Author : LFY
@File   : fill_handler.py
"""

# here put the import lib
import logging
import re

import playwright.async_api

from config.crawl_config import InputTextMap, crawler_config
from crawler.browser.js.js_crawlergo import *
from crawler.browser.page import PageHandler
from crawler.utils import gen_random_str, get_minimal_img, is_dangerous_element


async def fill_handler(css_locator: list | str, page: playwright.async_api.Page):
    if isinstance(css_locator, list):
        for i in css_locator:
            await fill_handler(i, page)
    if isinstance(css_locator, str):
        located_elems = await PageHandler.safe_locator_get_all(page, css_locator)
        for e in located_elems:
            try:
                current_tagname = await PageHandler.safe_locator_evaluate(e, "node => node.tagName")
                await fill_element(e, current_tagname.upper())
            except Exception as e:
                logging.debug(f"[-] Fill form on {page.url} failed: {repr(e)}")


def _action_blacklist_rules() -> dict:
    return {
        "words": [w.lower() for w in crawler_config.ACTION_BLACKLIST_WORDS if w],
        "regex": list(crawler_config.ACTION_BLACKLIST_REGEX),
        "attrs": list(crawler_config.ACTION_BLACKLIST_ATTRS),
    }


async def _is_blacklisted_element(located: playwright.async_api.Locator, rules: dict) -> bool:
    words = rules.get("words", []) if rules else []
    regex_list = rules.get("regex", []) if rules else []
    if not words and not regex_list:
        return False
    try:
        outer = await PageHandler.safe_locator_evaluate(located, "node => node.outerHTML || ''")
    except Exception:
        outer = ""
    if not outer:
        try:
            outer = await PageHandler.safe_locator_evaluate(located, "node => node.textContent || ''")
        except Exception:
            outer = ""
    hay = outer.lower()
    if any(kw in hay for kw in words if kw):
        return True
    for pattern in regex_list:
        try:
            if re.search(pattern, hay, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


async def fill_element(located: playwright.async_api.Locator, tag_name: str):
    if tag_name == "INPUT":
        if (await PageHandler.safe_get_attribute(located, "role")).lower() == "combobox":
            try:
                await located.click()
                options = await PageHandler.safe_locator_get_all(
                    located.page, "[role='option'], .ant-select-item-option, li[role='option']"
                )
                for option in options:
                    if (await PageHandler.safe_get_attribute(option, "aria-disabled")).lower() == "true":
                        continue
                    text = (
                        await PageHandler.safe_locator_evaluate(option, "node => node.textContent || ''") or ""
                    ).strip()
                    if not text:
                        continue
                    await option.click()
                    break
            except Exception as e:
                logging.debug(f"[-] Error at combobox fill: {repr(e)}")

        attr_type = (await PageHandler.safe_get_attribute(located, "type")).lower()
        if attr_type == "text" or attr_type == "" or attr_type == "number":
            input_name = (
                await PageHandler.safe_get_attribute(located, "id")
                + await PageHandler.safe_get_attribute(located, "placeholder")
                + await PageHandler.safe_get_attribute(located, "class")
                + await PageHandler.safe_get_attribute(located, "name")
            )
            input_value = get_match_input_value(input_name)
            await PageHandler.safe_fill(located, input_value)
            inputed = await located.input_value()
            if inputed != input_value:
                await PageHandler.safe_locator_evaluate(located, SetNodeAttr, {"attr": "value", "value": input_value})
        elif attr_type in ["email", "password", "tel"]:
            input_value = get_match_input_value(attr_type)
            await PageHandler.safe_fill(located, input_value)
        elif attr_type in ["radio", "checkbox"]:
            await PageHandler.safe_check(located)
        elif attr_type in ["file", "image"]:
            await located.set_input_files(
                files=[{"name": "upload.png", "mimeType": "image/png", "buffer": get_minimal_img()}]
            )
    elif tag_name == "TEXTAREA":
        # TODO select by name/id/class
        input_value = get_match_input_value("default")
        await PageHandler.safe_fill(located, input_value)
    elif tag_name == "OPTION":
        await PageHandler.safe_locator_evaluate(located, SetNodeAttr, {"attr": "selected", "value": "selected"})


async def form_submit(page: playwright.async_api.Page):
    located_forms = await set_form_target(page)
    if located_forms is not None:
        await try_raw_submit(located_forms)
    await try_click_submit(page)
    await try_button_submit(page)


async def set_form_target(page: playwright.async_api.Page) -> playwright.async_api.Locator | None:
    located_forms = None
    try:
        # make all forms' target point to a hidden frame
        random_id = gen_random_str(8)
        await PageHandler.safe_evaluate(page, NewFrameTemplate % (random_id, random_id))
        located_forms = PageHandler.safe_locator(page, "form")
        await PageHandler.safe_locator_evaluate_all(located_forms, SetNodeAttr, {"attr": "target", "value": random_id})
    except Exception as e:
        logging.debug(f"[-] Error at set form target: {repr(e)}")
    return located_forms


async def try_raw_submit(located_forms: playwright.async_api.Locator):
    try:
        # 1. get forms and submit
        rules = _action_blacklist_rules()
        await PageHandler.safe_locator_evaluate_all(located_forms, FormRawSubmit, rules)
    except Exception as e:
        logging.debug(f"[-] Error at FormRawSubmit: {repr(e)}")


async def try_click_submit(page: playwright.async_api.Page):
    try:
        # 2. Node[type=submit]
        located_elements = await PageHandler.safe_locator_get_all(page, "[type=submit]")
        rules = _action_blacklist_rules()
        for e in located_elements:
            if await is_dangerous_element(e) or await _is_blacklisted_element(e, rules):
                continue
            await e.click()
    except Exception as e:
        logging.debug(f"[-] Error at type submit: {repr(e)}")


async def try_button_submit(page: playwright.async_api.Page):
    try:
        # 3. click all button in forms
        locator = ["button", "[type=button]"]
        rules = _action_blacklist_rules()
        for l in locator:
            located_elements = await PageHandler.safe_locator_get_all(page, l)
            for e in located_elements:
                if await is_dangerous_element(e) or await _is_blacklisted_element(e, rules):
                    continue
                await PageHandler.safe_locator_evaluate(e, FormNodeClickJS)
                await e.click(force=True)
    except Exception as e:
        logging.debug(f"[-] Error at click button in forms: {repr(e)}")


def get_match_input_value(input_name: str) -> str:
    for k, v in crawler_config.CUSTOM_FORM_KEYWORD.items():
        if k in input_name:
            return v
    for i in InputTextMap:
        for k in i.value["key"]:
            if k in input_name:
                return i.value["value"]
    return crawler_config.DEFAULT_INPUT_VALUE
