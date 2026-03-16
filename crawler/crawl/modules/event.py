#!/user/bin/env python
"""
@Time   : 2022-03-08 20:17
@Author : LFY
@File   : event.py
"""

# here put the import lib
import asyncio
import json
import logging

import playwright.async_api

from config.crawl_config import crawler_config
from crawler.browser.js.js_crawlergo import (
    TriggerDom2EventJS,
    TriggerInlineEventJS,
    TriggerJavascriptProtocol,
    TriggerUntriggeredClickableJS,
)
from crawler.browser.page import PageHandler


async def trigger_events(page: playwright.async_api.Page, trigger_interval):
    rules = {
        "words": [w.lower() for w in crawler_config.ACTION_BLACKLIST_WORDS if w],
        "regex": list(crawler_config.ACTION_BLACKLIST_REGEX),
        "attrs": list(crawler_config.ACTION_BLACKLIST_ATTRS),
    }
    rules_json = json.dumps(rules)
    mode = (crawler_config.EVENT_TRIGGER_MODE or "random").lower()
    randomize = mode != "full"
    inline_limit = crawler_config.INLINE_EVENT_LIMIT if randomize else 0
    dom2_limit = crawler_config.DOM2_EVENT_LIMIT if randomize else 0
    randomize_js = "true" if randomize else "false"
    try:
        # Trigger Javascript Protocol
        triggered_js_protocol = await PageHandler.safe_evaluate(
            page, TriggerJavascriptProtocol % (trigger_interval, trigger_interval)
        )
        # Trigger HTML inline events
        triggered_inline_events = await PageHandler.safe_evaluate(
            page, TriggerInlineEventJS % (rules_json, randomize_js, inline_limit, trigger_interval)
        )
        # Trigger simple button/section clicks for three rounds.
        triggered_clickables = await PageHandler.safe_evaluate(page, TriggerUntriggeredClickableJS % trigger_interval)
        # Trigger DOM0 & DOM2 events
        triggered_js_events = await PageHandler.safe_evaluate(
            page, TriggerDom2EventJS % (rules_json, randomize_js, dom2_limit, trigger_interval)
        )
    except Exception as e:
        logging.error(f"[-] Error at trigger events: {repr(e)}")
    # Wait for ajax's return which may update DOM
    await asyncio.sleep(crawler_config.BEFORE_EXIT_DELAY)
