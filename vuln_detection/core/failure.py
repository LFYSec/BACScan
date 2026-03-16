# -*- coding: utf-8 -*-
import re

from config import vuln_scan_config


def _has_empty_root_div(html_text, root_ids):
    if not html_text:
        return False
    for root_id in root_ids:
        safe_id = re.escape(str(root_id))
        pattern = r'<div[^>]*id=["\"]' + safe_id + r'["\"][^>]*>\s*</div>'
        if re.search(pattern, html_text, flags=re.IGNORECASE):
            return True
    return False


def is_html_shell_failure(response, req_url):
    if not response or not req_url:
        return False
    if getattr(vuln_scan_config, "HTML_FAILURE_REQUIRE_API", True):
        if "/api" not in str(req_url).lower():
            return False
    text = str(response)
    lower = text.lower()
    if "<html" not in lower and "<!doctype html" not in lower:
        return False
    markers = getattr(vuln_scan_config, "HTML_FAILURE_MARKERS", ["vite-legacy"])
    if markers and not any(marker in lower for marker in markers):
        return False
    if getattr(vuln_scan_config, "HTML_FAILURE_REQUIRE_ROOT", True):
        root_ids = getattr(vuln_scan_config, "HTML_FAILURE_ROOT_IDS", ["root", "app"])
        if not _has_empty_root_div(text, root_ids):
            return False
    return True


def is_failure_response(response, req_url=None):
    if response is None:
        return True
    text = str(response).lower()
    if not text:
        return True
    for marker in vuln_scan_config.REPLAY_ERROR_MARKERS:
        if re.search(marker, text):
            return True
    if is_html_shell_failure(response, req_url):
        return True
    return False
