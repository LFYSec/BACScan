# -*- coding: utf-8 -*-
import json
import logging
import os

from config import vuln_scan_config

_PARAM_VARIANTS_CACHE = None


def load_param_variants():
    global _PARAM_VARIANTS_CACHE
    if _PARAM_VARIANTS_CACHE is not None:
        return _PARAM_VARIANTS_CACHE
    path = getattr(vuln_scan_config, "CONTROLLABLE_PARAM_PATH", None)
    if not path or not os.path.exists(path):
        _PARAM_VARIANTS_CACHE = {}
        return _PARAM_VARIANTS_CACHE
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _PARAM_VARIANTS_CACHE = data
            return _PARAM_VARIANTS_CACHE
    except Exception as e:
        logging.error(f"[-] Failed to load param variants: {repr(e)}")
    _PARAM_VARIANTS_CACHE = {}
    return _PARAM_VARIANTS_CACHE


def save_param_variants(data):
    global _PARAM_VARIANTS_CACHE
    path = getattr(vuln_scan_config, "CONTROLLABLE_PARAM_PATH", None)
    if not path:
        return
    try:
        dir_path = os.path.dirname(path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path)
        with open(path, "w") as f:
            json.dump(data, f, indent=4)
        _PARAM_VARIANTS_CACHE = data
    except Exception as e:
        logging.error(f"[-] Failed to save param variants: {repr(e)}")
