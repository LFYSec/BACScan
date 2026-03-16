#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
TARGET_FILE = ROOT_DIR / "target.json"
DEFAULT_LOG_LEVEL = "debug"
DEFAULT_TAB_COUNT = "15"


def _run_python_script(args, cms):
    cmd = [sys.executable] + args
    print(f"[run] {' '.join(cmd)}")
    merged_env = dict(os.environ)
    merged_env["BACSCAN_CMS"] = cms
    subprocess.run(cmd, cwd=str(ROOT_DIR), check=True, env=merged_env)


def _resolve_roles(target_role):
    if target_role is None:
        return ["visitor", "user", "admin"]

    if isinstance(target_role, str):
        role = target_role.strip().lower()
        if role in ("user", "admin"):
            return ["visitor", role]
        if role in ("all", "both"):
            return ["visitor", "user", "admin"]
        if role == "visitor":
            return ["visitor"]
        raise ValueError(f"Unsupported role value in target.json: {target_role}")

    if isinstance(target_role, list):
        normalized = []
        for role in target_role:
            role_text = str(role).strip().lower()
            if role_text not in ("visitor", "user", "admin"):
                raise ValueError(f"Unsupported role value in target.json: {role}")
            if role_text not in normalized:
                normalized.append(role_text)
        if not normalized:
            return ["visitor", "user", "admin"]
        if "visitor" not in normalized:
            normalized.insert(0, "visitor")
        ordered = [r for r in ("visitor", "user", "admin") if r in normalized]
        return ordered

    raise ValueError("Field 'role' in target.json must be a string or list.")


def _load_target():
    if not TARGET_FILE.exists():
        raise FileNotFoundError(f"target.json not found: {TARGET_FILE}")
    with open(TARGET_FILE, "r", encoding="utf-8") as f:
        targets = json.load(f)
    if not isinstance(targets, list):
        raise ValueError("target.json root must be a JSON array.")
    if not targets:
        raise ValueError("target.json must contain at least one target item.")

    normalized_targets = []
    for idx, target in enumerate(targets):
        if not isinstance(target, dict):
            raise ValueError(f"target.json item #{idx} must be a JSON object.")
        cms = str(target.get("cms") or "").strip()
        url = str(target.get("url") or "").strip()
        role = target.get("role", target.get("roles", None))
        if not cms:
            raise ValueError(f"target.json item #{idx} requires field: cms")
        if not url:
            raise ValueError(f"target.json item #{idx} requires field: url")
        normalized_targets.append((cms, url, role))
    return normalized_targets


def _role_cookie_path(cms, role):
    auth_dir = ROOT_DIR / "auth" / cms
    if role == "user":
        cookie_path = auth_dir / "user_nav.json"
    elif role == "admin":
        cookie_path = auth_dir / "admin_nav.json"
    else:
        return None

    if not cookie_path.exists():
        raise FileNotFoundError(f"Cookie file not found for role={role}: {cookie_path}")
    return cookie_path.relative_to(ROOT_DIR).as_posix()


def _run_crawler(url, cms, role):
    cookie_path = _role_cookie_path(cms, role)
    cmd = [
        "crawler_run.py",
        "-u",
        url,
        "--log-level",
        DEFAULT_LOG_LEVEL,
        "-t",
        DEFAULT_TAB_COUNT,
        "-r",
        role,
    ]
    if cookie_path:
        cmd.extend(["-cp", cookie_path])
    _run_python_script(cmd, cms)


def main():
    targets = _load_target()
    for cms, url, target_role in targets:
        roles = _resolve_roles(target_role)
        print(f"[target] cms={cms} url={url} roles={','.join(roles)}")
        for role in roles:
            _run_crawler(url, cms, role)

        _run_python_script(["build_dependence.py"], cms)
        _run_python_script(["vuln_scan.py"], cms)


if __name__ == "__main__":
    main()
