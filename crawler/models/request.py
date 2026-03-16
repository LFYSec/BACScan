#!/user/bin/env python
"""
@Time   : 2022-02-06 14:46
@Author : LFY
@File   : request.py
"""

# here put the import lib
import hashlib
import json
import logging
import urllib.parse

import requests
import urllib3

from config.crawl_config import ContentType, RequestMethod, crawler_config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Request:
    def __init__(
        self,
        url,
        method="GET",
        headers=None,
        post_data=None,
        redirect_flag=False,
        response=None,
        from_url=None,
        base_url=None,
    ):
        self.url: str = url
        self.method: str = method
        self.headers: dict[str, str] = headers
        self.post_data: bytes = post_data
        self.redirect_flag: bool = redirect_flag
        self.response: str = response
        self.from_url: str = from_url
        self.base_url: str | None = base_url
        self.seq: int | None = None
        self.layer = 1
        self._dedup_key = self._build_dedup_key()

    @staticmethod
    def _post_data_digest(post_data) -> str:
        if post_data is None:
            return ""
        if isinstance(post_data, bytes):
            raw = post_data
        elif isinstance(post_data, str):
            raw = post_data.encode("utf-8", errors="ignore")
        else:
            raw = str(post_data).encode("utf-8", errors="ignore")
        return hashlib.sha256(raw).hexdigest()

    def _build_dedup_key(self):
        method = str(self.method).upper() if self.method is not None else "GET"
        url = str(self.url) if self.url is not None else ""
        body_digest = self._post_data_digest(self.post_data)
        return method, url, body_digest, bool(self.redirect_flag)

    def __hash__(self):
        return hash(self._dedup_key)

    def __eq__(self, other):
        if not isinstance(other, Request):
            return False
        return self._dedup_key == other._dedup_key

    def request(self):
        proxy = {"http": crawler_config.PROXY, "https": crawler_config.PROXY} if crawler_config.PROXY else None
        try:
            if self.method == RequestMethod.GET.value:
                return requests.get(
                    self.url, headers=self.headers, proxies=proxy, allow_redirects=False, verify=False
                ).text
            else:
                return requests.post(
                    self.url,
                    headers=self.headers,
                    data=self.post_data,
                    proxies=proxy,
                    allow_redirects=False,
                    verify=False,
                ).text
        except Exception as e:
            logging.info(f"[-] Requests {self.url} error: {repr(e)}")

    def post_data_map(self) -> dict:
        re_content_type = self.get_content_type()
        try:
            if self.post_data is not None:
                self.post_data = self.post_data.decode()
        except Exception:
            logging.error("[-] Error at post_data_map")
            pass
        if re_content_type == "":
            return {"key": self.post_data}

        result = {}
        if re_content_type.startswith(ContentType.JSON):
            try:
                result = json.loads(self.post_data)
            except Exception as e:
                logging.debug(f"[-] Error at post_data_map: {repr(e)}")
                return {"key": self.post_data}
            return result
        elif re_content_type.startswith(ContentType.URLENCODED):
            try:
                r = urllib.parse.parse_qs(self.post_data, keep_blank_values=True)
            except Exception as e:
                logging.debug(f"[-] Error at post_data_map: {repr(e)}")
                return {"key": self.post_data}

            for key, value in r.items():
                if len(value) == 1:
                    result[key] = value[0]
                else:
                    result[key] = value
            return result
        else:
            return {"key": self.post_data}

    def get_content_type(self) -> str:
        """
        获取当前请求的content type

        :return:
        """
        headers = self.headers
        re_content_type = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                re_content_type = v
        if re_content_type == "":
            return ""

        support_content_type = [ContentType.JSON, ContentType.URLENCODED]
        for ct in support_content_type:
            if re_content_type.startswith(ct):
                return re_content_type
        return ""

    def set_response(self, response):
        self.response = response
