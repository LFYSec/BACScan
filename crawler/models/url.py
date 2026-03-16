#!/user/bin/env python
"""
@Time   : 2022-02-24 19:46
@Author : WJQ
@File   : url.py
"""

import urllib.parse
from urllib.parse import urlparse


class URL:
    def __init__(self, url=None):
        self.url: str = url  # url string
        self.scheme: str = ""
        self.host: str = ""  # host or host:port
        self.raw_path: str = ""  # encoded path hint (see EscapedPath method)
        self.raw_query: str = ""  # encoded query values, without '?'
        self.raw_fragment: str = ""  # encoded fragment hint (see EscapedFragment method)
        self._init_param()

    def _init_param(self):
        parsed = urlparse(self.url)
        self.scheme = parsed.scheme
        self.host = parsed.netloc
        self.raw_path = parsed.path
        self.raw_query = parsed.query
        self.raw_fragment = parsed.fragment

    def query_map(self) -> dict:
        query_map = dict()
        for key, value in urllib.parse.parse_qs(self.raw_query, keep_blank_values=True).items():
            if len(value) == 1:
                query_map[key] = value[0]
            else:
                query_map[key] = value
        return query_map

    def get_hostname(self) -> str:
        """
        Get hostname, strip port and []

        :return:
        """
        if ":" in self.host:
            return self.host.split(":")[0]
        if self.host.startswith("[") and self.host.endswith("]"):
            return self.host[1 : len(self.host) - 1]
        return self.host

    def request_uri(self) -> str:
        """
        Get current ur's request uri, with some format

        :return:
        """
        result = ""
        if result == "":
            result = urllib.parse.quote(self.raw_path)
            if result == "":
                result = "/"
        else:
            if result.startswith("//"):
                result = self.scheme + ":" + result
        if self.raw_query != "":
            result = result + "?" + self.raw_query
        return result

    def parent_path(self):
        """
        Get parent path of current uri

        :return:
        """
        if self.raw_path == "/":
            return ""
        elif self.raw_path.endswith("/"):
            if self.raw_path.count("/") == 2:
                return "/"
            parts = self.raw_path.split("/")
            parts = parts[:-2]
            result = "/"
            return result.join(parts)
        else:
            if self.raw_path.count("/") == 1:
                return "/"
            parts = self.raw_path.split("/")
            parts = parts[:-1]
            result = "/"
            return result.join(parts)

    def file_ext(self) -> str:
        """
        Get file extension

        :return:
        """
        file_name = self.get_filename()
        if file_name == "":
            return ""
        parts = file_name.split(".")
        return parts[len(parts) - 1].lower()

    def get_filename(self):
        """
        Return filename

        :return:
        """
        parts = self.raw_path.split("/")
        last_part = parts[len(parts) - 1]
        if "." in last_part:
            return last_part
        else:
            return ""
