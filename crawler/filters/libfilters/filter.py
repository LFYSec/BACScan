#!/user/bin/env python
"""
@Time   : 2022-02-23 17:24
@Author : LFY
@File   : FilterBase.py
"""

# here put the import lib
import copy

from config.crawl_config import STATIC_SUFFIX
from crawler.models.request import Request
from crawler.models.url import URL
from crawler.utils import is_ignored_by_keywords, is_same_host_without_port


class FilterBase:
    """
    Filter's base class
    """

    def do_filter(self, req: Request):
        if not is_same_host_without_port(req.base_url, req.url):
            return True
        return bool(self.static_filter(req.url))

    @staticmethod
    def static_filter(url: str) -> bool:
        """
        Filter all static & blacklist url

        :return: True -> filtered; False -> add to urlpool
        """
        url = URL(url)
        if is_ignored_by_keywords(url.url):
            return True
        if url.scheme != "http" and url.scheme != "https":
            return True
        static_suffix = copy.deepcopy(STATIC_SUFFIX)
        static_suffix.extend(["json", "js", "css"])
        return url.file_ext() in static_suffix
