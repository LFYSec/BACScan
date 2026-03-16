#!/user/bin/env python
# -*- coding: utf-8 -*-
"""
@Time   : 2022-02-03 14:59
@Author : LFY
@File   : simple.py
"""

# here put the import lib
import copy
from typing import Set

from crawler.filters.libfilters.filter import FilterBase
from crawler.models.request import Request
from crawler.utils import *


@Singleton
class SimpleFilter(FilterBase):
    def __init__(self):
        self.simple_unique_set: Set = set()

    def do_filter(self, req: Request) -> bool:
        """
        做三种最简单的过滤：
            1. 过滤其他domain的url
            2. 过滤静态资源
            3. md5(url)去重

        :return: True -> filtered; False -> add to urlpool
        """
        if super().do_filter(req):
            return True

        if self.simple_filter(req):
            return True
        return False

    def simple_filter(self, req: Request) -> bool:
        req = self.replace_param(req)
        hash_url = self.unique_id(req)
        if hash_url in self.simple_unique_set:
            return True
        else:
            self.simple_unique_set.add(hash_url)
            return False

    def unique_id(self, req: Request):
        if req.redirect_flag:
            return self.calc_id(req) + "Redirect"
        else:
            return self.calc_id(req)

    def replace_param(self, req: Request) -> Request:
        # if any(i in req.url.lower() for i in ['/order/list?draw=']):
        #     return req
        params_to_replace = ["t"]
        min_length = 8
        url_parts = urlparse(req.url)
        query = parse_qs(url_parts.query,keep_blank_values=False)

        for param in params_to_replace:
            if param in query:
                if any(len(v) == min_length and v.isdigit() for v in query[param]):
                    query[param] = ['']

        new_query = urlencode(query, doseq=True)
        new_url = urlunparse((url_parts.scheme, url_parts.netloc, url_parts.path, url_parts.params, new_query, url_parts.fragment))
        req.url = new_url
        return req

    @staticmethod
    def calc_id(req: Request):
        if req.post_data is not None:
            try:
                return get_md5_str(req.method + req.url + req.post_data.decode())
            except:
                pass
        return get_md5_str(req.method + req.url)
