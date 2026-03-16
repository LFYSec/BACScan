#!/user/bin/env python
"""
@Time   : 2022-02-03 19:31
@Author : LFY
@File   : filter.py
"""

# here put the import lib
from config.crawl_config import crawler_config
from crawler.filters.libfilters.simple import SimpleFilter
from crawler.filters.libfilters.smart import SmartFilter
from crawler.models.request import Request


class Filter:
    def __init__(self):
        self._simple_filter = SimpleFilter()
        self._smart_filter = SmartFilter()

    def do_filter(self, req: Request) -> bool:
        """
        做三种过滤：
           1. simple_filter做md5级别的过滤和静态资源过滤
           2. 没筛掉的，走model_filter做url建模过滤
           3. 还没筛掉的，走dom_filter做dom相似度的过滤

        :return: True -> filtered; False -> add to urlpool
        """
        if crawler_config.FILTER_MODE == "smart":
            return self._smart_filter.do_filter(req)
        else:
            return self._simple_filter.do_filter(req)
