#!/user/bin/env python
"""
@Time   : 2022-01-23 15:54
@Author : LFY
@File   : task.py
"""

import traceback

# here put the import lib
from asyncio import Queue, Semaphore

from config.crawl_config import crawler_config
from crawler.browser.browser import BrowserHandler
from crawler.crawl.crawl import Crawler
from crawler.filters.filter import Filter
from crawler.models.nav_graph import NavigationGraph
from crawler.models.request import Request
from crawler.utils import *


class Task:
    def __init__(self, init_url: Union[str, list], navigraph: NavigationGraph):
        """
        Task object, including async and task schedule and

        :param init_url:
        """
        self.navigraph = navigraph
        self._init_url = init_url
        self._url_pool: Queue = Queue()
        self.finish_count = 0
        self.task_count = 0
        self._created_task = 0
        self._seq = 0
        self._crawler: Optional[Crawler] = None
        self._filter: Filter = Filter()
        self._tasks: List[asyncio.Task] = []
        self._browser_handler: Optional[BrowserHandler] = None
        self._semaphore: Semaphore = asyncio.Semaphore(crawler_config.MAX_PAGE_NUM)
        self._graph_semaphore: Semaphore = asyncio.Semaphore(crawler_config.MAX_GRAPH_NUM)
        self._lock = asyncio.Lock()

    async def run(self):
        """
        Main entry, init coroutines pool

        :return:
        """
        if isinstance(self._init_url, list):
            for u in self._init_url:
                await self.add_to_urlpool(Request(u.strip(), base_url=u.strip()))
        else:
            urls = self._init_url.split(",")
            for u in urls:
                await self.add_to_urlpool(Request(u, base_url=u))
        if self._crawler is None:
            logging.info("[*] Start crawling...")
            from crawler.crawl.crawl import Crawler as _Crawler

            self._crawler = await _Crawler.create()
            self._browser_handler = self._crawler.browser_handler

        schedule_task = asyncio.create_task(self._task_schedule())

        while True:
            await asyncio.sleep(1)
            if (self._url_pool.empty() and (self.finish_count == self.task_count)) or (self.finish_count > 100):
                for task in self._tasks:
                    task.cancel()
                schedule_task.cancel()
                logging.debug("[+] Crawling task canceled success")
                break
            continue
        await self._crawler.browser_handler.safe_close_browser()

        logging.info("[*] Stop crawling...")

    async def _task_schedule(self):
        while True:
            if self._created_task >= 100 and self._created_task % 100 == 0:
                [self._tasks.remove(t) for t in self._tasks if t.done()]
                await asyncio.wait(self._tasks)
                await self._browser_handler.refresh_context()
            req = await self.get_from_urlpool()
            self._tasks.append(asyncio.create_task(self._async_run_task(req)))
            self._created_task += 1

    async def _async_run_task(self, req: Request):
        """
        Minimal coroutines task for crawler

        :return:
        """
        async with self._semaphore:
            try:
                collected_reqs = await self._crawler.crawl_pages(req, self.navigraph)
                self.navigraph.add_link(req)

                for r in collected_reqs:
                    r.layer = req.layer + 1
                    if r.layer > 1:
                        r.base_url = req.base_url
                    if r.layer > crawler_config.LAYER:
                        continue
                    await self.add_to_urlpool(r)
            except Exception as e:
                logging.error(f"[-] Error at handling collected {req.url} requests: {repr(e)}")
                logging.error(traceback.format_exc())
            finally:
                self.finish_count += 1

    async def get_from_urlpool(self) -> Request:
        """
        Get url from url-queued

        :return:
        """
        return await self._url_pool.get()

    async def add_to_urlpool(self, req: Request):
        """
        Add task to url-queue

        :param req:
        :return:
        """
        if req.from_url:
            req.url = format_url(req.url, req.from_url)
        else:
            req.url = format_url(req.url, req.base_url)
        if req.url:
            if self._filter.do_filter(req) or check_error_request(req):
                logging.debug(f"[-] Url {req.url} method {req.method} filtered")
            else:
                logging.debug(f"[+] Url {req.url} method {req.method} added to pool")
                self._seq += 1
                req.seq = self._seq
                await self._url_pool.put(req)
                self.task_count += 1
