# here put the import lib
import argparse
import asyncio
import logging
import time

from config.crawl_config import *
from crawler.models.nav_graph import NavigationGraph
from crawler.task import Task
from crawler.utils import form_value_parser, ignore_parser, init_logging

# os.environ["HTTP_PROXY"] = "http://127.0.0.1:8080"
# os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8080"


async def main(init_urls: str | list, navigraph: NavigationGraph):
    logging.info(
        f"[*] Loading config: {type(crawler_config).__name__}, filter mode: {crawler_config.FILTER_MODE}, "
        f"proxy: {crawler_config.PROXY} max page-number: {crawler_config.MAX_PAGE_NUM}"
    )
    await Task(init_urls, navigraph).run()
    navigraph.visualize()


if __name__ == "__main__":
    start_time = time.time()
    parser = argparse.ArgumentParser(
        description="A powerful dynamic crawler for web vulnerability scanners",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url",
        "-u",
        metavar="http://example.com",
        type=str,
        nargs="?",
        help="The target url, or multi urls split by ','",
        dest="url",
        required=False,
    )
    parser.add_argument(
        "--tab-count",
        "-t",
        metavar="15",
        type=int,
        nargs="?",
        help="Maximum number of tabs running. Default: 15",
        dest="tab_count",
        required=False,
    )
    parser.add_argument(
        "--layer",
        "-l",
        metavar="3",
        type=int,
        nargs="?",
        help="Maximum crawl layer. Default: 3",
        dest="layer",
        required=False,
    )
    parser.add_argument(
        "--filter-mode",
        "-fm",
        choices=["smart", "simple", "page"],
        type=str,
        nargs="?",
        help="Filter mode for collected url. Default: simple",
        dest="filter",
        default="smart",
        required=False,
    )
    parser.add_argument(
        "--ignore-url-keywords",
        "-ig",
        metavar="logout",
        type=str,
        nargs="?",
        action="append",
        help="Ignore urls which contain these words. e.g.: -ig exit -ig logout",
        dest="ignore",
        required=False,
    )
    parser.add_argument(
        "--form-value",
        "-fv",
        metavar="username=admin",
        nargs="?",
        action="append",
        help="Custom input value to fill forms. e.g.:-fv a=b -fv c=d",
        dest="form_value",
        required=False,
    )
    parser.add_argument(
        "--proxy",
        "-p",
        metavar="http://127.0.0.1:8080",
        default=None,
        type=str,
        nargs="?",
        help="Proxy for all requests. Default: None",
        dest="proxy",
        required=False,
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info"],
        type=str,
        nargs="?",
        default="debug",
        help="Log level of crawler. Default: info",
        dest="log_level",
        required=False,
    )
    parser.add_argument(
        "--no-headless",
        action="store_true",
        dest="noheadless",
        help="Whether to run browser in no headless mode. Default: False",
        required=False,
    )
    parser.add_argument("--extra-header", "-eh", metavar="a:b", type=str, nargs="?", dest="headers", required=False)
    parser.add_argument(
        "--cookie-path", "-cp", metavar="/a/b.json", type=str, nargs="?", dest="cookie_path", required=False
    )
    parser.add_argument("--cookie", "-c", metavar="a:b", type=str, nargs="?", dest="cookie", required=False)
    parser.add_argument(
        "--role",
        "-r",
        metavar="all_user",
        default="visitor",
        type=str,
        nargs="?",
        help=" The identity of role for accessing webApp ','",
        dest="role",
        required=False,
    )

    args = parser.parse_args()
    navigraph = NavigationGraph(role=args.role)
    # url = args.url[:-1] if args.url.endswith("/") else args.url
    init_logging(args.log_level)
    if args.filter:
        crawler_config.FILTER_MODE = args.filter
    if args.form_value:
        if any("=" not in x for x in args.form_value):
            logging.error("[!] Custom form-value format error!")
            exit()
        form_value_parser(args.form_value)
    if args.tab_count:
        crawler_config.MAX_PAGE_NUM = args.tab_count
    if args.noheadless:
        crawler_config.HEADLESS_MODE = False
    if args.ignore:
        ignore_parser(args.ignore)
    if args.proxy:
        crawler_config.PROXY = args.proxy
    if args.layer:
        crawler_config.LAYER = args.layer
    if args.headers:
        crawler_config.EXTRA_HEADER = {args.headers.split(":")[0]: args.headers.split(":")[1]}
    if args.cookie:
        cookies = args.cookie.split("#")
        crawler_config.COOKIE = {}
        for c in cookies:
            crawler_config.COOKIE[c.split(":")[0]] = c.split(":")[1]
    if args.cookie_path:
        crawler_config.COOKIE_PATH = args.cookie_path

    if args.url:
        url = args.url
        asyncio.run(main(url, navigraph))
    else:
        logging.error("[!] None target! -u is required")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Code executed in {elapsed_time:.4f} seconds")
