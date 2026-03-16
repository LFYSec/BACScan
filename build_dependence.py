#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   vuln_url_scan.py
@Time    :   2024/07/17 14:50:10
@Author  :   LFY
'''
from vuln_detection.utils.data_dependence_util import build_dependence
import asyncio
from config import *
from vuln_detection.utils.pipeline_context import load_or_generate_merged_graph

# os.environ["HTTP_PROXY"] = "http://127.0.0.1:8080"
# os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8080"

async def main():
    graph = load_or_generate_merged_graph()
    await build_dependence(graph)


if __name__ == '__main__':

    asyncio.run(main())

