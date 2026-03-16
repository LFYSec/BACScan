#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   vuln_url_scan.py
@Time    :   2024/07/17 14:50:10
@Author  :   LFY
'''
import time
import asyncio
import csv
import json

from config import *
from vuln_detection.vuln_scan import vuln_detect
from vuln_detection.utils.pipeline_context import load_existing_merged_graph, load_existing_dependence_map

# os.environ["HTTP_PROXY"] = "http://127.0.0.1:8080"
# os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8080"


async def main():
    start_time = time.time()
    cms = vuln_scan_config.CMS
    print(f"vuln detect---{cms}---")
    graph = load_existing_merged_graph()
    dependence_map = load_existing_dependence_map()
    cms_vuln_dict = await vuln_detect(
        graph,
        vuln_scan_config.DET_USER_ROLE,
        dependence_map=dependence_map,
    )
    combined_vuln_dict = {cms: cms_vuln_dict}

    vuln_scan_end_time = time.time()
    vuln_scan_time = vuln_scan_end_time - start_time
    print(f"vuln_scan in {vuln_scan_time:.4f} seconds")

    with open(vuln_scan_config.RESULT_CSV_PATH, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['cms', 'vuln_type', 'attacker_role', 'victim_role', 'req_method', 'req', 'req_data'])
        for cms, cms_vuln_dict in combined_vuln_dict.items():
            for node, info in cms_vuln_dict.items():
                data = info["get_params"] if info["method"] == "GET" else info["post_params"]
                writer.writerow([
                    cms,
                    info.get("vuln_type", ""),
                    info.get("attacker_role", ""),
                    info.get("victim_role", ""),
                    info["method"],
                    info["req_url"],
                    data,
                ])

    with open(vuln_scan_config.RESULT_JSON_PATH, 'w') as f:
        json.dump(combined_vuln_dict, f, indent=4)


if __name__ == '__main__':
    asyncio.run(main())
