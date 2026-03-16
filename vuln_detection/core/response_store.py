# -*- coding: utf-8 -*-
import logging

from elasticsearch import NotFoundError

from vuln_detection.utils.es_util import ElasticsearchClient
from vuln_detection.core.http_client import get_html


async def get_normal_response(target):
    es = ElasticsearchClient().get_client()
    es_id = target.get("es_id")
    try:
        es_data = es.get(index="node_info", id=es_id)
        normal_html = es_data.get("_source", {}).get("response")
        if normal_html:
            return normal_html
    except NotFoundError:
        pass
    except Exception as e:
        logging.error(f"[-] ES error at get_normal_response: {repr(e)}")

    normal_html = await get_html(target, None)
    if normal_html is None:
        normal_html = ""
    try:
        es.index(index="node_info", id=es_id, body={"response": normal_html})
    except Exception as e:
        logging.error(f"[-] Failed to index document in Elasticsearch: {repr(e)}")
    return normal_html
