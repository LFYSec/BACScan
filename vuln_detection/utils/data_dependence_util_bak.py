import Levenshtein
from config import *
import json
import asyncio
import random
import string
from vuln_detection.similarity.json_similarity import is_valid_json
from vuln_detection.vuln_scan import *
from vuln_detection.utils.es_util import ElasticsearchClient


def get_headers_redirect_url(headers):
    if 'Location' in headers:
        return headers['Location']
    else:
        return None


def get_redirect_from_json(data):
    try:
        response_json = json.loads(data)
        redirect_url = response_json.get('redirect')
        return redirect_url
    except json.JSONDecodeError:
        print("Response is not in valid JSON format.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def calculate_similarity(str1, str2):
    """
    Calculates similarity between two strings using Levenshtein ratio.

    Args:
        str1 (str): First string to compare.
        str2 (str): Second string to compare.

    Returns:
        float: Similarity score between 0 and 1.
    """
    if not str1 or not str2:
        return 0.0
    return Levenshtein.ratio(str1, str2)



def count_unique_params(node_param_list, get_response):
    count = 0
    unique_params = set(node_param_list)
    for param in unique_params:
        if param in get_response:
            count += 1
    return count


def get_param_list(info):
    headers = info["headers"]
    method = info["method"]
    if method == "GET" or "content-type" not in headers:
        data = str(info["get_params"])
        url = "?" + data
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        return query_params
    elif method in vuln_scan_config.OPERATE_METHOD_LIST and info["post_params"] != "None":
        if headers['content-type'] in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
            data = str(info["post_params"])
            url = "?" + data
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            return query_params
        elif headers['content-type'] in vuln_scan_config.JSON_POST_DATA_TYPE:
            keys_list = []
            try:
                data = json.loads(info["post_params"])
                keys_list = list(data.keys())
            except Exception as e:
                print(e)
            return keys_list
    return []


async def count_score(node, get_node, info, get_info):
    node_param_list = get_param_list(info)
    get_response = await get_normal_response(get_info)
    headers = info["headers"]
    headers_redirect_url = get_headers_redirect_url(headers)
    post_response = await get_normal_response(info)
    if "body" in post_response:
        soup = BeautifulSoup(post_response, 'html.parser')
        json_data = soup.find('body').get_text()
    else:
        json_data = post_response
    redirect_url = get_redirect_from_json(json_data)

    score = 1 / (
            1 + calculate_similarity(headers_redirect_url, get_node) + calculate_similarity(redirect_url, get_node))
    if len(node_param_list) > 0:
        score += count_unique_params(node_param_list, get_response) / len(node_param_list)
    else:
        score += 0
    return score


async def sort_by_score(node, info, graph):
    sorted_graph = {}
    for get_node, get_info in graph.items():
        if get_info["method"] in ["GET"] and get_node != node:
            # count score
            sorted_graph[get_node] = await count_score(node, get_node, info, get_info)
    # sort by score
    sorted_graph = dict(sorted(sorted_graph.items(), key=lambda item: item[1]))
    return sorted_graph


def get_data_dependence_list(url):
    data_dependence_dict = json.load(open(vuln_scan_config.DATA_DEPENDENCE_PATH, "r"))
    data_dependence_list = data_dependence_dict[url]
    return data_dependence_list


def contains_letters(value):
    if isinstance(value, str) or isinstance(value, list):
        # 空字符串直接返回True
        if not value:
            return True
        return any(c.isalpha() for c in value)
    return False


def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(characters, k=length))
    return random_string


def insert_str_token(info):
    token = generate_random_string(10)
    data = None
    headers = info["headers"]
    if "content-length" not in info["headers"] or info["headers"]["content-length"] == "0":
        pass
    elif headers['content-type'] in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
        data = str(info["post_params"])
        url = "?" + data
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for key in query_params:
            if any(i in key.lower() for i in vuln_scan_config.INPUT_STRING_LIST) and not any(
                    i in key.lower() for i in vuln_scan_config.NOT_INPUT_STRING_LIST):
                query_params[key] = [token]
        new_query_string = urlencode(query_params, doseq=True)
        info["post_params"] = new_query_string

    elif headers['content-type'] in vuln_scan_config.JSON_POST_DATA_TYPE:
        data = json.loads(info["post_params"])
        for key, value in data.items():
            if any(i in key.lower() for i in vuln_scan_config.INPUT_STRING_LIST) and not any(
                    i in key.lower() for i in vuln_scan_config.NOT_INPUT_STRING_LIST):
                data[key] = token
        info["post_params"] = json.dumps(data)

    return info, token


def update_num_token(info):
    token = random.randint(1, 10)
    data = None
    headers = info["headers"]
    if headers['content-type'] in vuln_scan_config.URLENCODED_POST_DATA_TYPE:
        data = str(info["post_params"])
        url = "?" + data
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for key in query_params:
            if any(i in key.lower() for i in vuln_scan_config.INPUT_NUM_LIST):
                query_params[key] = [str(token)]
        new_query_string = urlencode(query_params, doseq=True)
        info["post_params"] = new_query_string
    elif headers['content-type'] in vuln_scan_config.JSON_POST_DATA_TYPE:
        data = json.loads(info["post_params"])
        for key, value in data.items():
            if any(i in key.lower() for i in vuln_scan_config.INPUT_NUM_LIST):
                data[key] = token
        info["post_params"] = json.dumps(data)

    return info, token


async def build_dependence(graph):
    es = ElasticsearchClient().get_client()
    if os.path.exists(vuln_scan_config.DATA_DEPENDENCE_PATH):
        data_dependence_dict = json.load(open(vuln_scan_config.DATA_DEPENDENCE_PATH, "r"))
    else:
        data_dependence_dict = {}
    token_set = list()
    for node, info in graph.items():
        if info["method"] in vuln_scan_config.OPERATE_METHOD_LIST:
            info, token = insert_str_token(info)
            token_set.append(token)
            if info["operation"] == "DELETE":
                info = replace_delete_id(info)

            cookie_path = get_session_by_role(info["roles"][0])
            add_response = await get_html(info, cookie_path)

            if node not in data_dependence_dict:
                data_dependence_dict[node] = []
            # sorted_graph
            sorted_graph = await sort_by_score(node, info, graph)
            # non_sorted_graph
            # sorted_graph = graph
            for target_node in sorted_graph.keys():
                target_info = graph[target_node]
                if target_info["method"] in ["GET"] and target_node != node:
                    normal_response = await get_normal_response(target_info)

                    cookie_path = get_session_by_role(target_info["roles"][0])
                    html = await get_html(target_info, cookie_path)

                    if (str(token) in html) or (
                            normal_response != html and info["operation"] in ["DELETE"] and target_info[
                        "operation"] in ["SELECT"]):
                        if target_node not in data_dependence_dict[node]:
                            data_dependence_dict[node].append(target_node)
                            es_id = target_node
                            doc = {
                                'response': html
                            }
                            try:
                                es.index(index="node_info", id=es_id, body=doc)
                                break
                            except Exception as e:
                                logging.error(f"[-] ES error: {repr(e)}")

    with open(vuln_scan_config.DATA_DEPENDENCE_PATH, "w") as f:
        json.dump(data_dependence_dict, f, indent=4)
