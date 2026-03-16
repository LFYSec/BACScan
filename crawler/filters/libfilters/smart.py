#!/user/bin/env python
"""
@Time   : 2022-02-24 12:31
@Author : WJQ
@File   : smart.py
"""

import re

from crawler.filters.libfilters.simple import *
from crawler.models.request import *
from crawler.models.url import *
from crawler.utils import get_md5_str

max_parent_path_count = 32  # 相对于上一级目录，本级path目录的数量修正最大值
max_param_key_single_count = 8  # 某个URL参数名重复修正最大值
max_param_key_all_count = 10  # 本轮所有URL中某个参数名的重复修正最大值
max_path_param_empty_count = 10  # 某个path下的参数值为空，参数名个数修正最大值
max_path_param_key_symbol_count = 5  # 某个Path下的某个参数的标记数量超过此值，则该参数被全局标记

custom_value_mark = "{{Crawlergo}}"
fix_param_repeat_mark = "{{fix_param}}"
fix_path_mark = "{{fix_path}}"
too_long_mark = "{{long}}"
number_mark = "{{number}}"
chinese_mark = "{{chinese}}"
upper_mark = "{{upper}}"
lower_mark = "{{lower}}"
url_encode_mark = "{{urlencode}}"
unicode_mark = "{{unicode}}"
bool_mark = "{{bool}}"
list_mark = "{{list}}"
time_mark = "{{time}}"
mix_alpha_num_mark = "{{mix_alpha_num}}"
mix_symbol_mark = "{{mix_symbol}}"
mix_num_mark = "{{mix_num}}"
no_lower_alpha_mark = "{{no_lower}}"
mix_string_mark = "{{mix_str}}"

chinese_regex = re.compile(r"[\u4e00-\u9fa5]+")
url_encode_regex = re.compile(r"(?:%[A-Fa-f0-9]{2,6})+")
unicode_regex = re.compile(r"(?:\\u\w{4})+")
only_alpha_regex = re.compile(r"^[a-zA-Z]+$")
only_alpha_upper_regex = re.compile(r"^[A-Z]+$")
alpha_upper_regex = re.compile(r"[A-Z]+")
alpha_lower_regex = re.compile(r"[a-z]+")
replace_num_regex = re.compile(r"[0-9]+\.[0-9]+|\d+")
only_number_regex = re.compile(r"^[0-9]+$")
number_regex = re.compile(r"[0-9]+")
one_number_regex = re.compile(r"[0-9]")
num_symbol_regex = re.compile(r"\.|_|-")
time_symbol_regex = re.compile(r"-|:|\s")
only_alpha_num_regex = re.compile(r"^[0-9a-zA-Z]+$")
marked_string_regex = re.compile(r"^{{.+}}$")
html_replace_regex = re.compile(r"\.shtml|\.html|\.htm")


class Filter:
    def __init__(self):
        self.marked_query_map: dict = {}
        self.marked_post_data_map: dict = {}
        self.query_keys_id: str = ""
        self.query_map_id: str = ""
        self.post_data_id: str = ""
        self.marked_path: str = ""
        self.path_id: str = ""
        self.unique_id: str = ""


class SmartFilter(FilterBase):
    def __init__(self):
        self.req_filter = Filter()
        self.simple_filter = SimpleFilter()
        self.filter_location_set = set()
        self.filter_param_key_repeat_count = {}
        self.filter_param_key_single_values = {}
        self.filter_path_param_key_symbol = {}
        self.filter_param_key_all_values = {}
        self.filter_path_param_empty_values = {}
        self.filter_parent_path_values = {}
        self.unique_marked_ids = set()

    def do_filter(self, req: Request) -> bool:
        """
        Crawlergo的smart去重模式实现。
        核心思路为对URL的path和query进行建模，

        :param req: 请求的request
        :return: 是否需要过滤
        """
        if self.simple_filter.do_filter(req):
            return True
        return bool(self.smart_filter(req))

    def smart_filter(self, req: Request) -> bool:
        smart_filter_url = URL(req.url)
        # 标记
        if (
            req.method == RequestMethod.GET.value
            or req.method == RequestMethod.DELETE.value
            or req.method == RequestMethod.HEAD.value
            or req.method == RequestMethod.OPTIONS.value
        ):
            self.get_mark(req)  # unique id 不对
        elif (
            req.method == RequestMethod.POST.value
            or req.method == RequestMethod.PUT.value
            or req.method == RequestMethod.PATCH.value
        ):
            self.post_mark(req)
        else:
            logging.debug("dont support such method: " + req.method)

        if (
            req.method == RequestMethod.GET.value
            or req.method == RequestMethod.DELETE.value
            or req.method == RequestMethod.HEAD.value
            or req.method == RequestMethod.OPTIONS.value
        ):
            self.repeat_count_statistic(req)

        # 对标记后的请求进行去重
        unique_id = self.req_filter.unique_id
        if unique_id in self.unique_marked_ids:
            logging.debug("filter req by unique_marked_ids 1: " + smart_filter_url.request_uri())
            return True

        # 全局数值型参数标记
        self.global_filter_location_mark(req)

        # 接下来对标记的GET请求进行去重
        if (
            req.method == RequestMethod.GET.value
            or req.method == RequestMethod.DELETE.value
            or req.method == RequestMethod.HEAD.value
            or req.method == RequestMethod.OPTIONS.value
        ):
            # 对超过阈值的GET请求进行标记
            self.over_count_mark(req)

            # 重新计算 QueryMapid
            self.req_filter.query_map_id = self.get_param_map_id(self.req_filter.marked_query_map)

            # 重新计算 Pathid
            self.req_filter.path_id = self.get_path_id(self.req_filter.marked_path)
        else:
            # 重新计算 PostDataid
            self.req_filter.post_data_id = self.get_param_map_id(self.req_filter.marked_post_data_map)

        # 重新计算请求唯一id
        self.req_filter.unique_id = self.get_marked_unique_id(req)
        # 新的id再次去重
        new_unique_id = self.req_filter.unique_id
        if new_unique_id in self.unique_marked_ids:
            logging.debug("filter req by unique_marked_ids 2: " + smart_filter_url.request_uri())
            return True

        # 添加到结果集
        self.unique_marked_ids.add(new_unique_id)
        return False

    @staticmethod
    def pre_query_mark(raw_query: str) -> str:
        """
        Query的Map对象会自动解码，所以对RawQuery进行预先的标记

        :param raw_query: reques的query
        :return: 替换之后的query
        """
        if re.search(chinese_regex, raw_query):
            return re.sub(chinese_regex, chinese_mark, raw_query)
        elif re.search(url_encode_regex, raw_query):
            return re.sub(url_encode_regex, url_encode_mark, raw_query)
        elif re.search(unicode_regex, raw_query):
            return re.sub(unicode_regex, unicode_mark, raw_query)
        return raw_query

    def get_mark(self, req: Request):
        """
        对GET请求的参数和路径进行标记

        :param req:
        :return: 标记后的唯一请求id
        """
        # 首先是解码前的预先替换
        todo_URL = URL(req.url)
        todo_URL.raw_query = self.pre_query_mark(todo_URL.raw_query)

        # 依次打标记
        query_map = todo_URL.query_map()
        query_map = self.mark_param_name(query_map)
        query_map = self.mark_param_value(query_map, req)
        marked_path = self.mark_path(todo_URL.raw_path)

        # 计算唯一的id
        if len(query_map) != 0:
            query_key_id = self.get_keys_id(query_map)
            query_map_id = self.get_param_map_id(query_map)
        else:
            query_key_id = ""
            query_map_id = ""

        path_id = self.get_path_id(marked_path)

        self.req_filter.marked_query_map = query_map
        self.req_filter.query_keys_id = query_key_id
        self.req_filter.query_map_id = query_map_id
        self.req_filter.marked_path = marked_path
        self.req_filter.path_id = path_id

        # 最后计算标记后的唯一请求id
        self.req_filter.unique_id = self.get_marked_unique_id(req)

    def post_mark(self, req: Request):
        """
        对POST请求的参数和路径进行标记

        :param req:
        :return: 计算标记后的唯一请求id
        """
        post_data_map = req.post_data_map()

        post_data_map = self.mark_param_name(post_data_map)
        post_data_map = self.mark_param_value(post_data_map, req)
        marked_path = self.mark_path(urlparse(req.url).path)

        # 计算唯一的id
        if len(post_data_map) != 0:
            post_data_map_id = self.get_param_map_id(post_data_map)
        else:
            post_data_map_id = ""

        path_id = self.get_path_id(marked_path)

        self.req_filter.marked_post_data_map = post_data_map
        self.req_filter.post_data_id = post_data_map_id
        self.req_filter.marked_path = marked_path
        self.req_filter.path_id = path_id

        # 最后计算标记后的唯一请求id
        self.req_filter.unique_id = self.get_marked_unique_id(req)

    @staticmethod
    def mark_param_name(param_map: dict) -> dict:
        """
        标记参数名

        :param param_map: 参数字典
        :return: 标记后的参数字典
        """
        marked_param_map = {}
        for key, value in param_map.items():
            # 纯字母不处理
            if re.search(only_alpha_regex, key):
                marked_param_map[key] = value
            # 参数名过长
            elif len(key) >= 32:
                marked_param_map[too_long_mark] = value
            # 替换掉数字
            else:
                key = re.sub(replace_num_regex, number_mark, key)
                marked_param_map[key] = value

        return marked_param_map

    def mark_param_value(self, param_map: dict, req: Request) -> dict:
        """
        标记参数值

        :param param_map: 参数值字典
        :param req: 请求的request
        :return: 标记后的参数值字典
        """
        smart_filter_url = URL(req.url)
        marked_param_map = {}
        for key, value in param_map.items():
            if isinstance(value, bool):
                marked_param_map[key] = bool_mark
                continue
            elif isinstance(value, list):
                marked_param_map[key] = list_mark
                continue
            elif isinstance(value, float):
                marked_param_map[key] = number_mark
                continue

            # 只处理string类型
            try:
                value_str = str(value)
            except Exception:
                logging.error("[-] Error at mark_param_value")
                continue

            # Crawlergo 为特定字符，说明此参数位置为数值型，非逻辑型，记录下此参数，全局过滤
            if crawler_config.DEFAULT_INPUT_VALUE in value_str:
                name = smart_filter_url.get_hostname() + smart_filter_url.raw_path + req.method + key
                self.filter_location_set.add(name)
                marked_param_map[key] = custom_value_mark
            # 全大写字母
            elif re.search(only_alpha_upper_regex, value_str):
                marked_param_map[key] = upper_mark
            # 参数值长度大于等于16
            elif len(value_str) >= 16:
                marked_param_map[key] = too_long_mark
            # 均为数字和一些符号组成
            elif re.search(only_number_regex, value_str) or re.search(
                only_number_regex, (re.sub(num_symbol_regex, "", value_str))
            ):
                marked_param_map[key] = number_mark
            # 存在中文
            elif re.search(chinese_regex, value_str):
                marked_param_map[key] = chinese_mark
            # urlencode
            elif re.search(url_encode_regex, value_str):
                marked_param_map[key] = url_encode_mark
            # unicode
            elif re.search(unicode_regex, value_str):
                marked_param_map[key] = unicode_mark
            # 时间
            elif re.search(only_number_regex, (re.sub(time_symbol_regex, "", value_str))):
                marked_param_map[key] = time_mark
            # 字母加数字混合
            elif re.search(only_alpha_num_regex, value_str) and re.search(number_regex, value_str):
                marked_param_map[key] = mix_alpha_num_mark
            # 含有一些特殊符号
            elif self.has_special_symbol(value_str):
                marked_param_map[key] = mix_symbol_mark
            # 数字出现的次数超过3，视为数值型参数
            elif len(one_number_regex.findall(value_str)) >= 3:
                marked_param_map[key] = mix_num_mark
            # 纯小写字母
            elif re.search(only_alpha_regex, value_str) and not re.search(alpha_upper_regex, value_str):
                marked_param_map[key] = lower_mark
            else:
                marked_param_map[key] = value

        return marked_param_map

    def mark_path(self, path: str) -> str:
        """
        # 标记路径

        :param path: request的path
        :return: 标记后的path，比如太长就替换成too_long_mark
        """
        path_parts = path.split("/")
        for index, part in enumerate(path_parts):
            if len(part) >= 32:
                path_parts[index] = too_long_mark
            elif re.search(only_number_regex, re.sub(num_symbol_regex, "", part)):
                path_parts[index] = number_mark
            elif part.endswith(".html") or part.endswith(".htm") or part.endswith(".shtml"):
                part = re.sub(html_replace_regex, "", part)
                # 大写、小写、数字混合
                if (
                    re.search(number_regex, part)
                    and re.search(alpha_upper_regex, part)
                    and re.search(alpha_lower_regex, part)
                ):
                    path_parts[index] = mix_alpha_num_mark
                elif re.search(only_number_regex, re.sub(num_symbol_regex, "", part)):
                    path_parts[index] = number_mark

            # 含有特殊符号
            elif self.has_special_symbol(part):
                path_parts[index] = mix_symbol_mark
            elif re.search(chinese_regex, part):
                path_parts[index] = chinese_mark
            elif re.search(unicode_regex, part):
                path_parts[index] = unicode_mark
            elif re.search(only_alpha_upper_regex, part):
                path_parts[index] = upper_mark
            # 均为数字和一些符号组成
            elif re.search(only_number_regex, re.sub(num_symbol_regex, "", part)):
                path_parts[index] = number_mark
            elif len(one_number_regex.findall(part)) >= 3:
                path_parts[index] = mix_num_mark

        str_join = "/"
        new_path = str_join.join(path_parts)
        return new_path

    def global_filter_location_mark(self, req: Request):
        """
        全局数值型参数过滤

        :param req:
        :return:
        """
        smart_filter_url = URL(req.url)
        base_name = smart_filter_url.get_hostname() + smart_filter_url.raw_path + req.method
        if (
            req.method == RequestMethod.GET.value
            or req.method == RequestMethod.DELETE.value
            or req.method == RequestMethod.HEAD.value
            or req.method == RequestMethod.OPTIONS.value
        ):
            for key in self.req_filter.marked_query_map:
                name = base_name + key
                if name in self.filter_location_set:
                    self.req_filter.marked_query_map[key] = custom_value_mark

        elif (
            req.method == RequestMethod.POST.value
            or req.method == RequestMethod.PUT.value
            or req.method == RequestMethod.PATCH.value
        ):
            for key in self.req_filter.marked_post_data_map:
                name = base_name + key
                if name in self.filter_location_set:
                    self.req_filter.marked_post_data_map[key] = custom_value_mark

    def repeat_count_statistic(self, req: Request):
        """
        进行全局重复参数名、参数值、路径的统计标记
        之后对超过阈值的部分再次打标记

        :param req:
        :return:
        """
        query_key_id = self.req_filter.query_keys_id
        path_id = self.req_filter.path_id
        if query_key_id != "":
            # 所有参数名重复数量统计
            if query_key_id in self.filter_param_key_repeat_count:
                self.filter_param_key_repeat_count[query_key_id] = self.filter_param_key_repeat_count[query_key_id] + 1
            else:
                self.filter_param_key_repeat_count[query_key_id] = 1

        for key, value in self.req_filter.marked_query_map.items():
            param_query_key = query_key_id + key

            if param_query_key in self.filter_param_key_single_values:
                self.filter_param_key_single_values[param_query_key] = set(
                    self.filter_param_key_single_values[param_query_key]
                )
                self.filter_param_key_single_values[param_query_key].add(value)
            else:
                self.filter_param_key_single_values[param_query_key] = set()
                self.filter_param_key_single_values[param_query_key].add(value)

            # 本轮所有URL中某个参数重复数量统计
            if key not in self.filter_param_key_all_values:
                self.filter_param_key_all_values[key] = set()
                self.filter_param_key_all_values[key].add(value)
            else:
                if key in self.filter_param_key_all_values:
                    self.filter_param_key_all_values[key] = set(self.filter_param_key_all_values[key])
                    if value not in self.filter_param_key_all_values[key]:
                        self.filter_param_key_all_values[key].add(value)

            # 如果参数值为空，统计该PATH下的空值参数名个数
            if value == "":
                if path_id not in self.filter_path_param_empty_values:
                    self.filter_path_param_empty_values[path_id] = set()
                    self.filter_path_param_empty_values[path_id].add(key)
                else:
                    if path_id in self.filter_path_param_empty_values:
                        self.filter_path_param_empty_values[path_id] = set(self.filter_path_param_empty_values[path_id])
                        if key not in self.filter_path_param_empty_values[path_id]:
                            self.filter_path_param_empty_values[path_id].add(key)

            path_id_key = path_id + key
            # 某path下的参数值去重标记出现次数统计
            if path_id_key in self.filter_path_param_key_symbol:
                if re.search(marked_string_regex, str(value)):
                    self.filter_path_param_key_symbol[path_id_key] = (
                        int(self.filter_path_param_key_symbol[path_id_key]) + 1
                    )
            else:
                self.filter_path_param_key_symbol[path_id_key] = 1

            # 相对于上一级目录，本级path目录的数量统计，存在文件后缀的情况下，放行常见脚本后缀
            smart_filter_url = URL(req.url)
            if smart_filter_url.parent_path() == "" or self.in_common_script_suffix(smart_filter_url.file_ext()):
                return

            parent_path_id = hashlib.md5(smart_filter_url.parent_path().encode("utf-8")).hexdigest()
            current_path = self.req_filter.marked_path.replace(smart_filter_url.parent_path(), "")
            if parent_path_id not in self.filter_parent_path_values:
                self.filter_parent_path_values[parent_path_id] = set()
                self.filter_parent_path_values[parent_path_id].add(current_path)
            else:
                if parent_path_id in self.filter_parent_path_values:
                    self.filter_parent_path_values[parent_path_id] = set(self.filter_parent_path_values[parent_path_id])
                    if current_path not in self.filter_parent_path_values:
                        self.filter_parent_path_values[parent_path_id].add(current_path)

    def over_count_mark(self, req: Request):
        """
        对重复统计之后，超过阈值的部分再次打标记

        :param req:
        :return:
        """
        query_key_id = self.req_filter.query_keys_id
        path_id = self.req_filter.path_id
        # 参数不为空，
        if query_key_id != "":
            # 某个URL的所有参数名重复数量超过阈值且该参数有超过三个不同的值则打标记
            if (
                self.filter_param_key_repeat_count[query_key_id]
                and int(self.filter_param_key_repeat_count[query_key_id]) > max_param_key_single_count
            ):
                for key in self.req_filter.marked_query_map:
                    param_query_key = query_key_id + key
                    if param_query_key in self.filter_param_key_single_values:
                        self.filter_param_key_single_values[param_query_key] = set(
                            self.filter_param_key_single_values[param_query_key]
                        )
                        if self.filter_param_key_single_values[param_query_key].__len__() > 3:
                            self.req_filter.marked_query_map[key] = fix_param_repeat_mark

            for key in self.req_filter.marked_query_map:
                # 所有URL中，某个参数不同的值出现次数超过阈值，打标记去重
                if key in self.filter_param_key_all_values:
                    self.filter_param_key_all_values[key] = set(self.filter_param_key_all_values[key])
                    if self.filter_param_key_all_values[key].__len__() > max_param_key_all_count:
                        self.req_filter.marked_query_map[key] = fix_param_repeat_mark

                path_id_key = path_id + key
                # 某个PATH的GET参数值去重标记出现次数超过阈值，则对该PATH的该参数进行全局标记
                if (
                    path_id_key in self.filter_path_param_key_symbol
                    and int(self.filter_path_param_key_symbol[path_id_key]) > max_path_param_key_symbol_count
                ):
                    self.req_filter.marked_query_map[key] = fix_param_repeat_mark

            # 处理某个path下空参数值的参数个数超过阈值 如伪静态： http://bang.360.cn/?chu_xiu
            if path_id in self.filter_path_param_empty_values:
                self.filter_path_param_empty_values[path_id] = set(self.filter_path_param_empty_values[path_id])
                if self.filter_path_param_empty_values[path_id].__len__() > max_path_param_empty_count:
                    new_marked_query_map = {}
                    for key, value in self.req_filter.marked_query_map.items():
                        if value == "":
                            new_marked_query_map[fix_param_repeat_mark] = ""
                        else:
                            new_marked_query_map[key] = value

                    self.req_filter.marked_query_map = new_marked_query_map

        # 处理本级path的伪静态
        smart_filter_url = URL(req.url)
        if smart_filter_url.parent_path() == "" or self.in_common_script_suffix(smart_filter_url.file_ext()):
            return

        parent_path_id = hashlib.md5(smart_filter_url.parent_path().encode("utf-8")).hexdigest()
        if parent_path_id in self.filter_parent_path_values:
            self.filter_parent_path_values[parent_path_id] = set(self.filter_parent_path_values[parent_path_id])
            if self.filter_parent_path_values[parent_path_id].__len__() > max_parent_path_count:
                if smart_filter_url.parent_path().endswith("/"):
                    self.req_filter.marked_path = smart_filter_url.parent_path() + fix_path_mark
                else:
                    self.req_filter.marked_path = smart_filter_url.parent_path() + "/" + fix_path_mark

    def get_marked_unique_id(self, req: Request) -> str:
        """
        得到mark之后的唯一id

        :param req:
        :return: md5
        """
        param_id = ""
        if (
            req.method == RequestMethod.GET.value
            or req.method == RequestMethod.DELETE.value
            or req.method == RequestMethod.HEAD.value
            or req.method == RequestMethod.OPTIONS.value
        ):
            param_id = self.req_filter.query_map_id
        elif (
            req.method == RequestMethod.POST.value
            or req.method == RequestMethod.PUT.value
            or req.method == RequestMethod.PATCH.value
        ):
            param_id = self.req_filter.post_data_id

        smart_filter_url = URL(req.url)
        unique_str = req.method + param_id + self.req_filter.path_id + smart_filter_url.host
        if req.redirect_flag:
            # TODO
            unique_str = unique_str + "Redirect"
        if smart_filter_url.raw_path == "/" and smart_filter_url.raw_query == "" and smart_filter_url.scheme == "https":
            unique_str = unique_str + "https"

        if smart_filter_url.raw_fragment != "":
            # 对于单页应用，fragment 是路由的一部分，即便不以 / 开头
            unique_str = unique_str + smart_filter_url.raw_fragment

        return get_md5_str(unique_str)

    @staticmethod
    def get_keys_id(data_map: dict) -> str:
        """
        计算请求参数名标记后的唯一id

        :param data_map:
        :return:
        """
        keys = []
        id_str = ""
        for key in data_map:
            keys.append(key)
        keys.sort()
        for key in keys:
            id_str = id_str + key

        return get_md5_str(id_str)

    @staticmethod
    def get_param_map_id(data_map: dict) -> str:
        """
        计算请求参数值标记后的唯一id

        :param data_map:
        :return:
        """
        keys = []
        id_str = ""
        mark_replace_regex = re.compile(r"{{.+}}")
        data_map = dict(data_map)
        for key in data_map:
            keys.append(key)
        keys.sort()
        for key in keys:
            value = data_map[key]
            id_str = id_str + key
            try:
                value = str(value)
                id_str += re.sub(mark_replace_regex, "{{mark}}", value)
            except Exception:
                logging.error("[-] Error at get_param_map_id")
                pass
        return hashlib.md5(id_str.encode("utf-8")).hexdigest()

    @staticmethod
    def get_path_id(path: str) -> str:
        """
        计算PATH标记后的唯一id

        :param path:
        :return:
        """
        return get_md5_str(path)

    @staticmethod
    def has_special_symbol(s: str) -> bool:
        symbol_list = ["{", "}", " ", "|", "#", "@", "$", "*", ",", "<", ">", "/", "?", "\\", "+", "="]
        for sym in symbol_list:
            if sym in s:
                return True
        return False

    @staticmethod
    def in_common_script_suffix(suffix: str) -> bool:
        script_suffix = ["php", "asp", "jsp", "asa"]
        for value in script_suffix:
            if value == suffix:
                return True
        return False
