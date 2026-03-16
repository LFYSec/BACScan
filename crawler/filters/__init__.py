#!/user/bin/env python
"""
@Time   : 2022-01-23 15:23
@Author : LFY
@File   : __init__.py.py
"""

# here put the import lib

# TODO
#       对启动的每个page采用基于DOM相似度+URL建模的去重策略。即在add_to_queue中首先根据URL建模的值判断是否重复
#       如果重复，则对URL进行请求并计算DOM相似度，相似度大于某个阈值，则不再加入queue中
#       如果不重复，则直接加入queue中
#  这样可以保证即不会因为URL建模导致漏掉，也不会因为md5(url)导致发出请求过多
#  注意某些静态收集的URL需要先请求一次才能拿到DOM
