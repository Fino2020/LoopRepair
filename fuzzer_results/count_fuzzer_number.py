#!/usr/bin/python3
# _*_ coding: utf-8 _*_
#
# Copyright (C) 2026 - 2026 Fino, Inc. All Rights Reserved 
#
# @Time    : 2026/1/13 8:43
# @Author  : Fino
# @File    : count_fuzzer_number.py
# @IDE     : PyCharm
import os
root_dir = './'
listdir = os.listdir(root_dir)
dict_fuzzer = {

}
for project in listdir:
    if os.path.isdir(project):
        print(project)
        dict_fuzzer[project] = {}
        list_file = os.listdir(project)
        print(len(list_file))
        for cve_id in list_file:
            if os.path.isdir(os.path.join(project, cve_id)):
                print(cve_id)
                dict_fuzzer[project][cve_id] = len(os.listdir(os.path.join(project, cve_id, 'concentrated_inputs')))

print(dict_fuzzer)
