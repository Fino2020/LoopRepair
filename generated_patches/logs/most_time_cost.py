# encoding: utf-8
# @File  : most_time_cost.py
# @Author: Yzl
# @Desc : 
# @Date  :  2025/02/17
import os
import re
from datetime import datetime

dict_cve = {}
most_time = 0
root_dir = '../logs'
for project in os.listdir(root_dir):
    if os.path.isfile(os.path.join(root_dir, project)):
        continue
    for vul_id in os.listdir(os.path.join(root_dir, project)):
        if not os.path.exists(os.path.join(root_dir, project, vul_id, 'orchestrator.log')):
            continue
        with open(os.path.join(root_dir, project, vul_id, 'orchestrator.log'), 'r', encoding='utf-8') as f:
            readlines = f.read()
            time_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})'
            times = re.findall(time_pattern, readlines)
            time_objects = [datetime.strptime(time, '%Y-%m-%d %H:%M:%S.%f') for time in times]
            if time_objects:
                first_time = time_objects[0]
                last_time = time_objects[-1]
                time_interval = last_time - first_time
                print("第一个时间点:", first_time)
                print("最后一个时间点:", last_time)
                print("时间间隔:", time_interval)
            else:
                print("没有找到时间节点。")
            dict_cve[vul_id] = time_interval

# print(most_time)
# 根据time_interval对dict_cve进行降序排列
sorted_dict_cve = sorted(dict_cve.items(), key=lambda x: x[1], reverse=True)
print(sorted_dict_cve)
# 超长且无法修复的漏洞
{'CVE-2017-15025', 'CVE-2017-15020', 'CVE-2016-9532', 'CVE-2017-14745', 'CVE-2017-6965', 'CVE-2016-5321'}
