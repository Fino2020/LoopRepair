# encoding: utf-8
# @File  : extract.py
# @Author: Yzl
# @Desc : 
# @Date  :  2025/02/08
import re

with open('../logs/libjpeg/CVE-2018-19664/orchestrator.log', 'r', encoding='utf-8') as f:
    log = f.read()

# 定义正则表达式
crash_location_pattern = r'\[info\] crash location: (.+)'
constraint_pattern = r'\[info\] crash free constraint: (.+)'
# 查找所有匹配项
crash_location_matches = re.findall(crash_location_pattern, log)
constraint_matches = re.findall(constraint_pattern, log)
# 获取最后一个匹配项
if crash_location_matches:
    last_crash_location = crash_location_matches[-1]
    print(last_crash_location)
    vulnerable_file_path = last_crash_location.split(':')[0]
    line_number = int(last_crash_location.split(':')[1])
    print(vulnerable_file_path)
    print(line_number)
else:
    print("No crash location found.")

if constraint_matches:
    last_constraint = constraint_matches[-1]
    print(last_constraint)
