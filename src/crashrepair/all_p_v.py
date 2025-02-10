import os

dir_path = os.listdir('/data/vulnloc')
dict_1 = {}
for project in dir_path:
    if project not in dict_1:
        dict_1[project] = []
    for vul_id in os.listdir(f'/data/vulnloc/{project}'):
        dict_1[project].append(vul_id)
print(dict_1)
