# encoding: utf-8
# @File  : run.py
# @Author: Yzl
# @Desc : 
# @Date  :  2025/01/10
import os
import subprocess

# 所有漏洞
# dict_project_vul_id = {
# 	'libtiff': ['bugzilla-2633', 'REDTEAM-CVE-2016-10268', 'CVE-2017-7595', 'CVE-2016-3186',
#                 'CVE-2016-10272', 'CVE-2016-5321', 'CVE-2016-9532', 'CVE-2016-10094',
#                 'REDTEAM-CVE-2022-48281', 'REDTEAM-CVE-2022-4645', 'REDTEAM-CVE-2017-17095',
#                 'bugzilla-2611', 'CVE-2016-10092', 'CVE-2016-9273', 'CVE-2017-7601', 'CVE-2017-5225',
#                 'REDTEAM-CVE-2018-18557', 'CVE-2016-5314', 'CVE-2017-7600', 'CVE-2017-7599'],
#     'libjpeg': ['CVE-2012-2806', 'CVE-2017-15232', 'CVE-2018-19664', 'CVE-2018-14498'],
#     'potrace': ['CVE-2013-7437'],
#     'libxml2': ['REDTEAM-CVE-2016-1833', 'CVE-2016-1839', 'CVE-2012-5134', 'REDTEAM-CVE-2021-3516',
#                 'CVE-2016-1838', 'REDTEAM-CVE-2022-40303', 'CVE-2017-5969'],
#     'binutils': ['CVE-2017-15025', 'REDTEAM-CVE-2021-43149', 'REDTEAM-CVE-2021-20294',
#                  'CVE-2017-6965', 'CVE-2017-14745', 'CVE-2017-15020'],
#     'libming': ['CVE-2018-8964', 'CVE-2018-8806', 'CVE-2016-9264'],
#     'jasper': ['REDTEAM-CVE-2021-3272', 'REDTEAM-CVE-2020-27828', 'CVE-2016-8691', 'CVE-2016-9557'],
#     'coreutils': ['gnubug-19784', 'gnubug-26545', 'gnubug-25003', 'gnubug-25023'],
#     'zziplib': ['CVE-2017-5976', 'CVE-2017-5974', 'CVE-2017-5975'],
#     'libarchive': ['CVE-2016-5844']
# }
dict_project_vul_id = {'binutils': ['CVE-2017-14745']}
# if os.path.exists('/data_bak/'):
# 	print('Returning back to the original data directory')
# 	subprocess.call('rm -rf /data/', shell=True)
# 	subprocess.call('cp -r /data_bak /data/', shell=True)
# else:
# 	print('Copy /data to /data_bak for backup')
# 	subprocess.call('cp -r /data /data_bak', shell=True)
# print('Operation OK, starting the repair process')

for project in dict_project_vul_id.keys():
	for vul_id in dict_project_vul_id[project]:
		if not os.path.exists(f"/logs/{project}/{vul_id}/"):
			os.makedirs(f"/logs/{project}/{vul_id}/")
		if not os.path.exists(f"/results/{project}/{vul_id}/analysis"):
			os.makedirs(f"/results/{project}/{vul_id}/analysis")
		if os.path.exists(f"/data/vulnloc/{project}/{vul_id}/bug.json"):
			subprocess.call(
				f"bash exec.sh {project} {vul_id}",
				shell=True,
			)
		try:
			# 将/data/vulnloc/{project}/{vul_id}/下的analysis文件夹复制到/results/{project}/{vul_id}/下
			subprocess.call(
				f"cp -r /data/vulnloc/{project}/{vul_id}/analysis/analysis.json /results/{project}/{vul_id}/analysis/analysis.json",
				shell=True
			)
			subprocess.call(
				f"cp -r /data/vulnloc/{project}/{vul_id}/analysis/localization.json /results/{project}/{vul_id}/analysis/localization.json",
				shell=True
			)
			subprocess.call(f"cp /data/vulnloc/{project}/{vul_id}/report.json /results/{project}/{vul_id}/", shell=True)
		except:
			pass
