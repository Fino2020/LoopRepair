# -*- coding: utf-8 -*-
import difflib
import json
import os
import sys
import typing
import re
from loguru import logger
import openai
from openai import OpenAI
from tree_sitter import Language, Parser
import tempfile
import subprocess
from json_repair import repair_json

openai.api_key = "sk-oCkkCqAtYNCnRHxnZpM1sPGq8tu1eSDuLC02uAtaNNLBTqSD"
openai.base_url = "https://chatapi.onechats.top/v1/"
client = OpenAI(api_key=openai.api_key, base_url=openai.base_url)
api_model = "gpt-4o-mini"
Language.build_library(
	
	# Store the library in the `build` directory
	'../tree-sitter/build/my-languages.so',
	
	# Include one or more languages
	[
		'../tree-sitter/vendor/tree-sitter-c',
	]
)

C_LANGUAGE = Language('../tree-sitter/build/my-languages.so', 'c')

with open('../prompt/repair_function.txt', 'r', encoding='utf-8') as f:
	repair_function = f.read()

with open('../prompt/iterative_function.txt', 'r', encoding='utf-8') as f:
	iterative_function = f.read()

with open('../prompt/predict_sequence.txt', 'r', encoding='utf-8') as f:
	predict_sequence = f.read()

def get_function_from_file(
		file_path,
		line_number
):
	parser = Parser()
	parser.set_language(C_LANGUAGE)
	
	with open(file_path, 'r', encoding='utf-8') as f:
		code = f.read()
	
	tree = parser.parse(bytes(code, 'utf-8'))
	root_node = tree.root_node
	
	def get_function_node(
			node,
			line_number
	):
		if node.type == 'function_definition':
			start_line = node.start_point[0]
			end_line = node.end_point[0]
			if start_line <= line_number <= end_line:
				return start_line, end_line
		for child in node.children:
			result = get_function_node(child, line_number)
			if result:
				return result
		return None
	
	results = get_function_node(root_node, line_number)
	if results:
		start_line = results[0]
		end_line = results[1]
		indent = ' ' * (len(code.split('\n')[start_line]) - len(code.split('\n')[start_line].lstrip()))
		
		function_code = '\n'.join(code.split('\n')[start_line:end_line + 1])
		# 去除function_code中每一行的第一个indent
		for i in range(len(function_code.split('\n'))):
			if function_code.split('\n')[i].startswith(indent):
				function_code.split('\n')[i] = function_code.split('\n')[i][len(indent):]
		return start_line, end_line, function_code, code.split('\n')[line_number - 1][len(indent):], indent
	else:
		return None


def patch_generation(
		question
):
	try:
		response = client.chat.completions.create(
			model=api_model,
			messages=[
				{ "role": "system", "content": "You are now playing the role of a vulnerability repair expert." },
				{ "role": "user", "content": question },
			],
			response_format={
				"type":        "json_schema",
				"json_schema": {
					"name":   "patch_function_generation",
					"schema": {
						"type":                 "object",
						"properties":           {
							"patch_function":    { "type": "string" },
							"explanation": { "type": "string" }
						},
						"required":             ["patch_function", "explanation"],
						"additionalProperties": False
					},
					"strict": True
				}
			}
		)
		text = response.choices[0].message.content
		json_result = json.loads(repair_json(text))
		return json_result['patch_function']
	except Exception as e:
		logger.error(f"The LLM returned an error. Error: {e}. Prompt:{question}")



def generate_candidates(
		patch,
		source_file_path,
		start_line,
		end_line,
		first_indent
):
	with open(source_file_path, 'r', encoding='utf-8') as f:
		code = f.read()
		original_lines = code.split('\n')
		patch_lines = original_lines[0:start_line] + [first_indent + line for line in
													  patch.split('\n')] + original_lines[end_line + 1:]
		_, patch_filename = tempfile.mkstemp(suffix=".c")
		# 将补丁内容写入刚刚创建的临时文件中。
		with open(patch_filename, "w", encoding='utf-8') as fh:
			fh.write('\n'.join(patch_lines))
		
		if os.path.exists("/tmp/diff.patch"):
			os.remove("/tmp/diff.patch")
		command = f"diff -Naur {source_file_path} {patch_filename} > /tmp/diff.patch"
		# try:
		subprocess.call(
			command,
			shell=True,
		)
		# finally:
		#     os.remove(patch_filename)
		with open("/tmp/diff.patch", 'r', encoding='utf-8') as f:
			diff_str = f.read()
			# 删除diff中以'---'或'+++'开头的行
			diff_str = '\n'.join(
				[line for line in diff_str.split('\n') if
				 not (line.startswith('---') or line.startswith('+++'))]
			)
	return diff_str

def Predict_sequence(
		function, number, line
):
	def ask_llm(question):
		response = client.chat.completions.create(
			model=api_model,
			messages=[
				{ "role": "system", "content": "You are now playing the role of a vulnerability repair expert." },
				{ "role": "user", "content": question },
			],
			response_format={
				"type":        "json_schema",
				"json_schema": {
					"name":   "repair_sequence_generation",
					"schema": {
						"type":                 "object",
						"properties":           {
							"sequence":    { "type": "string" },
							"explanation": { "type": "string" }
						},
						"required":             ["sequence", "explanation"],
						"additionalProperties": False
					},
					"strict": True
				}
			}
		)
		text = response.choices[0].message.content
		json_result = json.loads(repair_json(text))
		return json_result['sequence']
	sequence_generate_prompt = predict_sequence.format(
		function=function,
		number= str(number),
		line=line,
	)
	sequence = ask_llm(sequence_generate_prompt)
	return sequence

def generate_use_llms_from_location(
		id: int,
		location: str,
		diff: str,
		vulnerability_type: str
):
	# 根据location的位置信息，以及diff所涉及的上一次修复的内容，生成下一次修复的prompt
	total_candidate = []
	vulnerable_file_path = location.split(':')[0]
	line_number = int(location.split(':')[1])
	results = get_function_from_file(vulnerable_file_path, line_number)
	if results:
		start_line = results[0]
		end_line = results[1]
		function = results[2]
		vulnerable_line = results[3]
		indent = results[4]
		prompt = iterative_function.format(
			function=function,
			line=vulnerable_line,
			number=line_number - start_line + 1
		)
		patch_function = patch_generation(prompt)
		diff = generate_candidates(
			patch=patch_function,
			source_file_path=vulnerable_file_path,
			start_line=start_line,
			end_line=end_line,
			first_indent=indent
		)
		return {
			'id':       id,
			'diff':     diff,
			'location': location
		}


def generate_use_llms_from_localization_list(
		localization_list,
		vulnerability_type,
		output_path
):
	logger.info(f"Generating candidates from localization dict")
	total_candidates = []
	patch_id = 0
	for i in localization_list:
		vulnerable_file_path = i['location'].split(':')[0]
		line_number = int(i['location'].split(':')[1])
		crash_free_constrain = i['constraint']
		# token_number = int(i['location'].split(':')[2])
		results = get_function_from_file(vulnerable_file_path, line_number)
		if results:
			start_line = results[0]
			end_line = results[1]
			function = results[2]
			vulnerable_line = results[3]  # 代表漏洞代码语句，非行号
			indent = results[4]
			
			prompt = iterative_function.format(
				function=function,
				line=vulnerable_line,
				vulnerability_type=vulnerability_type,
				crash_free_constrain=crash_free_constrain,
				number=line_number - start_line + 1,
				sequence=Predict_sequence(function=function, number=line_number - start_line + 1, line=vulnerable_line),
			)
			for _ in range(5):
				patch_function = patch_generation(prompt)
				diff = generate_candidates(
					patch_function,
					vulnerable_file_path,
					start_line,
					end_line,
					indent
				)
				total_candidates.append(
					{
						'diff':     diff,
						'id':       patch_id,
						'location': i['location'],
					}
				)
				patch_id += 1
	logger.info(f"total_candidates:#{total_candidates}")
	with open(output_path, 'w', encoding='utf-8') as f_1:
		f_1.write(json.dumps(total_candidates, ensure_ascii=False, indent=4))


def generate_use_llms_from_localization_path(
		localization_path: str,
		output_path: str
):
	total_candidates = []
	patch_id = 0
	with open(localization_path, "r", encoding='utf-8') as fh:
		localization = json.loads(fh.read())
	for i in localization:
		vulnerable_file_path = i['location'].split(':')[0]
		line_number = int(i['location'].split(':')[1])
		# token_number = int(i['location'].split(':')[2])
		results = get_function_from_file(vulnerable_file_path, line_number)
		if results:
			start_line = results[0]
			end_line = results[1]
			function = results[2]
			vulnerable_line = results[3]  # 代表漏洞代码语句，非行号
			indent = results[4]
			
			prompt = repair_function.format(
				function=function,
				line=vulnerable_line,
				number=line_number - start_line + 1,
				sequence=Predict_sequence(function=function, number=line_number - start_line + 1, line=vulnerable_line),
			)
			for _ in range(5):
				patch_function = patch_generation(prompt)
				diff = generate_candidates(
					patch_function,
					vulnerable_file_path,
					start_line,
					end_line,
					indent
				)
				total_candidates.append(
					{
						'diff':     diff,
						'id':       patch_id,
						'location': i['location'],
					}
				)
				patch_id += 1
	logger.info("total_candidates:{}".format(total_candidates))
	with open(output_path, 'w', encoding='utf-8') as f_write:
		f_write.write(json.dumps(total_candidates, ensure_ascii=False, indent=4))

