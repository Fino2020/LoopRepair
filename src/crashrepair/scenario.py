# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import typing as t

import attrs

from loguru import logger

from analyzer import Analyzer
from candidate import PatchCandidate, PatchEvaluation, AnalyzeCandidate
from exceptions import CrashRepairException, AnalyzerTimedOut, AnalyzerCrashed
from fuzzer import Fuzzer, FuzzerConfig
from LLMrepair import generate_use_llms_from_localization_path, generate_use_llms_from_localization_list
from report import (
	AnalysisReport,
	FuzzerReport,
	GenerationReport,
	Report,
	ValidationReport,
	IterativeReport,
	AnalyzeForGuideReport
)
from shell import Shell
from location import Location
from stopwatch import Stopwatch
from test import Test, TestOutcome

# TODO allow these to be customized via environment variables
CRASHREPAIRFIX_PATH = "/opt/crashrepair/bin/crashrepairfix"
CRASHREPAIRLINT_PATH = "/opt/crashrepair/bin/crashrepairlint"
CREPAIR_LIB_PATH = "/CrashRepair/lib"
CREPAIR_RUNTIME_HEADER_PATH = "/CrashRepair/lib/crepair_runtime.h"
KLEE_LIB_PATH = "/klee/build/lib"


@attrs.define(slots=True, auto_attribs=True)
class Scenario:
	"""Provides access to the program under repair.

	Attributes
	----------
	subject: str
		The name of the subject program
	name: str
		The name of the bug scenario
	directory: str
		The absolute path of the bug scenario directory
	build_directory: str
		The absolute path of the build directory for this bug scenario
	source_directory: str
		The absolute path of the source directory for this bug scenario
	compile_commands_path: str
		The absolute path of the compile commands for this bug scenario
	binary_path: str
		The absolute path of the binary under repair for this scenario
	should_terminate_early: bool
		Flag used to control whether the repair process should stop when the first
		acceptable patch has been found, or, alternatively, if it should continue
		finding all acceptable patches for the given bug.
	analysis_directory: str
		The absolute path of the directory that holds the results of the analysis.
	patches_directory: str
		The absolute path of the directory that holds validated patches.
	clean_command: str
		The command that should be used to clean the build space.
	prebuild_command: str
		The command that should be used prior to building the program (e.g., configure).
	build_command: str
		The command that should be used to build the program.
	crashing_command: str
		The command that should be used to trigger the program to crash.
	crashing_input: t.Optional[str]
		The optional path to the file that causes the binary to crash, if relevant.
	expected_exit_code_for_crashing_input: int
		The exit code that _should_ be produced by the program when the crashing input is provided (i.e., the oracle).
	fuzzer: t.Optional[Fuzzer]
		The fuzzer, if any, that should be used to generate additional test cases.
	time_limit_seconds_single_test: int
		The maximum number of seconds that the test is allowed to run before being considered a timeout.
	time_limit_minutes_analysis: int
		The maximum number of minutes that the analysis can run before being considered a timeout.
	sanitizer_flags: str
		Additional CFLAGS/CXXFLAGS that should be used to enable the relevant sanitizers.
	halt_on_error: bool
		If :code:`True`, instructs the sanitizer to halt the program upon failure.
		Otherwise, the program will continue to run where possible.
	rebuild_for_validation: bool
		Forces the orchestrator to rebuild the project from scratch before beginning validation.
	asan_options: t.Optional[str]
		Optional, custom ASAN options that should be used when validating patches.
	ubsan_options: t.Optional[str]
		Optional, custom UBSAN options that should be used when validating patches.
	use_ghost_functions: bool
		Inject the necessary compilation options to allow support for ghost functions during validation.
		Should only be used when ASAN is enabled and must not be used during analysis.
	acceptable_patch_limit: t.Optional[int]
		The maximum number of acceptable patches that should be found before the repair process is halted.
	"""
	subject: str
	name: str
	directory: str
	build_directory: str
	source_directory: str
	tag_id: str
	binary_path: str
	clean_command: str
	prebuild_command: str
	build_command: str
	crashing_command: str
	crashing_input: t.Optional[str]
	shell: Shell
	crash_test: Test
	sanitizer_flags: str = attrs.field(default="")
	additional_klee_flags: str = attrs.field(default="")
	expected_exit_code_for_crashing_input: int = attrs.field(default=0)
	should_terminate_early: bool = attrs.field(default=True)
	fuzzer_tests: t.List[Test] = attrs.field(factory=list)
	fuzzer: t.Optional[Fuzzer] = attrs.field(default=None)
	time_limit_minutes_validation: t.Optional[int] = attrs.field(default=None)
	time_limit_seconds_single_test: int = attrs.field(default=30)
	time_limit_minutes_analysis: int = attrs.field(default=3600)
	halt_on_error: bool = attrs.field(default=True)
	rebuild_for_validation: bool = attrs.field(default=False)
	asan_options: t.Optional[str] = attrs.field(default=None)
	ubsan_options: t.Optional[str] = attrs.field(default=None)
	use_ghost_functions: bool = attrs.field(default=False)
	acceptable_patch_limit: t.Optional[int] = attrs.field(default=None)
	time_limit_minutes_iterative: int = attrs.field(default=60 * 3)
	vulnerability_type: str = attrs.field(default="")
	
	@property
	def compile_commands_path(
			self
	) -> str:
		return os.path.join(self.source_directory, "compile_commands.json")
	
	@property
	def analysis_directory(
			self
	) -> str:
		return os.path.join(self.directory, "analysis")
	
	@property
	def fuzzer_directory(
			self
	) -> str:
		return os.path.join(self.directory, "fuzzer")
	
	@property
	def patches_directory(
			self
	) -> str:
		return os.path.join(self.directory, "patches")
	
	# TODO rename config.ini to fuzzer.ini to make its purpose clear
	@property
	def fuzzer_config_path(
			self
	) -> str:
		return os.path.join(self.directory, "config.ini")
	
	@property
	def localization_path(
			self
	) -> str:
		return os.path.join(self.analysis_directory, "localization.json")
	
	@property
	def analysis_path(
			self
	) -> str:
		return os.path.join(self.analysis_directory, "analysis.json")
	
	@property
	def linter_report_path(
			self
	) -> str:
		return os.path.join(self.directory, "linter-summary.json")
	
	@property
	def patch_candidates_path(
			self
	) -> str:
		return os.path.join(self.directory, "candidates.json")
	
	@property
	def patch_iterative_path(
			self
	) -> str:
		return os.path.join(self.directory, "iterative.json")
	
	def analysis_results_exist(
			self
	) -> bool:
		"""Determines whether the results of the analysis exist."""
		return os.path.exists(self.analysis_directory)
	
	def candidate_repairs_exist(
			self
	) -> bool:
		"""Determines whether a set of candidate repairs exists."""
		return os.path.exists(self.patch_candidates_path)
	
	@classmethod
	def build(
			cls,
			filename: str,
			subject: str,
			name: str,
			tag_id: str,
			build_directory: str,
			source_directory: str,
			binary_path: str,
			clean_command: str,
			prebuild_command: str,
			build_command: str,
			crashing_command: str,
			crashing_input: t.Optional[str],
			expected_exit_code_for_crashing_input: int,
			additional_klee_flags: str,
			sanitizer_flags: str,
			fuzzer_config: t.Optional[FuzzerConfig] = None,
			bad_output: t.Optional[str] = None,
			rebuild_for_validation: bool = False,
			halt_on_error: bool = True,
			ubsan_options: t.Optional[str] = None,
			asan_options: t.Optional[str] = None,
			use_ghost_functions: bool = False,
	) -> Scenario:
		directory = os.path.dirname(filename)
		directory = os.path.abspath(directory)
		
		if not os.path.isabs(build_directory):
			build_directory = os.path.join(directory, build_directory)
		
		if not os.path.isabs(source_directory):
			source_directory = os.path.join(directory, source_directory)
		
		if not os.path.isabs(binary_path):
			binary_path = os.path.join(directory, binary_path)
		
		shell = Shell(cwd=directory)
		
		full_crash_command = f"{binary_path} {crashing_command}"
		if crashing_input:
			full_crash_command = full_crash_command.replace("$POC", crashing_input)
		
		crash_test = Test(
			name="crash",
			command=full_crash_command,
			expected_exit_code=expected_exit_code_for_crashing_input,
			cwd=directory,
			shell=shell,
			bad_output=bad_output,
			asan_options=asan_options,
			ubsan_options=ubsan_options,
		)
		
		scenario = Scenario(
			subject=subject,
			name=name,
			tag_id=tag_id,
			directory=directory,
			build_directory=build_directory,
			source_directory=source_directory,
			binary_path=binary_path,
			clean_command=clean_command,
			prebuild_command=prebuild_command,
			build_command=build_command,
			crashing_command=crashing_command,
			crashing_input=crashing_input,
			shell=shell,
			crash_test=crash_test,
			additional_klee_flags=additional_klee_flags,
			sanitizer_flags=sanitizer_flags,
			rebuild_for_validation=rebuild_for_validation,
			halt_on_error=halt_on_error,
			ubsan_options=ubsan_options,
			asan_options=asan_options,
			use_ghost_functions=use_ghost_functions,
		)
		
		if fuzzer_config:
			scenario.fuzzer = fuzzer_config.build(scenario)
		
		logger.info(f"loaded bug scenario: {scenario}")
		return scenario
	
	@classmethod
	def for_file(
			cls,
			filename: str,
			*,
			skip_fuzzing: bool = False,
			fuzz_seed: int = 0,
	) -> Scenario:
		if not os.path.exists(filename):
			raise ValueError(f"bug file not found: {filename}")
		
		with open(filename, "r") as fh:
			bug_dict = json.load(fh)
		
		fuzzer_config: t.Optional[FuzzerConfig] = None
		
		try:
			project_dict = bug_dict["project"]
			subject = project_dict["name"]
			name = bug_dict["name"]
			tag_id = f"{subject}_{name}"
			binary_path = bug_dict["binary"]
			source_directory = bug_dict["source-directory"]
			build_dict = bug_dict["build"]
			build_directory = build_dict["directory"]
			build_commands = build_dict["commands"]
			clean_command = build_commands["clean"]
			prebuild_command = build_commands["prebuild"]
			build_command = build_commands["build"]
			sanitizer_flags = build_dict.get("sanitizerflags", "")
			rebuild_for_validation = build_dict.get("rebuild-for-validation", False)
			use_ghost_functions = build_dict.get("use-ghost-functions", False)
			
			crash_dict = bug_dict["crash"]
			crashing_command = crash_dict["command"]
			halt_on_error = crash_dict.get("halt-on-error", True)
			crashing_input = crash_dict.get("input")
			bad_output = crash_dict.get("bad_output")
			asan_options = crash_dict.get("asan-options")
			ubsan_options = crash_dict.get("ubsan-options")
			additional_klee_flags = crash_dict.get("extra-klee-flags", "")
			expected_exit_code_for_crashing_input = crash_dict.get("expected-exit-code", 0)
		except KeyError as exc:
			raise ValueError(f"missing field in bug.json: {exc}")
		
		if "fuzzer" in bug_dict and not skip_fuzzing:
			fuzzer_config = FuzzerConfig.from_dict(bug_dict["fuzzer"])
		
		return Scenario.build(
			filename=filename,
			subject=subject,
			name=name,
			tag_id=tag_id,
			binary_path=binary_path,
			build_directory=build_directory,
			source_directory=source_directory,
			clean_command=clean_command,
			prebuild_command=prebuild_command,
			build_command=build_command,
			crashing_command=crashing_command,
			crashing_input=crashing_input,
			additional_klee_flags=additional_klee_flags,
			expected_exit_code_for_crashing_input=expected_exit_code_for_crashing_input,
			sanitizer_flags=sanitizer_flags,
			rebuild_for_validation=rebuild_for_validation,
			fuzzer_config=fuzzer_config,
			bad_output=bad_output,
			halt_on_error=halt_on_error,
			ubsan_options=ubsan_options,
			asan_options=asan_options,
			use_ghost_functions=use_ghost_functions,
		)
	
	@classmethod
	def for_directory(
			cls,
			directory: str
	) -> Scenario:
		if not os.path.isdir(directory):
			raise ValueError("bug directory does not exist [{directory}]")
		
		filename = os.path.join(directory, "bug.json")
		return cls.for_file(filename)
	
	@classmethod
	def for_directory_or_file(
			cls,
			directory_or_filename: str
	) -> Scenario:
		if os.path.isdir(directory_or_filename):
			return cls.for_directory(directory_or_filename)
		else:
			return cls.for_file(directory_or_filename)
	
	def rebuild(
			self,
			*,
			env: t.Optional[t.Dict[str, str]] = None,
			clean: bool = True,
			prebuild: bool = False,
			record_compile_commands: bool = True,
			use_sanitizers: bool = True,
	) -> None:
		"""Performs a clean rebuild of the program under test."""
		if not env:
			env = { }
		
		logger.debug(f"original environment: {os.environ}")
		
		generic_cflags = "-g -O0 -Wno-error"
		klee_cflags = f"-L{KLEE_LIB_PATH} -lkleeRuntest"
		crepair_cflags = (
			f"-I{CREPAIR_LIB_PATH} "
			f"-L{CREPAIR_LIB_PATH} "
			"-lcrepair_runtime -lcrepair_proxy"
		)
		cflags = f"{generic_cflags} {klee_cflags} {crepair_cflags}"
		
		if self.use_ghost_functions:
			ghost_flags = "-lcrepair_ghost"
			logger.debug(f"injecting ghost function into CFLAGS during build: {ghost_flags}")
			cflags = f"{cflags} {ghost_flags}"
		
		if use_sanitizers:
			cflags = f"{cflags} {self.sanitizer_flags}"
		
		# if CC/CXX aren't specified, use LLVM/Clang 11
		default_env = {
			"INJECT_CFLAGS":   cflags,
			"INJECT_CXXFLAGS": cflags,
			"INJECT_LDFLAGS":  cflags,
		}
		if "LD_LIBRARY_PATH_ORIG" in os.environ:
			default_env["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH_ORIG"]
		env = { **default_env, **env }
		
		logger.debug(f"using environment: {env}")
		
		if clean:
			self.shell(self.clean_command, cwd=self.build_directory, check_returncode=False)
		
		if prebuild:
			self.shell(self.prebuild_command, env=env, cwd=self.build_directory)
		
		build_command = self.build_command
		if record_compile_commands:
			build_command = f"bear {build_command}"
		self.shell(build_command, env=env, cwd=self.build_directory)
	
	def analyze(
			self
	) -> None:
		"""Analyzes the underlying cause of the bug and generates repair hints."""
		if self.analysis_results_exist():
			logger.info(f"skipping analysis: results already exist [{self.analysis_directory}]")
			return
		
		analyzer = Analyzer.for_scenario(
			self,
			timeout_minutes=self.time_limit_minutes_analysis,
		)
		analyzer.run(write_to=self.analysis_directory)
	
	def fuzz(
			self
	) -> None:
		"""Generates additional test cases via concentrated fuzzing."""
		if not self.fuzzer:
			logger.info("skipping fuzzing: fuzzer disabled")
			return
		
		self.fuzzer_tests = list(self.fuzzer.fuzz())
	
	def _determine_implicated_files(
			self
	) -> t.Set[str]:
		"""Determines the set of source files that are implicated by the fix localization."""
		implicated_files: t.Set[str] = set()
		with open(self.localization_path, "r") as fh:
			localization: t.List[t.Dict[str, t.Any]] = json.load(fh)
			for entry in localization:
				if entry.get("ignore", False):
					continue
				filename = entry["location"].split(":")[0]
				implicated_files.add(filename)
		return implicated_files
	
	def generate(
			self
	) -> None:
		"""Generates candidate patches using the analysis results."""
		assert self.analysis_results_exist()
		
		# generate a compile_commands.json file
		# self.rebuild()
		# assumes that bear has produced a compilation database previously
		assert os.path.exists(self.compile_commands_path)
		# 记录初始漏洞类型
		if os.path.exists(self.analysis_path):
				with open(self.analysis_path, 'r', encoding='utf-8') as f:
					analysis_json = json.loads(f.read())
					self.vulnerability_type = analysis_json['analysis_output'][0]['bug_type']
		# extract a list of implicated source files
		implicated_files = self._determine_implicated_files()
		logger.info(f"generating candidate repairs in implicated files: {implicated_files}")
		generate_use_llms_from_localization_path(self.localization_path, self.patch_candidates_path)
		# command = " ".join((
		#     CRASHREPAIRFIX_PATH,
		#     "--output-to",
		#     self.patch_candidates_path,
		#     # FIXME replace with --analysis-directory
		#     "--localization-filename",
		#     self.localization_path,
		#     "-p",
		#     self.compile_commands_path,
		#     " ".join(implicated_files),
		#     "-extra-arg=-I/opt/llvm11/lib/clang/11.1.0/include/",
		# ))
		# self.shell(command, cwd=self.source_directory, check_returncode=False)
		assert os.path.exists(self.patch_candidates_path)
	
	def validate(
			self
	) -> (ValidationReport, bool, AnalyzeForGuideReport):
		"""Validates candidate patches."""
		assert self.candidate_repairs_exist()
		isrepair = False
		logger.info(
			"beginning candidate patch evaluation with time limit: "
			f"{self.time_limit_minutes_validation} minutes",
		)
		
		time_limit_seconds: t.Optional[int] = None
		if self.time_limit_minutes_validation:
			time_limit_seconds = self.time_limit_minutes_validation * 60
		
		timer = Stopwatch()
		timer.start()
		candidates = PatchCandidate.load_all(self.patch_candidates_path)
		# candidates = PatchCandidate.rank(candidates, self.localization_path)
		evaluations: t.List[PatchEvaluation] = []
		num_repairs_found = 0
		
		analyze_timer = Stopwatch()
		analyzes: t.List[AnalyzeCandidate] = []
		
		# rebuild the whole project once before using incremental builds for each patch
		# don't bother rebuilding if we don't use additional sanitizer flags
		should_rebuild = self.sanitizer_flags or self.rebuild_for_validation
		should_rebuild = should_rebuild or not os.path.exists(self.compile_commands_path)
		if should_rebuild:
			self.rebuild(record_compile_commands=False)
		
		for candidate in candidates:
			if time_limit_seconds and timer.duration >= time_limit_seconds:
				logger.info("reached candidate patch evaluation time limit")
				break
			
			if self.acceptable_patch_limit and num_repairs_found >= self.acceptable_patch_limit:
				logger.info(f"reached acceptable patch limit ({self.acceptable_patch_limit})")
				break
			
			outcome = self.evaluate(candidate)
			evaluations.append(outcome)
			if outcome:
				logger.info(f"saving successful patch #{candidate.id_}...")
				num_repairs_found += 1
				patch_filename = f"{candidate.id_}.diff"
				patch_filename = os.path.join(self.patches_directory, patch_filename)
				candidate.write(patch_filename)
				isrepair = True
				if self.should_terminate_early:
					logger.info("stopping search: patch was found")
					break
		if not isrepair:
			analyze_timer.start()
			# 如果没有找到修复方案，那么就对这些补丁重新分析，生成新的报告
			# 如果evaluations中的元素超过50个，取前50个
			if len(evaluations) > 20:
				evaluations = evaluations[:20]
			for evaluation in evaluations:
				if evaluation.compiles:
					analyze_result = self.analyze_for_guide(
						PatchCandidate(
							id_=evaluation.patch_id,
							location=evaluation.location,
							diff=evaluation.candidate_diff,
						)
					)
				else:
					analyze_result = AnalyzeCandidate.failed_to_compile(
						id_=evaluation.patch_id,
						location=evaluation.location,
						diff=evaluation.candidate_diff,
						compile_time_seconds=0.0,
						analyze_time_seconds=0.0,
						impact_lines=-1,
						vulnerability_type='',
						localization_result=[],  # FIXME this should be the localization result
					)
				analyzes.append(analyze_result)
		# print("Analysis_For_Guide:{}".format(analyzes))
		return ValidationReport(
			duration_seconds=timer.duration,
			evaluations=evaluations,
		), isrepair, AnalyzeForGuideReport(
			duration_seconds=analyze_timer.duration,
			analyze=analyzes,
		)
	
	def analyze_for_guide(
			self,
			candidate: PatchCandidate
	) -> AnalyzeCandidate:
		"""If there is no patch that can repair that vulnerability, then we need to reanalyze the localization file"""
		logger.info(f"reanalyzing candidate patch: #{candidate.id_}:\n{candidate.diff}")
		timer_compiler = Stopwatch()
		timer_compiler.start()
		average: float = 0.0
		
		timer_analyze = Stopwatch()
		vulnerability_type: str = ''
		localization_json: t.List = []
		try:
			candidate.apply()
			
			try:
				self.rebuild(prebuild=False, clean=False, record_compile_commands=False)
			except subprocess.CalledProcessError:
				logger.info(f"candidate patch #{candidate.id_} failed to compile")
				timer_compiler.stop()
				return AnalyzeCandidate.failed_to_compile(
					id_=candidate.id_,
					location=candidate.location,
					diff=candidate.diff,
					compile_time_seconds=timer_compiler.duration,
					analyze_time_seconds=0.0,
					impact_lines=-1,
					vulnerability_type='',
					localization_result=[],
				)
			# 重新分析
			if self.analysis_results_exist():
				shutil.rmtree(self.analysis_directory)
			# with Stopwatch() as timer_analyze:
			try:
				timer_analyze.start()
				self.analyze()
			except (AnalyzerTimedOut, AnalyzerCrashed) as e:
				logger.info(f"analysis failed for candidate patch #{candidate.id_}: {e}")
				return AnalyzeCandidate.failed_to_analyze(
					id_=candidate.id_,
					location=candidate.location,
					diff=candidate.diff,
					compile_time_seconds=timer_compiler.duration,
					analyze_time_seconds=timer_analyze.duration,
					impact_lines=-1,
					vulnerability_type='',
					localization_result=[],
				)
			# # 基于污点轨迹的排序方式
			# if os.path.exists(self.analysis_directory):
			#     if os.path.exists(os.path.join(self.analysis_directory, "klee-out-concrete-0", 'taint.log')):
			#         with open(os.path.join(self.analysis_directory, "klee-out-concrete-0", 'taint.log')) as f:
			#             readline = f.readline()
			#             average = float(len(readline))
			#     if os.path.exists(os.path.join(self.analysis_directory, "klee-out-taint-0", 'taint.log')):
			#         with open(os.path.join(self.analysis_directory, "klee-out-taint-0", 'taint.log')) as f:
			#             readline = f.readline()
			#             average = float(len(readline))
			
			# 基于分支覆盖的排序方式
			readline = []
			if os.path.exists(self.analysis_directory):
				if os.path.exists(os.path.join(self.analysis_directory, "klee-out-concrete-0", 'taint.log')):
					with open(os.path.join(self.analysis_directory, "klee-out-concrete-0", 'taint.log')) as f:
						readline = f.readline()
				elif os.path.exists(os.path.join(self.analysis_directory, "klee-out-taint-0", 'taint.log')):
					with open(os.path.join(self.analysis_directory, "klee-out-taint-0", 'taint.log')) as f:
						readline = f.readline()
				if not readline:
					average = 0.0
				dict_path_line = { }
				for line in readline:
					if line.startswith("KLEE: TaintTrack: ") and '/data/vulnloc' in line:
						line = line[len("KLEE: TaintTrack: "):]
						parts = line.split(":")
						if len(parts) >= 3:
							file_path = parts[0].strip()
							line_number = parts[1].strip()
							if line_number not in dict_path_line:
								dict_path_line[file_path] = [line_number]
							else:
								dict_path_line[file_path].append(line_number)
				
				# dict_path_line中的键代表文件位置，值代表污点分析执行到的行号，请根据该字典，给出分支覆盖值。
				def calculate_branch_coverage(dict_path_line):
					"""
					Calculate branch coverage based on impacted lines and source code.

					Args:
						dict_path_line (dict): Dictionary with file paths as keys and impacted lines as values.

					Returns:
						float: Branch coverage percentage.
					"""
					total_branches = 0
					covered_branches = 0
					
					for file_path, lines in dict_path_line.items():
						try:
							# Step 1: Read the source code from the file
							with open(file_path, 'r') as source_file:
								source_code = source_file.read()
							
							# Step 2: Extract all branches using regex
							branch_pattern = re.compile(r"if\s*\(.*?\)|else\s*|switch\s*\(.*?\)|case\s+.*?:")
							all_branches = branch_pattern.findall(source_code)
							total_branches += len(all_branches)
							
							# Step 3: Match impacted lines to branches
							impacted_lines = set(map(int, lines))  # Convert line numbers to integers
							for line in impacted_lines:
								# Check if the impacted line corresponds to a branch (approximation)
								for branch in all_branches:
									if f"if" in branch or f"else" in branch or f"case" in branch or f"switch" in branch:
										covered_branches += 1
										break  # Avoid double counting
						
						except FileNotFoundError:
							print(f"File not found: {file_path}")
							continue
					
					# Step 4: Calculate coverage
					coverage = (covered_branches / total_branches) * 100 if total_branches > 0 else 0
					return coverage
				
				average = float(calculate_branch_coverage(dict_path_line))
			
			# # 基于约束的排序方式
			# if os.path.exists(self.localization_path):
			#     with open(self.localization_path, 'r', encoding='utf-8') as f:
			#         localization_json = json.loads(f.read())
			#         total_impact_line = []
			#         for i in localization_json:
			#             impact_line = set()
			#             for j in i['variables']:
			#                 impact_line.add(j['line'])
			#             total_impact_line.append(len(list(impact_line)))
			#         average = sum(total_impact_line) / len(total_impact_line)
			
			# # 基于AST差异的排序方式
			# average = candidate.calculate_AST_difference()
			
			# # 基于余弦相似度的排序方式
			# average = candidate.calculate_cosine_similarity()
			
			# 获取定位结果
			if os.path.exists(self.localization_path):
				with open(self.localization_path, 'r', encoding='utf-8') as f:
					localization_json = json.loads(f.read())
			if os.path.exists(self.analysis_path):
				with open(self.analysis_path, 'r', encoding='utf-8') as f:
					analysis_json = json.loads(f.read())
					vulnerability_type = analysis_json['analysis_output'][0]['bug_type']
		
		finally:
			candidate.revert()
			if self.analysis_results_exist():
				shutil.rmtree(self.analysis_directory)
			return AnalyzeCandidate.analyze_report(
				id_=candidate.id_,
				location=candidate.location,
				diff=candidate.diff,
				compile_time_seconds=timer_compiler.duration,
				analyze_time_seconds=timer_analyze.duration,
				impact_lines=average,
				vulnerability_type=vulnerability_type,
				localization_result=localization_json,
			)
	
	def evaluate(
			self,
			candidate: PatchCandidate
	) -> PatchEvaluation:
		"""Evaluates a candidate repair and returns :code:`True` if it passes all tests."""
		logger.info(f"evaluating candidate patch #{candidate.id_}:\n{candidate.diff}")
		timer_compile = Stopwatch()
		timer_compile.start()
		try:
			candidate.apply()
			try:
				self.rebuild(prebuild=False, clean=False, record_compile_commands=False)
			except subprocess.CalledProcessError:
				logger.info(f"candidate patch #{candidate.id_} failed to compile")
				return PatchEvaluation.failed_to_compile(candidate, timer_compile.duration)
			timer_compile.stop()
			
			# run both the proof of exploit and the fuzzer-generated tests
			timer_tests = Stopwatch()
			timer_tests.start()
			all_tests: t.Sequence[Test] = [self.crash_test] + self.fuzzer_tests
			tests_passed: t.List[Test] = []
			tests_failed: t.List[Test] = []
			test_outcomes: t.List[TestOutcome] = []
			for test in all_tests:
				logger.debug(f"testing candidate #{candidate.id_} against test #{test.name}...")
				outcome = test.run(self.time_limit_seconds_single_test, halt_on_error=self.halt_on_error)
				test_outcomes.append(outcome)
				if outcome:
					logger.info(f"candidate #{candidate.id_} passes test #{test.name}")
					tests_passed.append(test)
				else:
					logger.info(f"candidate #{candidate.id_} fails test #{test.name}")
					tests_failed.append(test)
					return PatchEvaluation.failed_tests(
						candidate=candidate,
						compile_time_seconds=timer_compile.duration,
						test_time_seconds=timer_tests.duration,
						test_outcomes=test_outcomes,
						tests_passed=tests_passed,
						tests_failed=tests_failed,
					)
			
			timer_tests.stop()
			logger.info(f"repair found! candidate #{candidate.id_} passes all tests")
		except:
			logger.info(f"candidate patch #{candidate.id_} failed to compile")
			return PatchEvaluation.failed_to_compile(candidate, timer_compile.duration)
		finally:
			candidate.revert()
		
		return PatchEvaluation.repair_found(
			candidate=candidate,
			compile_time_seconds=timer_compile.duration,
			test_time_seconds=timer_tests.duration,
			test_outcomes=test_outcomes,
			tests_passed=tests_passed,
		)
	
	def repair(
			self
	) -> None:
		"""Performs end-to-end repair of this bug scenario."""
		report = Report()
		report_filename = os.path.join(self.directory, "report.json")
		timer_overall = Stopwatch()
		timer_overall.start()
		# if os.path.exists(f'/results/{self.subject}/{self.name}/report.json'):
		#     with open(f'/results/{self.subject}/{self.name}/report.json', 'r', encoding='utf-8') as f:
		#         report = json.loads(f.read())
		#         analyze_for_guide_report = report['analysis-for-guide']
		#         timer_iterative = Stopwatch()
		#         timer_iterative.start()
		#         self.iterative_repair(
		#             timer_iterative,
		#             analyze_for_guide_report,
		#             0,
		#             {}
		#         )
		#         report.iterative_repair = IterativeReport.build(
		#             duration_seconds=timer_iterative.duration,
		#             patch_iterative_path=self.patch_iterative_path
		#         )
		#         report['duration-minutes'] = timer_overall.duration / 60
		#         with open(report_filename, 'w', encoding='utf-8') as f_1:
		#             f_1.write(json.dumps(report, ensure_ascii=False, indent=4))
		# else:
		try:
			with Stopwatch() as timer_fuzz:  # noqa: F841
				self.fuzz()
				report.fuzzer = FuzzerReport.build(
					fuzzer_tests=self.fuzzer_tests,
					duration_seconds=timer_fuzz.duration,
				)
			
			with Stopwatch() as timer_analyze:
				self.analyze()
				# self.lint(fix=True)
				report.analysis = AnalysisReport.build(
					duration_seconds=timer_analyze.duration,
					analysis_directory=self.analysis_directory,
					localization_filename=self.localization_path,
					linter_filename='',
				)
			
			with Stopwatch() as timer_generate:
				self.generate()
				report.generation = GenerationReport.build(
					duration_seconds=timer_generate.duration,
					candidates_filename=self.patch_candidates_path,
				)
			
			report.validation, repair, report.analysis_for_guide = self.validate()
			if not repair:
				timer_iterative = Stopwatch()
				timer_iterative.start()
				self.iterative_repair(
					timer_iterative=timer_iterative,
					analysis_for_guide=report.analysis_for_guide.to_dict(),
					iteration=0,
					iterative_json={ }
				)
				report.iterative_repair = IterativeReport.build(
					duration_seconds=timer_iterative.duration,
					patch_iterative_path=self.patch_iterative_path
				)
		
		except CrashRepairException as error:
			report.error = error
			print(f"FATAL ERROR: {error}")
		finally:
			report.duration_seconds = timer_overall.duration
			report.save(report_filename)
	
	def iterative_repair(
			self,
			timer_iterative: Stopwatch,
			analysis_for_guide: dict,
			iteration: int,
			iterative_json: dict
	) -> None:
		"""If no patch repair the vulnerability, iteratively repairs the vulnerability scenario."""
		logger.info(f"iteratively repairing the vulnerability scenario")
		
		# 如果超时或超过预期迭代次数，直接返回失败结果
		if iteration >= 3 or timer_iterative.duration >= self.time_limit_minutes_iterative * 60:
			timer_iterative.stop()
			with open(self.patch_iterative_path, 'w', encoding='utf-8') as f:
				f.write(json.dumps(iterative_json, ensure_ascii=False, indent=4))
			return
		# 如果某个补丁的vulnerability_type与原始补丁不一致，直接删除
		if analysis_for_guide['vulnerability_type'] != self.vulnerability_type:
			iterative_json[analysis_for_guide['patch_id']] = {}
		# 对analysis_for_guide['candidates']中的每个元素，按照元素中的impact_lines字段的数字大小进行降序排序，在排序的时候删除impact_lines为0的元素
		# 如果所有补丁的impact_lines都为0，那么就随机选择5个补丁进行分析
		if len([i for i in analysis_for_guide['candidates'] if i['impact_lines'] != 0.0]) == 0:
			analysis_for_guide['candidates'] = analysis_for_guide['candidates'][:5]
		else:
			analysis_for_guide['candidates'] = sorted(
				analysis_for_guide['candidates'],
				key=lambda
					x: x['impact_lines'],
				reverse=True
			)
		total_candidates = {
			'summary':    {
				'num-candidates': 0
			},
			'candidates': []
		}
		# 生成新的候选补丁
		logger.info(f"generating candidate patches for iteration {iteration}...")
		iteration_analysis_report = t.List = []
		iteration_validation_report = t.List = []
		# 删掉analysis_for_guide['candidates']中每个i['localization_result']为[]的元素
		analysis_for_guide['candidates'] = [i for i in analysis_for_guide['candidates'] if i['localization_result']]
		# 如果analysis_for_guide['candidates']超过2个元素，按照impact_lines字段的数字大小进行降序排序，并只取前两个元素
		# analysis_for_guide['candidates'] = analysis_for_guide['candidates'][:2]
		if len(analysis_for_guide['candidates']) > 2:
			analysis_for_guide['candidates'] = sorted(
				analysis_for_guide['candidates'],
				key=lambda
					x: x['impact_lines'],
				reverse=True
			)[:2]
		for i in analysis_for_guide['candidates']:
			patch: PatchCandidate = PatchCandidate.from_dict(i)
			vulnerability_type: str = ''
			try:
				try:
					patch.apply()
				except subprocess.CalledProcessError:
					logger.info(f"candidate patch #{patch.id_} failed to compile")
					continue
				logger.info(f"applying candidate patch #{patch.id_}...")
				localization_result = i['localization_result']
				if localization_result:
					# 如果localization_result中元素数量超过3，则只取前三个元素
					if len(localization_result) >= 2:
						localization_result = localization_result[:2]
					logger.info(f"generating candidate patches for {patch.id_} in iteration {iteration}...")
					if os.path.exists(self.analysis_path):
						with open(self.analysis_path, 'r', encoding='utf-8') as f_analyse:
							analysis_json = json.loads(f_analyse.read())
							vulnerability_type = analysis_json['analysis_output'][0]['bug_type']
					generate_use_llms_from_localization_list(
						localization_result,
						vulnerability_type,
						self.patch_candidates_path
					)
					report_validation, repair, report_analysis_for_guide = self.validate()
					iteration_validation_report.append(report_validation.to_dict())
					iteration_analysis_report.append(report_analysis_for_guide.to_dict())
					logger.info(f"iteration_validation_report:#{iteration_validation_report}")
					logger.info(f"iteration_analysis_report:#{iteration_analysis_report}")
					if repair:
						logger.info(f"successful patch #{patch.id_} found")
						iterative_json["iteration_" + str(iteration)] = iteration_validation_report
						with open(self.patch_iterative_path, 'w', encoding='utf-8') as f_write:
							f_write.write(json.dumps(iterative_json, ensure_ascii=False, indent=4))
						return
			finally:
				try:
					patch.revert()
				except subprocess.CalledProcessError:
					logger.info(f"reverting candidate patch #{patch.id_} failed")
					continue
				logger.info(f"reverting candidate patch #{patch.id_}...")
		# 合并所有的候选补丁，包括上一轮得到的候选补丁
		patch_id = 0
		total_candidates['summary']['num-candidates'] = len(analysis_for_guide['candidates'])
		for candidate in analysis_for_guide['candidates']:
			candidate['id'] = patch_id
			total_candidates['candidates'].append(candidate)
			patch_id += 1
		for i in iteration_analysis_report:
			total_candidates['summary']['num-candidates'] += i['summary']['num-candidates']
			for j in i['candidates']:
				j['id'] = patch_id
				total_candidates['candidates'].append(j)
				patch_id += 1
		iterative_json["iteration_" + str(iteration)] = iteration_validation_report
		self.iterative_repair(timer_iterative, total_candidates, iteration + 1, iterative_json)
	
	def lint(
			self,
			fix: bool
	) -> bool:
		"""Lints the fix localization for this bug scenario.

		Arguments
		---------
		fix: bool
			Attempts to automatically fix any issues with the fix localization if :code:`True`

		Returns
		-------
		bool
			:code:`True` if OK; :code:`False` if bad.
		"""
		self.analyze()
		
		# ensure that compile_commands.json exists
		if not os.path.exists(self.compile_commands_path):
			self.rebuild(record_compile_commands=True)
		
		fix_flag = "--fix" if fix else ""
		implicated_files = self._determine_implicated_files()
		command = " ".join(
			(
				CRASHREPAIRLINT_PATH,
				fix_flag,
				"--output-to",
				self.linter_report_path,
				"--localization-filename",
				self.localization_path,
				"-p",
				self.compile_commands_path,
				" ".join(implicated_files),
				"-extra-arg=-I/opt/llvm11/lib/clang/11.1.0/include/",
			)
		)
		outcome = self.shell(command, cwd=self.source_directory, check_returncode=False)
		assert os.path.exists(self.linter_report_path)
		return outcome.returncode == 0
