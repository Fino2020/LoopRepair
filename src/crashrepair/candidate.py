# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import typing as t
from datetime import datetime
from subprocess import DEVNULL

import attrs
from loguru import logger

from location import Location

if t.TYPE_CHECKING:
    from test import Test, TestOutcome


@attrs.define(auto_attribs=True, slots=True)
class PatchEvaluation:
    patch_id: int
    is_repair: bool
    compiles: bool
    candidate_diff: str
    location: Location
    compile_time_seconds: float
    test_time_seconds: t.Optional[float] = attrs.field(default=None)
    tests_passed: t.Collection[Test] = attrs.field(factory=list)
    tests_failed: t.Collection[Test] = attrs.field(factory=list)
    test_outcomes: t.Collection[TestOutcome] = attrs.field(factory=list)

    @classmethod
    def failed_to_compile(
            cls,
            candidate: PatchCandidate,
            time_taken: float,
    ) -> PatchEvaluation:
        return PatchEvaluation(
            patch_id=candidate.id_,
            candidate_diff=candidate.diff,
            location=candidate.location,
            is_repair=False,
            compiles=False,
            compile_time_seconds=time_taken,
        )

    @classmethod
    def failed_tests(
            cls,
            candidate: PatchCandidate,
            compile_time_seconds: float,
            test_time_seconds: float,
            tests_passed: t.Collection[Test],
            tests_failed: t.Collection[Test],
            test_outcomes: t.Collection[TestOutcome],
    ) -> PatchEvaluation:
        return PatchEvaluation(
            patch_id=candidate.id_,
            is_repair=False,
            compiles=True,
            candidate_diff=candidate.diff,
            location=candidate.location,
            compile_time_seconds=compile_time_seconds,
            test_time_seconds=test_time_seconds,
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            test_outcomes=test_outcomes,
        )

    @classmethod
    def repair_found(
            cls,
            candidate: PatchCandidate,
            compile_time_seconds: float,
            test_time_seconds: float,
            tests_passed: t.Collection[Test],
            test_outcomes: t.Collection[TestOutcome],
    ) -> PatchEvaluation:
        return PatchEvaluation(
            patch_id=candidate.id_,
            is_repair=True,
            compiles=True,
            candidate_diff=candidate.diff,
            location=candidate.location,
            compile_time_seconds=compile_time_seconds,
            test_time_seconds=test_time_seconds,
            tests_passed=tests_passed,
            test_outcomes=test_outcomes,
        )

    def to_dict(self) -> t.Dict[str, t.Any]:
        total_time_seconds = self.compile_time_seconds + (self.test_time_seconds or 0)
        return {
            "patch-id": self.patch_id,
            "is-repair": self.is_repair,
            "candidate-diff": self.candidate_diff,
            "location": str(self.location),
            "compiles": self.compiles,
            "time-taken-seconds": {
                "total": total_time_seconds,
                "compile": self.compile_time_seconds,
                "tests": self.test_time_seconds,
            },
            "tests": {
                "executed": len(self.tests_passed) + len(self.tests_failed),
                "passed": len(self.tests_passed),
                "failed": len(self.tests_failed),
                "outcomes": [outcome.to_dict() for outcome in self.test_outcomes],
            },
        }

    def __bool__(self) -> bool:
        return self.is_repair


@attrs.define(auto_attribs=True, slots=True)
class AnalyzeCandidate:
    id_: int
    location: Location
    diff: str
    impact_lines: float
    compile_time_seconds: float
    analyze_time_seconds: float
    vulnerability_type: str
    localization_result: t.List

    @classmethod
    def analyze_report(
            cls,
            id_: int,
            location: Location,
            diff: str,
            compile_time_seconds: float,
            analyze_time_seconds: float,
            impact_lines: float,
            vulnerability_type: str,
            localization_result: t.List
    ) -> AnalyzeCandidate:
        return AnalyzeCandidate(
            id_=id_,
            location=location,
            diff=diff,
            impact_lines=impact_lines,
            compile_time_seconds=compile_time_seconds,
            analyze_time_seconds=analyze_time_seconds,
            vulnerability_type=vulnerability_type,
            localization_result=localization_result
        )

    @classmethod
    def failed_to_analyze(
            cls,
            id_: int,
            location: Location,
            diff: str,
            compile_time_seconds: float,
            analyze_time_seconds: float,
            impact_lines: float,
            vulnerability_type: str,
            localization_result: t.List
    ) -> AnalyzeCandidate:
        return AnalyzeCandidate(
            id_=id_,
            location=location,
            diff=diff,
            impact_lines=-1,
            compile_time_seconds=compile_time_seconds,
            analyze_time_seconds=analyze_time_seconds,
            vulnerability_type='',
            localization_result=localization_result
        )

    @classmethod
    def failed_to_compile(
            cls,
            id_: int,
            location: Location,
            diff: str,
            compile_time_seconds: float,
            analyze_time_seconds: float,
            impact_lines: float,
            vulnerability_type: str,
            localization_result: t.List
    ) -> AnalyzeCandidate:
        return AnalyzeCandidate(
            id_=id_,
            location=location,
            diff=diff,
            impact_lines=-1,
            compile_time_seconds=compile_time_seconds,
            analyze_time_seconds=analyze_time_seconds,
            vulnerability_type='',
            localization_result=localization_result
        )

    def to_dict(self) -> t.Dict[str, t.Any]:
        return {
            "id": self.id_,
            "location": str(self.location),
            "diff": self.diff,
            "impact_lines": self.impact_lines,
            "vulnerability_type": self.vulnerability_type,
            'localization_result': self.localization_result,
            "time-taken-seconds": {
                "compile": self.compile_time_seconds,
                "analyze": self.analyze_time_seconds,
            },
        }


@attrs.define(auto_attribs=True, slots=True)
class PatchCandidate:
    id_: int
    location: Location
    diff: str

    @classmethod
    def rank(
            cls,
            candidates: t.Collection[PatchCandidate],
            localization_filename: str,
    ) -> t.Sequence[PatchCandidate]:
        """Sorts a list of patches by their estimated likelihood of correctness."""
        location_to_crash_distance: t.Dict[str, int] = {}
        with open(localization_filename, "r") as fh:
            localization = json.load(fh)
        for entry in localization:
            location = entry["location"]
            distance = entry["distance"]
            if location in location_to_crash_distance:
                logger.warning(f"found duplicate fix location: {location}")
            else:
                location_to_crash_distance[location] = distance

        def score(candidate: PatchCandidate) -> float:
            distance = location_to_crash_distance[str(candidate.location)]
            return float(distance)

        # for now, we simply rank based on crash distance
        return sorted(candidates, key=score)

    @classmethod
    def load_all(cls, filename: str) -> t.Collection[PatchCandidate]:
        """Loads a set of patch candidates from disk."""
        with open(filename, "r") as fh:
            jsn = json.load(fh)
        candidates = [cls.from_dict(candidate_dict) for candidate_dict in jsn]
        # exclude any patches with an empty diff (workaround to #15)
        candidates = [candidate for candidate in candidates if candidate.diff]
        return candidates

    @classmethod
    def from_dict(cls, dict_: t.Dict[str, t.Any]) -> PatchCandidate:
        return PatchCandidate(
            id_=dict_["id"],
            location=Location.from_string(dict_["location"]),
            diff=dict_["diff"],
        )

    def to_dict(self) -> t.Dict[str, t.Any]:
        return {
            "id": self.id_,
            "location": str(self.location),
            "diff": self.diff,
        }

    @property
    def filename(self) -> str:
        """The name of the source file to which this patch is applied."""
        return self.location.filename

    def write(self, filename: str) -> None:
        """Writes the patch encoded to a unified diff text file."""
        directory = os.path.dirname(filename)
        os.makedirs(directory, exist_ok=True)

        modification_time_string = datetime.now().isoformat()
        header_from_line = f"--- {self.filename} {modification_time_string}\n"
        header_to_line = f"+++ {self.filename} {modification_time_string}\n"

        with open(filename, "w") as fh:
            fh.write(header_from_line)
            fh.write(header_to_line)
            fh.write(self.diff)

    def apply(self) -> None:
        """Applies this patch to the program."""
        logger.trace("applying candidate patch...")
        # 创建一个临时文件，文件名以 .diff 结尾，并将文件路径存储在 patch_filename 变量中。
        _, patch_filename = tempfile.mkstemp(suffix=".diff")
        # 将补丁内容写入刚刚创建的临时文件中。
        self.write(patch_filename)
        # 构建一个 patch 命令，用于将补丁文件应用到目标文件上。{self.filename} 是目标文件，{patch_filename} 是补丁文件。
        command = f"patch -u {self.filename} {patch_filename}"
        try:
            subprocess.check_call(
                command,
                stdin=DEVNULL,
                stdout=DEVNULL,
                stderr=DEVNULL,
                shell=True,
            )
        finally:
            os.remove(patch_filename)
        logger.trace("applied candidate patch")

    def revert(self) -> None:
        """Reverts the changes introduced by this patch."""
        logger.trace("reverting candidate patch...")
        _, patch_filename = tempfile.mkstemp(suffix=".diff")
        self.write(patch_filename)
        command = f"patch -R -u {self.filename} {patch_filename}"
        try:
            subprocess.check_call(
                command,
                stdin=DEVNULL,
                stdout=DEVNULL,
                stderr=DEVNULL,
                shell=True,
            )
        finally:
            os.remove(patch_filename)
        logger.trace("reverted candidate patch")
