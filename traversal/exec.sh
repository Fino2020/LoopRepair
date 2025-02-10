#!/bin/bash
#输入两个参数
PROGRAM=$1
SCENARIO=$2

bug_json_path=/data/vulnloc/${PROGRAM}/${SCENARIO}/bug.json
log_dir=/logs/${PROGRAM}/${SCENARIO}

python cli.py repair --time-limit-minutes-validation "${REPAIR_TIME_LIMIT:-45}" --time-limit-seconds-test "${TEST_TIME_LIMIT:-30}" --patch-limit "${PATCH_LIMIT:-10}" $bug_json_path --no-fuzzing --stop-early 2>&1 |& tee "${log_dir}/orchestrator.log"