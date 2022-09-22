#!/bin/bash

#  Copyright (C) 2019-2022 Xcalibyte (Shenzhen) Limited.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

SCRIPT_NAME=`basename $0`
SCRIPT_PATH=`pwd`
VTXTREADER=`realpath ./tool/vtxtreader`
VTXTDIFF=`realpath ./tool/vtxt_diff`
V2CSF=`realpath ./tool/v2csf`
XML2VTXT=`realpath ./tool/xml2vtxt`
STLFILT_INC=`realpath ../include/stlfilt.inc`

VTXTREADER_MERGE_OPT="-merge"
VTXTREADER_FILT_STL_OPT="-filts"
VTXTREADER_FILT_MAYBE_OPT="-maybe"
VTXTDIFF_CMD=""
V2CSF_CMD=""
PERFORMANCE_CMD=""

TEST_RESULT="test_results"
BASELINE="baseline"
CURRENT="current"
FIRST_SCAN="test_first_scan"
SECOND_SCAN="test_second_scan"
THIRD_SCAN="test_third_scan"
FOURTH_SCAN="test_fourth_scan"
MERGE_BASELINE_SCAN="merge_baseline_scan"
PUSH_SCAN="push_scan"
MERGE_SCAN="merge_scan"
MERGE_PROJECT_PATH1="/home/xc5/jenkinsslave/workspace/basic_dsr_scan_cd_0518c"
PUSH_PROJECT_PATH1="/home/xc5/jenkinsslave/workspace/basic_dsr_scan_ci_0518c"
MERGE_PROJECT_PATH2="/home/xc5/jenkinsslave/workspace/basic_dsr_scan_cd_0608a"
PUSH_PROJECT_PATH2="/home/xc5/jenkinsslave/workspace/basic_dsr_scan_ci_0608a"
MERGE_PROJECT_PATH3="/home/xc5/jenkinsslave/workspace/basic_dsr_scan_cd_0608b"
PUSH_PROJECT_PATH3="/home/xc5/jenkinsslave/workspace/basic_dsr_scan_ci_0608b"
MERGE_PROJECT_PATH4="/home/xc5/jenkinsslave/workspace/basic_dsr_scan_cd_0616a"
PUSH_PROJECT_PATH4="/home/xc5/jenkinsslave/workspace/basic_dsr_scan_ci_0616a"

NTXT="xvsa-xfa-dummy.ntxt"
FTXT="xvsa-xfa-dummy.ftxt"
ETXT="xvsa-xfa-dummy.etxt"
LTXT="xvsa-xfa-dummy.ltxt"
MTXT="xvsa-xfa-dummy.mtxt"
OTXT="xvsa-xfa-dummy.otxt"
VTXT="xvsa-xfa-dummy*.vtxt"
GIT_DIFF="git_diff_line_map"
CSF="xvsa-xfa-dummy.csf"
SOURCE_FILES_JSON="source_files.json"

TEST_VTXTREADER_MERGE="test_vtxtreader"
TEST_VTXTREADER_FILT="test_vtxtreader_filt"
TEST_VTXTREADER_FILT_MAYBE="${TEST_VTXTREADER_FILT}/test_filt_maybe"
TEST_VTXTREADER_FILT_STL="${TEST_VTXTREADER_FILT}/test_filt_stl"
TEST_VTXTDIFF="test_vtxtdiff"
TEST_V2CSF="test_v2csf"
TEST_XML2VTXT="test_xml2vtxt"
TEST_PERFORMANCE="test_performance"

function usage()
{
  echo "Usage:"
  echo "  bash ${SCRIPT_NAME} [OPTION]"
  echo "  "
  echo "OPTION:"
  echo "  -all        :  test all functions include merge, dsr, v2csf and performance"
  echo "  -vtxtreader :  test the merge and filter functions of the tool named [vtxtreader]"
  echo "  -vtxtdiff   :  test the dsr function of the tool named [vtxt_diff]"
  echo "  -v2csf      :  test the functions of the tool named [v2csf]"
  echo "  -xml2vtxt   :  test the functions of the tool named [xml2vtxt]"
  echo "  -performance:  test the performance of merge, dsr, v2csf when vtxt is large"
  echo "  "
}

function test_vtxtreader()
{
  if [ ! -d "${TEST_RESULT}" ]; then
    mkdir ${SCRIPT_PATH}/${TEST_RESULT}
  fi

  # test vtxtreader merge function
  echo "*** Testing vtxtreader merge function:"
  cd ${SCRIPT_PATH}/${TEST_VTXTREADER_MERGE}
  TEST_FOLDER=`find -type d -name "test*"`
  for merge in ${TEST_FOLDER}
  do
    mkdir -p ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTREADER_MERGE}/${merge}
    cd ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTREADER_MERGE}/${merge}
    echo "  Run cmd: ${VTXTREADER} ${VTXTREADER_MERGE_OPT} ${SCRIPT_PATH}/${TEST_VTXTREADER_MERGE}/${merge}/${VTXT}"
    ${VTXTREADER} ${VTXTREADER_MERGE_OPT} ${SCRIPT_PATH}/${TEST_VTXTREADER_MERGE}/${merge}/${VTXT}
    if [ $? -ne 0 ]; then
      echo "  [vtxtreader merge] failed: ${SCRIPT_PATH}/${TEST_VTXTREADER_MERGE}/${merge}"
    else
      DIFF_RESULTS=`diff ${MTXT} ${SCRIPT_PATH}/${TEST_VTXTREADER_MERGE}/${merge}/${MTXT} |wc -l`
      if [ ${DIFF_RESULTS} -ne 0 ]; then
        echo "  The test of [${merge}] has difference with baseline, please check!"
        diff ${MTXT} ${SCRIPT_PATH}/${TEST_VTXTREADER_MERGE}/${merge}/${MTXT}
      fi
    fi
    echo " "
  done
  echo " "

  # test vtxtreader filter STL function
  echo "*** Testing vtxtreader filt STL function:"
    mkdir -p ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTREADER_FILT_STL}
    cd ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTREADER_FILT_STL}
    echo " Run cmd: ${VTXTREADER} -i ${SCRIPT_PATH}/${TEST_VTXTREADER_FILT_STL}/${VTXT} -o ${OTXT} ${VTXTREADER_FILT_STL_OPT} ${STLFILT_INC}"
    ${VTXTREADER} -i ${SCRIPT_PATH}/${TEST_VTXTREADER_FILT_STL}/${VTXT} -o ${OTXT} ${VTXTREADER_FILT_STL_OPT} ${STLFILT_INC}
    if [ $? -ne 0 ]; then
      echo "  [vtxtreader filter STL] failed: ${TEST_VTXTREADER_FILT_STL}"
    else
      DIFF_RESULTS=`diff ${OTXT} ${SCRIPT_PATH}/${TEST_VTXTREADER_FILT_STL}/${OTXT} |wc -l`
      if [ ${DIFF_RESULTS} -ne 0 ]; then
        echo "  The test of [${TEST_VTXTREADER_FILT_STL}] has difference with baseline, please check!"
        diff ${OTXT} ${SCRIPT_PATH}/${TEST_VTXTREADER_FILT_STL}/${OTXT}
      fi
    fi
    echo " "
  echo " "

  # test vtxtreader filter maybe function
  echo "*** Testing vtxtreader filt maybe function:"
    mkdir -p ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTREADER_FILT_MAYBE}
    cd ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTREADER_FILT_MAYBE}
    echo "  Run cmd: ${VTXTREADER} -i ${SCRIPT_PATH}/${TEST_VTXTREADER_FILT_MAYBE}/${VTXT} -o ${OTXT} ${VTXTREADER_FILT_MAYBE_OPT}"
    ${VTXTREADER} -i ${SCRIPT_PATH}/${TEST_VTXTREADER_FILT_MAYBE}/${VTXT} -o ${OTXT} ${VTXTREADER_FILT_MAYBE_OPT}
    if [ $? -ne 0 ]; then
      echo "  [vtxtreader filter maybe] failed: ${SCRIPT_PATH}/${TEST_VTXTREADER_FILT_MAYBE}"
    else
      DIFF_RESULTS=`diff ${OTXT} ${SCRIPT_PATH}/${TEST_VTXTREADER_FILT_MAYBE}/${OTXT} |wc -l`
      if [ ${DIFF_RESULTS} -ne 0 ]; then
        echo "  The test of [${TEST_VTXTREADER_FILT_MAYBE}] has difference with baseline, please check!"
        diff ${OTXT} ${SCRIPT_PATH}/${TEST_VTXTREADER_FILT_MAYBE}/${OTXT}
      fi
    fi
    echo " "
  echo " "
}

function run_vtxtdiff()
{
  dsr_scan_folder=$1
  baseline_folder=$2
  current_folder=$3
  baseline_project_path=$4
  current_project_path=$5
  mkdir -p ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}
  cd ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}
  if [ ! -n "$baseline_project_path" ] || [ ! -n "$current_project_path" ]; then
    echo "  Run cmd: ${VTXTDIFF} -g ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${GIT_DIFF} -n ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${NTXT} -l ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${LTXT} -e ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${ETXT} -c ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${MTXT} -d `pwd`"
    ${VTXTDIFF} -g ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${GIT_DIFF} -n ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${NTXT} -l ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${LTXT} -e ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${ETXT} -c ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${MTXT} -d `pwd`
  else
    echo "  Run cmd: ${VTXTDIFF} -g ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${GIT_DIFF} -n ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${NTXT} -l ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${LTXT} -e ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${ETXT} -c ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${MTXT} -p ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${SOURCE_FILES_JSON} -b ${baseline_project_path} -o ${current_project_path} -d `pwd`"
    ${VTXTDIFF} -g ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${GIT_DIFF} -n ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${NTXT} -l ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${LTXT} -e ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${baseline_folder}/${ETXT} -c ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${MTXT} -p ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${SOURCE_FILES_JSON} -b ${baseline_project_path} -o ${current_project_path} -d `pwd`
  fi
  if [ $? -ne 0 ]; then
    echo "  [vtxt_diff] failed: ${dsr_scan_folder} ${baseline_folder} ${current_folder}"
  else
    DIFF_NTXT_RESULTS=`diff ${NTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${NTXT} |wc -l`
    DIFF_LTXT_RESULTS=`diff ${LTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${LTXT} |wc -l`
    DIFF_ETXT_RESULTS=`diff ${ETXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${ETXT} |wc -l`
    DIFF_FTXT_RESULTS=`diff ${FTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${FTXT} |wc -l`
    if [ ${DIFF_NTXT_RESULTS} -ne 0 ]; then
      echo "  The test of [${dsr_scan_folder}] ntxt has difference with baseline ${current_folder}, please check!"
      diff ${NTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${NTXT}
    fi
    if [ ${DIFF_LTXT_RESULTS} -ne 0 ]; then
      echo "  The test of [${dsr_scan_folder}] ltxt has difference with baseline ${current_folder}, please check!"
      diff ${LTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${LTXT}
    fi
    if [ ${DIFF_ETXT_RESULTS} -ne 0 ]; then
      echo "  The test of [${dsr_scan_folder}] etxt has difference with baseline ${current_folder}, please check!"
      diff ${ETXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${ETXT}
    fi
    if [ ${DIFF_FTXT_RESULTS} -ne 0 ]; then
      echo "  The test of [${dsr_scan_folder}] ftxt has difference with baseline ${current_folder}, please check!"
      diff ${FTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${current_folder}/${FTXT}
    fi
  fi
  echo " "
}

function test_push_merge_mixed_dsr_diff()
{
  dsr_scan_folder=$1
  push_dsr_scan_folder=$2
  merge_dsr_scan_folder=$3
  diff_results="push_merge_diff_results"
  mkdir -p ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${diff_results}
  cd ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTDIFF}/${dsr_scan_folder}
  ndiff_results="ndiff.txt"
  ldiff_results="ldiff.txt"
  ediff_results="ediff.txt"
  fdiff_results="fdiff.txt"
  diff ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${push_dsr_scan_folder}/${NTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${merge_dsr_scan_folder}/${NTXT} > ${diff_results}/${ndiff_results}
  diff ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${push_dsr_scan_folder}/${LTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${merge_dsr_scan_folder}/${LTXT} > ${diff_results}/${ldiff_results}
  diff ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${push_dsr_scan_folder}/${ETXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${merge_dsr_scan_folder}/${ETXT} > ${diff_results}/${ediff_results}
  diff ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${push_dsr_scan_folder}/${FTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${merge_dsr_scan_folder}/${FTXT} > ${diff_results}/${fdiff_results}
  final_diff_result=`diff -r ${diff_results} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${diff_results} | wc -l`
  if [ ${final_diff_result} -ne 0 ]; then
    echo "  The test of [${dsr_scan_folder}] final result has difference with baseline, please check!"
    diff -r ${diff_results} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr_scan_folder}/${diff_results}
  else
    echo "  The test of [${dsr_scan_folder}] final diff is ok!"
  fi
  echo " "
}

function test_vtxtdiff()
{
  if [ ! -d "${TEST_RESULT}" ]; then
    mkdir ${SCRIPT_PATH}/${TEST_RESULT}
  fi

  # TODO: need to refactor the test of vtxt_diff later to make add test cases and check test results more friendly
  echo "*** Testing vtxt_diff with push/merge dsr scan"
  push_merge_dsr_scan="test_push_merge_mixed_dsr_file_path"
  cd ${SCRIPT_PATH}/${TEST_VTXTDIFF}
  run_vtxtdiff $push_merge_dsr_scan $MERGE_BASELINE_SCAN $PUSH_SCAN $MERGE_PROJECT_PATH1 $PUSH_PROJECT_PATH1
  run_vtxtdiff $push_merge_dsr_scan $MERGE_BASELINE_SCAN $MERGE_SCAN $MERGE_PROJECT_PATH1 $MERGE_PROJECT_PATH1
  test_push_merge_mixed_dsr_diff $push_merge_dsr_scan $PUSH_SCAN $MERGE_SCAN

  push_merge_dsr_scan="test_new_issue_to_fix_issue"
  cd ${SCRIPT_PATH}/${TEST_VTXTDIFF}
  run_vtxtdiff $push_merge_dsr_scan $MERGE_BASELINE_SCAN $PUSH_SCAN $MERGE_PROJECT_PATH3 $PUSH_PROJECT_PATH3

  push_merge_dsr_scan="test_simple_linechange"
  cd ${SCRIPT_PATH}/${TEST_VTXTDIFF}
  run_vtxtdiff $push_merge_dsr_scan $MERGE_BASELINE_SCAN $PUSH_SCAN $MERGE_PROJECT_PATH4 $PUSH_PROJECT_PATH4

  echo "*** Testing vtxt_diff with mutiple dsr scan"
  declare -a multiple_dsr_scan_folders=(test_continuous_fix test_continuous_new test_new_issue_format)
  cd ${SCRIPT_PATH}/${TEST_VTXTDIFF}
  for dsr_scan_folder in "${multiple_dsr_scan_folders[@]}"
  do  
    run_vtxtdiff $dsr_scan_folder $FIRST_SCAN $SECOND_SCAN
    run_vtxtdiff $dsr_scan_folder $SECOND_SCAN $THIRD_SCAN
    run_vtxtdiff $dsr_scan_folder $THIRD_SCAN $FOURTH_SCAN
  done
  
  special_multiple_dsr_scan_folder="test_partial_scan_modify_one_file"
  run_vtxtdiff $special_multiple_dsr_scan_folder $FIRST_SCAN $SECOND_SCAN
  run_vtxtdiff $special_multiple_dsr_scan_folder $SECOND_SCAN $THIRD_SCAN

  echo "*** Testing vtxt_diff when second scan(DSR)"
  cd ${SCRIPT_PATH}/${TEST_VTXTDIFF}
  declare -a simple_dsr_scan_folders=(
    test_two_atsign_one_colon
    test_four_atsign_two_colon
    test_issue_check
    test_issue_path_node_change
    test_map_line_range
    test_customize_rule_line_change
    test_linechange_one
    test_fix_one
    test_three_atsign_one_colon
    #test_new_issues
    test_file_add
    test_new_one
    test_customize_rule_fix
    test_four_atsign_one_colon
    #test_filename_overlapping
    test_one_atsign_one_colon
    test_three_atsign_two_colon
    test_customize_rule_new
    test_trancate_var_path
    test_partial_scan_blank_line
    test_partial_scan_del_file
    test_push_merge_mixed_file_path
  )
  # cases in this array need to test with  -p, -b, -o option
  declare -a simple_cases_need_new_options=(test_push_merge_mixed_file_path)
  echo "===case test_new_issues has been skipped currently since its raw data(file number in issue) has some problems."
  echo "===case test_filename_overlapping has been skipped currently since its raw data(file path) has some problems."
  for dsr2 in "${simple_dsr_scan_folders[@]}"
  do
    mkdir -p ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTDIFF}/${dsr2}
    cd ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_VTXTDIFF}/${dsr2}
    if [[ " ${simple_cases_need_new_options[*]} " =~ " ${dsr2} " ]]; then
      echo "  Run cmd: ${VTXTDIFF} -g ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${GIT_DIFF} -n ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${NTXT} -l ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${LTXT} -e ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${ETXT} -c ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${MTXT} -p ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${SOURCE_FILES_JSON} -b ${MERGE_PROJECT_PATH2} -o ${PUSH_PROJECT_PATH2} -d `pwd`"
      ${VTXTDIFF} -g ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${GIT_DIFF} -n ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${NTXT} -l ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${LTXT} -e ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${ETXT} -c ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${MTXT} -p ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${SOURCE_FILES_JSON} -b ${MERGE_PROJECT_PATH2} -o ${PUSH_PROJECT_PATH2} -d `pwd`
    else
      echo "  Run cmd: ${VTXTDIFF} -g ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${GIT_DIFF} -n ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${NTXT} -l ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${LTXT} -e ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${ETXT} -c ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${MTXT} -d `pwd`"
      ${VTXTDIFF} -g ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${GIT_DIFF} -n ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${NTXT} -l ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${LTXT} -e ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${BASELINE}/${ETXT} -c ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${MTXT} -d `pwd`
    fi
    if [ $? -ne 0 ]; then
      echo "  [vtxt_diff] failed: ${dsr2}"
    else
      DIFF_NTXT_RESULTS=`diff ${NTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${NTXT} |wc -l`
      DIFF_LTXT_RESULTS=`diff ${LTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${LTXT} |wc -l`
      DIFF_ETXT_RESULTS=`diff ${ETXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${ETXT} |wc -l`
      DIFF_FTXT_RESULTS=`diff ${FTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${FTXT} |wc -l`
      if [ ${DIFF_NTXT_RESULTS} -ne 0 ]; then
        echo "  The test of [${dsr2}] ntxt has difference with baseline, please check!"
        diff ${NTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${NTXT}
      fi
      if [ ${DIFF_LTXT_RESULTS} -ne 0 ]; then
        echo "  The test of [${dsr2}] ltxt has difference with baseline, please check!"
        diff ${LTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${LTXT}
      fi
      if [ ${DIFF_ETXT_RESULTS} -ne 0 ]; then
        echo "  The test of [${dsr2}] etxt has difference with baseline, please check!"
        diff ${ETXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${ETXT}
      fi
      if [ ${DIFF_FTXT_RESULTS} -ne 0 ]; then
        echo "  The test of [${dsr2}] ftxt has difference with baseline, please check!"
        diff ${FTXT} ${SCRIPT_PATH}/${TEST_VTXTDIFF}/${dsr2}/${CURRENT}/${FTXT}
      fi
    fi
    echo " "
  done
  echo " "
}

function test_v2csf()
{
  if [ ! -d "${TEST_RESULT}" ]; then
    mkdir ${SCRIPT_PATH}/${TEST_RESULT}
  fi

  # test v2csf
  echo "*** Testing v2csf functions"
  cd ${SCRIPT_PATH}/${TEST_V2CSF}
  TEST_FOLDER=`find * -type d -name "test*"`
  for v2csf in ${TEST_FOLDER}
  do
    mkdir -p ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}
    cp ${SCRIPT_PATH}/${TEST_V2CSF}/${v2csf}/${NTXT} ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}
    cp ${SCRIPT_PATH}/${TEST_V2CSF}/${v2csf}/${LTXT} ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}
    cp ${SCRIPT_PATH}/${TEST_V2CSF}/${v2csf}/${ETXT} ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}
    cp ${SCRIPT_PATH}/${TEST_V2CSF}/${v2csf}/${FTXT} ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}
    cd ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}
    echo "  Run cmd: ${V2CSF} -n ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}/${NTXT} -l ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}/${LTXT} -e ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}/${ETXT} -f ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}/${FTXT} -h /home"
    ${V2CSF} -n ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}/${NTXT} -l ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}/${LTXT} -e ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}/${ETXT} -f ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_V2CSF}/${v2csf}/${FTXT} -h /home
    if [ $? -ne 0 ]; then
      echo "  [v2csf] failed: ${v2csf}"
    else
      CURR_CSF_RESULTS=`ls -l ${CSF} |awk -F ' ' '{print $5}'`
      BASE_CSF_RESULTS=`ls -l ${SCRIPT_PATH}/${TEST_V2CSF}/${v2csf}/${CSF} |awk -F ' ' '{print $5}'`
      if [[ -n ${CURR_CSF_RESULTS} ]] && [[ -n ${BASE_CSF_RESULTS} ]]; then
        if [ ${CURR_CSF_RESULTS} -ne ${BASE_CSF_RESULTS} ]; then
          echo "  The test of [${v2csf}] has difference with baseline, please check!"
          echo "  The size of current csf is ${CURR_CSF_RESULTS}"
	  echo "  The size of baseline csf is ${BASE_CSF_RESULTS}"
        fi
      fi
    fi
    echo " "
  done
  echo " "
}

function test_xml2vtxt()
{
  if [ ! -d "${TEST_RESULT}" ]; then
    mkdir ${SCRIPT_PATH}/${TEST_RESULT}
  fi

  xml_filename="result.xml"
  vtxt_filename="result.vtxt"
  magic_number="DKnKu"
  # test xml2vtxt
  echo "*** Testing xml2vtxt functions"
  cd ${SCRIPT_PATH}/${TEST_XML2VTXT}
  TEST_FOLDER=`find * -type d -name "test*"`
  for test_case in ${TEST_FOLDER}
  do
    mkdir -p ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_XML2VTXT}/${test_case}
    cp ${SCRIPT_PATH}/${TEST_XML2VTXT}/${test_case}/${xml_filename} ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_XML2VTXT}/${test_case}
    cd ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_XML2VTXT}/${test_case}
    echo "  Run cmd: ${XML2VTXT} -i ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_XML2VTXT}/${test_case}/${xml_filename} -magic ${magic_number}"
    ${XML2VTXT} -i ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_XML2VTXT}/${test_case}/${xml_filename} -magic ${magic_number}
    if [ $? -ne 0 ]; then
      echo "  [xml2vtxt] failed: ${test_case}"
    else
      DIFF_RESULTS=`diff ${vtxt_filename} ${SCRIPT_PATH}/${TEST_XML2VTXT}/${test_case}/${vtxt_filename} |wc -l`
      if [ ${DIFF_RESULTS} -ne 0 ]; then
        echo "  The test of [${test_case}] has difference with baseline, please check!"
        diff ${vtxt_filename} ${SCRIPT_PATH}/${TEST_XML2VTXT}/${test_case}/${vtxt_filename}
      fi
    fi
    echo " "
  done
  echo " "
}

function test_performance()
{
  if [ ! -d "${TEST_RESULT}" ]; then
    mkdir ${SCRIPT_PATH}/${TEST_RESULT}
  fi

  # test performance
  echo "*** Testing v2csf performance"
  cd ${SCRIPT_PATH}/${TEST_PERFORMANCE}
  TEST_FOLDER=`find -type d -name "test*"`
  for performance in ${TEST_PERFORMANCE}
  do
    mkdir -p ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_PERFORMANCE}/${performance}
    cd ${SCRIPT_PATH}/${TEST_RESULT}/${TEST_PERFORMANCE}/${performance}
    echo "  Run cmd: time ${V2CSF} -n ${SCRIPT_PATH}/${TEST_PERFORMANCE}/${performance}/${VTXT} -h /home"
    time ${V2CSF} -n ${SCRIPT_PATH}/${TEST_PERFORMANCE}/${performance}/${VTXT} -h /home > test_time_usage
    if [ $? -ne 0 ]; then
      echo "  [v2csf performance test] failed: ${performance}"
    else
      BASE_TIME_USAGE=${SCRIPT_PATH}/${TEST_PERFORMANCE}/${performance}/baseline_time_usage
      if [ -f ${BASE_TIME_USAGE} ]; then
        echo "  The baseline time usage of v2csf is:"
	cat ${BASE_TIME_USAGE}
	echo "  The current time usage of v2csf is:"
	cat test_time_usage
      fi
    fi
    echo " "
  done
  echo " "
}

if [ $# -ne 1 ]; then
  usage
  exit 1
else
  case "$1" in
    -all)
      test_vtxtreader
      test_vtxtdiff
      test_v2csf
      test_xml2vtxt
      test_performance
      ;;
    -vtxtreader)
      test_vtxtreader
      ;;
    -vtxtdiff)
      test_vtxtdiff
      ;;
    -v2csf)
      test_v2csf
      ;;
    -xml2vtxt)
      test_xml2vtxt
      ;;
    -performance)
      test_performance
      ;;
  esac
fi


