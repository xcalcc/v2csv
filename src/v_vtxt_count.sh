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

#
# if you want to check the number of each issue grp, please open the code of line 27-37 and 66-76
# and it will lead to longer time usage 

input_file=$1
output_file=$2
argument_no=$#

if [ ${argument_no} -ne 1 ]  && [ ${argument_no} -ne 2 ]; then
  echo "Usage of count: v_vtxt_count.sh .v/.[vnlefm]txt"
  echo 'Usage of deduplicate: v_vtxt_count.sh .v/.[vnlefm]txt ${output_filename}.vtxt'
else
  file_suffix="${input_file##*.}"

  # count the defect info about .v file
  if [ "${file_suffix}" = "v" ]; then
    v_rule_list=`grep "\"rc\"" ${input_file} |awk -F '\"' '{print $4}' |sort |uniq`
    v_rule_list_num=`grep "\"rc\"" ${input_file} |awk -F '\"' '{print $4}' |sort |uniq |wc -l`
    v_total_issue_num=`grep "\"k\"\:" ${input_file} |wc -l`
    v_issuegrp_list=`grep "\"k\"\:" ${input_file} | awk -F '"' '{print $4}' | sort |uniq`
    v_issuegrp_num=`grep "\"k\"\:" ${input_file} |sort |uniq |wc -l`
    echo "The summary info of the file [ ${input_file} ]:"
    echo "  the total number of [ all defects ] is: ${v_total_issue_num}"
    echo "  the number of [ issue group ] is: ${v_issuegrp_num}"
    echo "  the number of [ defect type ] is: ${v_rule_list_num}"
    echo " "

    ## output the count number of each issue group
    #if [ ${v_issuegrp_num} -gt 0 ]; then
    #  echo "About the number of [ each issue grp ] as below:"
    #  for v_issuegrp in ${v_issuegrp_list}
    #  do
    #    issuegrp_number=0
    #    issuegrp_number=`grep "${v_issuegrp}" ${input_file} |wc -l`
    #    echo "  the number of issue group [ ${v_issuegrp} ] is: ${issuegrp_number}"
    #  done
    #fi
    #echo " "

    # output the count number of each defect rule
    if [ ${v_rule_list_num} -gt 0 ]; then
      echo "About the number of [ each defect type ] as below:"
      for v_rule in ${v_rule_list}
      do
        rule_number=0
	rule_number=`grep "\"rc\"" ${input_file} | grep ${v_rule} |wc -l`
	echo "  the number of [ ${v_rule} ] is: ${rule_number}"
      done
    fi

  # count the defect info about .vtxt file
  elif [[ "${file_suffix}" =~ "txt" ]]; then
    vtxt_blt_rule_list=`grep "\[Vul\]" ${input_file} |grep -v "\[RBC\]" |awk -F ']' '{print $7}' |awk -F '[' '{print $2}' |sort |uniq`
    vtxt_rbc_rule_list=`grep "\[Vul\]" ${input_file} |grep "\[RBC\]" |awk -F ']' '{print $10}' |awk -F '[' '{print $2}' |sort |uniq`
    vtxt_blt_rule_list_num=`grep "\[Vul\]" ${input_file} |grep -v "\[RBC\]" |awk -F ']' '{print $7}' |awk -F '[' '{print $2}' |sort |uniq |wc -l`
    vtxt_rbc_rule_list_num=`grep "\[Vul\]" ${input_file} |grep "\[RBC\]" |awk -F ']' '{print $10}' |awk -F '[' '{print $2}' |sort |uniq |wc -l`
    vtxt_rule_list_num=$((vtxt_blt_rule_list_num + vtxt_rbc_rule_list_num))
    vtxt_total_issue_num=`grep "\[Vul\]" ${input_file} |wc -l`
    vtxt_issuegrp_list=`grep "\[Vul\]" ${input_file} |awk -F '],' '{print $2}' |awk -F '[' '{print $2}' |sort |uniq`
    vtxt_issuegrp_num=`grep "\[Vul\]" ${input_file} |awk -F '],' '{print $2}' |sort |uniq |wc -l`
    echo "The summary info of the file [ ${input_file} ]: "
    echo "  the total number of [ all defect ] is: ${vtxt_total_issue_num}"
    echo "  the number of [ issue group ] is: ${vtxt_issuegrp_num}"
    echo "  the number of [ defect type ] is: ${vtxt_rule_list_num}"
    echo " "

    ## output the count number of each issue group
    #if [ ${vtxt_issuegrp_num} -gt 0 ]; then
    #  echo "About the number of [ each issue grp ] as below:"
    #  for vtxt_issuegrp in ${vtxt_issuegrp_list}
    #  do
    #    issuegrp_number=0
    #    issuegrp_number=`grep "${vtxt_issuegrp}" ${input_file} |wc -l`
    #    echo "  the number of issue group [ ${vtxt_issuegrp} ] is: ${issuegrp_number}"
    #  done
    #fi
    #echo " "

    # output the count number of each defect rule
    if [ ${vtxt_rule_list_num} -gt 0 ]; then
      echo "About the number of [ each defect type ] as below:"
      for vtxt_rule in ${vtxt_blt_rule_list}
      do
        rule_number=0
	rule_number=`grep "\[Vul\]" ${input_file} | grep ${vtxt_rule} |wc -l`
	echo "  the number of [ ${vtxt_rule} ] is: ${rule_number}"
      done
      for vtxt_rule in ${vtxt_rbc_rule_list}
      do
        rule_number=0
	rule_number=`grep "\[Vul\]" ${input_file} | grep ${vtxt_rule} |wc -l`
	echo "  the number of [ ${vtxt_rule} ] is: ${rule_number}"
      done
    fi

  # Deduplicate issue group and output results to specify file.
    if [ ${argument_no} -eq 2 ]; then
      deduplicate_grp=`grep "\[Vul\]" ${input_file} |awk -F ',' '{print $2}' |sort |uniq`
      fid_path_end=`grep -n "^]" ${input_file} | awk -F ':' '{print $1}'`

      if [ -f ${output_file} ]; then
        echo "The specify output file already exist, it maybe overwrite, please specify other file"
        exit 1
      else
        head -n ${fid_path_end} ${input_file} >> ${output_file}

        for grp in ${deduplicate_grp}
        do
	  # convert the special symbol, add \ befor it, avoid grep it fail
          grp=`echo "${grp}" | sed 's@\[@\\\[@g'`
          grp=`echo "${grp}" | sed 's@\]@\\\]@g'`
          grp=`echo "${grp}" | sed 's@\*@\\\*@g'`
	  grp_issue=`grep -R "${grp}" ${input_file} | head -1`
	  echo "grp is ${grp}"
	  echo "iss is ${grp_issue}"
          grep -R "${grp}" ${input_file} | head -1 >> ${output_file}
        done
      fi
    fi
  else
    echo "input file format is error, please input .v/.vtxt file."
    exit 1
  fi
fi


