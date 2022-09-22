#
# the repo of v2csf & vtxt_diff & vtxtreader & csvreader
#

# How to build:
  1. build Release version:(for product packaging)
     build command: make release

  2. build Debug version:(default is debug version for internal testing)
     build command: make

#
# the summary of all tools:
  the order of usage in product of all these tools is:
  
  vtxtreader --> vtxt_diff --> v2csf

  * vtxtreader merge all vtxtfiles to simplify the input of vtxt_diff.
  * the output of vtxt_diff as the input of v2csf.
  * the output of v2csf will be recorded into DB for webpage displaying.

# What is csvreader:
  csvreader is the tool for converting excel data to inc data.
  1. "excel data" is raw data of all rule info, and include the relationship of all rule's mapping.
  2. "inc data" is used when v2csf converting vtxt to csf file, v2csf will read these inc files to do rule info map.

  3. before run the cmd of csvreader, you need convert the xlsx file to csv file manually, and the xlsx file should include one sheet one time.
  4. Usage (the example of command):
  ./csvreader -p pathmsg.csv -b blt.csv -c cert.csv -m master.csv -o owasp.csv -w cwe.csv -e p3c.csv  -h 1  -d "," -C cert-info.csv -filto owasptoblt.csv -filtc cwetoblt.csv -filtO owasptocert.csv -filtC cwetocert.csv

# What is vtxtreader:
  vtxtreader is the tool to do merge all vtxt files. when scan mode is single file scan, scan engine will generate multi vtxt files, in order to make the follow-up task easier, merge all vtxt files as one mtxt is better method.

  1. Usage of merge all vtxt files directly:
  ./vtxtreader -merge *.vtxt
  2. Usage of merge all vtxt flies through one file that record all vtxt files' name, and this secnario is used when the number of vtxt files over the system limit:
  ./vtxtreader -fmerge ${file_name}

# What is vtxt_diff:
  vtxt_diff is the tool to do real diff, input is baseline and current scan result, output is n/l/e/ftxt file that represent new, fix, existing and line number change results.

  1. Usage: [The first scan(no DSR)]  ./vtxt_diff -c xvsa-xfa-dummy.mtxt 
  2. Usage: [The second scan(DSR)]    ./vtxt_diff -g git_diff_line_map -n xvsa-xfa-dummy.ntxt -l xvsa-xfa-dummy.ltxt -e xvsa-xfa-dummy.etxt -c xvsa-xfa-dummy.mtxt [ -d ${log_file_path} ]

  # when first scan it is no need do diff, so just input 

# what is v2csf:
  v2csf is the tool to covert diff results to csf file. input is the output of vtxt_diff, output is csf file that include all rule info, and this csf file will be used by POST_PROC service, all info will be written into DB.

  1. Usage: ./v2csf -n ${file}.ntxt -l ${file}.ltxt -f ${file}ftxt -e ${file}.etxt -h host_path_string [ -p log_file_path -d -i ]

  * the option -i : this option is uesed to ignore all issues from header files. if turn on this option, the csf file has no header files' results.
