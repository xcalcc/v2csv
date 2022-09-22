//-*-c++-*-

/*
   Copyright (C) 2019-2022 Xcalibyte (Shenzhen) Limited.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <errno.h>
#include <assert.h>

#include "commondefs.h"
#include "rule_desc_blt.h"
#include "rule_desc_std.h"  // CERT standard rules info (C, C++, Java)

#include "vtxtlib.h"
#include "vtxt_diff.h"
#include "vtxt_report.h"
#include "filepath.h"

using namespace std;

// =============================================================================
//
// Unified Print Interface for all internal data structures
//
// =============================================================================
void
Manage::Print(FILE *fp)
{
  printf("who am I\n");
}

void
LINEMAP::Print(FILE *fp)
{
  fprintf(fp, "{Old_ln: %d, New_ln: %d}\n", Old_ln(), New_ln());
}


void
MAGIC_PAIR::Print(FILE *fp)
{
  fprintf(fp, "{Ln_limit: %d, Ln_change: %d, Operation: %s}\n",
          Ln_limit(), Ln_change(), (Operation()==OPER_INSERT) ?  "+" : "-");
  fprintf(fp, "------------------------------------------------------------\n");
}


void
LINE_MATCH::Print(FILE *fp)
{
  LP_VEC::iterator iter;
  fprintf(fp, "LINE_MATCH Trace for File:%s; File_id:%d :\n", Fname(), File_id());
  fprintf(fp, "------------------------------------------------------------\n");
  Magic().Print(fp);
  for (iter = Line_map().begin(); iter != Line_map().end(); ++iter) {
    iter->Print(fp);
  }
}


void
CHECKSUM_ISSUES::Print(FILE *fp)
{
  fprintf(fp, "{Checksum: 0x%lx, Issue: %s}\n", Checksum(), Issue());
}


void
FIND_MATCH::Print(FILE *fp)
{
  LM_VEC::iterator iter1;
  fprintf(fp, "%sLine_match dump\n%s", SEPARATOR_s, SEPARATOR_s);
  if (Lm_vec().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for (iter1 = Lm_vec().begin(); iter1 != Lm_vec().end(); ++iter1) {
      (*iter1)->Print(fp);
    }
  }

  FP_VEC::iterator iter;
  fprintf(fp, "%sCurrent Scan Fid Path\n%s", SEPARATOR_s, SEPARATOR_s);
  if (C_fid_path().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for ( iter = C_fid_path().begin(); iter != C_fid_path().end(); ++iter ) {
      iter->Print(fp);
    }
  }

#if 0
  fprintf(fp, "%sBaseline Scan Fid Path\n%s", SEPARATOR_s, SEPARATOR_s);
  if (B_fid_path().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for ( iter = B_fid_path().begin(); iter != B_fid_path().end(); ++iter ) {
      iter->Print(fp);
    }
  }
#endif

  CI_VEC::iterator iter2;
  fprintf(fp, "%sCurrent vtxt issues dump\n%s", SEPARATOR_s, SEPARATOR_s);
  if (Ci_vec().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for (iter2 = Ci_vec().begin(); iter2 != Ci_vec().end(); ++iter2) {
      iter2->Print(fp);
    }
  }

  fprintf(fp, "%sBaseline vtxt issues dump\n%s", SEPARATOR_s, SEPARATOR_s);
  if (Bi_vec().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for (iter2 = Bi_vec().begin(); iter2 != Bi_vec().end(); ++iter2) {
      iter2->Print(fp);
    }
  }

  fprintf(fp, "%sCurrent simple diff current issues dump\n%s", SEPARATOR_s, SEPARATOR_s);
  if (Ci_simpdiff().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for (iter2 = Ci_simpdiff().begin(); iter2 != Ci_simpdiff().end(); ++iter2) {
      iter2->Print(fp);
    }
  }

  fprintf(fp, "%sBaseline simple diff baseline issues dump\n%s", SEPARATOR_s, SEPARATOR_s);
  if (Bi_simpdiff().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for (iter2 = Bi_simpdiff().begin(); iter2 != Bi_simpdiff().end(); ++iter2) {
      iter2->Print(fp);
    }
  }

  fprintf(fp, "%sCurrent filt diff current issues dump\n%s", SEPARATOR_s, SEPARATOR_s);
  if (Ci_filtdiff().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for (iter2 = Ci_filtdiff().begin(); iter2 != Ci_filtdiff().end(); ++iter2) {
      iter2->Print(fp);
    }
  }

  fprintf(fp, "%sBaseline filt diff baseline issues dump\n%s", SEPARATOR_s, SEPARATOR_s);
  if (Bi_filtdiff().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for (iter2 = Bi_filtdiff().begin(); iter2 != Bi_filtdiff().end(); ++iter2) {
      iter2->Print(fp);
    }
  }

  Glb_fp().Print(fp);

}


// =============================================================================
//
// Open_file: Used to open file and return file pointer.
//
// =============================================================================
ifstream FIND_MATCH::Open_file(char *fname)
{
  ifstream f (fname);
  if (!f.is_open()) {
    INT errorNum = errno;
    const char *errStr = strerror(errorNum);
    char *errMsg = (char *)malloc(1024 + strlen(errStr));
    if (errMsg == NULL) {
      exit(0);
    }
    strcpy(errMsg, "");
    sprintf(errMsg, "Open git_diff_line_map file failed: %s : %s", fname, errStr);
    free(errMsg);
  }
  return f;
}


// =============================================================================
//
// regex_match: Used to match some key info, include "fid:lineno:msg_index",
//              "issuekey", "fid:lineno".
//
// =============================================================================
void
FIND_MATCH::Regex_match(string str)
{
  std::string str_line = str;
  const char *rawline = str.c_str();
  INT  i;

#define BUFLEN 32
  // get ln_change
  char lc_str[BUFLEN];
  if (strstr((char*)rawline, "ln_change") != NULL) {
    fprintf(Logfile(), "process ln_change\n");
    std::smatch ln_change;
    std::regex ln_change_patten("\\'ln_change\\': \\'(\\+|-)?[[:digit:]]+\\'");
    std::sregex_iterator iter2(str_line.begin(), str_line.end(), ln_change_patten);
    string lc = (*iter2).str();  // found the ln_change
    for (i = 0; i < BUFLEN; ++i) lc_str[i] = '\0';
    sscanf(lc.c_str(), "\'ln_change\': \'%s\'", lc_str);
    // remove the last character which is a bug in sccanf
    for (i = 0; i < strlen(lc_str); ++i) if (lc_str[i] == '\'') lc_str[i] = '\0';
  }

  // get ln_limit
  INT ll_value;
  if (strstr((char*)rawline, "ln_limit") != NULL) {
    fprintf(Logfile(), "process ln_limit\n");
    std::regex ln_limit_patten("\\'ln_limit\\': [0-9]+");
    std::sregex_iterator iter3(str_line.begin(), str_line.end(), ln_limit_patten);
    string ll = (*iter3).str();
    sscanf(ll.c_str(), "\'ln_limit\': %d", &ll_value);
  }

  // get last_change
  char lsc_str[BUFLEN];
  if (strstr((char*)rawline, "last_change") != NULL) {
    fprintf(Logfile(), "process last_change\n");
    std::smatch last_change;
    std::regex last_change_patten("\\'last_change\\': \\'(\\+|-)?[[:digit:]]+\\'");
    std::sregex_iterator iter4(str_line.begin(), str_line.end(), last_change_patten);
    string lsc = (*iter4).str();  // found the last_change
    for (i = 0; i < BUFLEN; ++i) lsc_str[i] = '\0';
    sscanf(lsc.c_str(), "\'last_change\': \'%s\'", lsc_str);
    // remove the last character which is a bug in sccanf
    for (i = 0; i < strlen(lsc_str); ++i) if (lsc_str[i] == '\'') lsc_str[i] = '\0';
  }


  fprintf(Logfile(), "process fname\n");
  // get fname
  char* fname = strstr((char*)rawline, "\'fname\':");
  INT   quote_cnt = 0;
  INT   fname_at = -1;
  INT   fname_len;
  for (i = 0; i < strlen(fname); ++i) {
    if (fname[i] == '\'') quote_cnt++;
    if (quote_cnt == 3 && fname_at == -1) fname_at = i+1;
    if (quote_cnt == 4) {
      fname_len = i - fname_at + 1;
      break;
    }
  }
  char *buf = (char*) malloc(fname_len);
  strncpy(buf, fname+fname_at, fname_len);
  buf[fname_len-1]='\0';
  
  // Add logic to calculate Ln_limit. No need calculate it again when line no mapping.
  INT lsc_no = 0;
  string tmp_str = lsc_str;
  if (strlen(lsc_str) > 1 && strstr(lsc_str, "+") != NULL) {
    lsc_no = stoi(tmp_str.replace(tmp_str.find("+"), 1, ""));
  } else {
    lsc_no = 0;
  }

  ll_value = ll_value + lsc_no; //
  char operation[5];
  int lc_int = 0;
  if (strlen(lc_str) > 1 && strstr(lc_str, "+") != NULL) {
    strcpy(operation,  "+");
    string tmp = lc_str;
    lc_int = stoi(tmp.replace(tmp.find("+"), 1, ""));
  } else if (strlen(lc_str) > 1 && strstr(lc_str, "-") != NULL) {
    strcpy(operation,  "-");
    string tmp = lc_str;
    lc_int = stoi(tmp.replace(tmp.find("-"), 1, ""));
  } else {
    strcpy(operation,  " ");
    lc_int = 0;
  }

  LINE_MATCH *lm = new LINE_MATCH(buf, ll_value, lc_int, operation);

  std::regex line_patten(R"~((\d+)\: (\d+))~");
  std::sregex_iterator iter1(str_line.begin(), str_line.end(), line_patten);
  std::sregex_iterator end;
  for (; iter1 != end; ++iter1) {
    string tmp1 = (*iter1)[1];
    string tmp2 = (*iter1)[2];
    LINEMAP lp(stoi(tmp1), stoi(tmp2));
    // lp.Print(Logfile());
    lm->Push_back(lp);
  }
  lm->Print(Logfile());
  Push_back(lm);
}


// =============================================================================
//
// FIND_MATCH::Read_gdiff_file: Read git_diff_results file and build line map
//                              for each scanned file.
// {
//    'magic': {'ln_limit': 27, 'last_change': '-4', 'ln_change': '-8'}, 
//    7: 9, 8: 10, 9: 11, 10: 12, 11: 13, 12: 14, 13: 17, 14: 18, 15: 19, 16: 20, 17: 21, 18: 22, 19: 23, 20: 24, 21: 25, 22: 26, 23: 27, 24: 28, 25: 29, 26: 30,
//    'fname': 'dbf.c'
// }
//
// =============================================================================
void
FIND_MATCH::Read_gdiff_file(void)
{
  if (Git_diff_results() == NULL) {
    return;
  }

  string  line;
  int     c = 1;

  ifstream git_diff_results = Open_file(Git_diff_results());
  
  while ( getline(git_diff_results, line) ) {
    fprintf(Logfile(), "git diff results file line number: %d, line content: %s\n", c, line);
    Regex_match(line);
    c++;
  }
}

// =============================================================================
//
// FIND_MATCH::Hash_issue read issues from file & create the checksum issues map
//
// =============================================================================
void
FIND_MATCH::Hash_issue(char *fname, INT start_ln, VTXT_KIND kind)
{
  ifstream   vtxt = Open_file(fname);
  string     issue;
  INT        line_no = 0;
  size_t     checksum;

  for (line_no = 0; line_no < start_ln; ++line_no) {
    getline(vtxt, issue); // skip fid_path section
  }
  while ( getline(vtxt, issue) ) {
    char unique_id[20] = {0};
    int  len = strlen((char*)issue.c_str()) + 1;
    char *tmp_issue = (char*)malloc(len);
    strcpy(tmp_issue, (char*)issue.c_str());
    // Need to match the order of processing baseline vtxt files in Read_files function:
    // process the second seen (now kind is VTXT_LBASE) and the third seen vtxt(now kind is VTXT_NBASE) file here.
    // Because baseline .[eln]vtxt file info will map into global file info data structure,
    // the file ids in the first seen vtxt file(now is etxt) will keep the same,
    // while the file ids in the second seen(now is ltxt) and third seen(now is ntxt) vtxt file will be changed
    // (based on the number of file ids in first seen vtxt file) in global file info data structure.
    // So the file ids in issues info in the second and third seen vtxt file also need to be updated.
    if(kind == VTXT_LBASE || kind == VTXT_NBASE) {
      tmp_issue = Parse_replace_fid_ln(tmp_issue, Vtxt_id(), Manager(), Partial_scan());
      issue.assign(tmp_issue);
    }
    sscanf(tmp_issue, "%[^,],%s", unique_id, tmp_issue); // before hash one issue, delete unique_id
    string str_issue(tmp_issue);
    checksum = hash<string>{}(str_issue);
    CHECKSUM_ISSUES ci(checksum, issue);
    Push_back(ci, kind);
    if(tmp_issue) free(tmp_issue);
  }
}

void
FIND_MATCH::Sort(COMPARE_KIND kind)
{
  switch (kind) {
  case COMPARE_N_F_E:
    sort(Ikey_grp_n().begin(), Ikey_grp_n().end(), Compare_key_chksum);
    sort(Ikey_grp_f().begin(), Ikey_grp_f().end(), Compare_key_chksum);
    sort(Ikey_grp_e().begin(), Ikey_grp_e().end(), Compare_key_chksum);
    break;
  case COMPARE_N_F:
    sort(Ikey_grp_n().begin(), Ikey_grp_n().end(), Compare_key_chksum);
    sort(Ikey_grp_f().begin(), Ikey_grp_f().end(), Compare_key_chksum);
    break;
  case COMPARE_F_E:
    sort(Ikey_grp_f().begin(), Ikey_grp_f().end(), Compare_key_chksum);
    sort(Ikey_grp_e().begin(), Ikey_grp_e().end(), Compare_key_chksum);
    break;
  case COMPARE_N_E:
    sort(Ikey_grp_n().begin(), Ikey_grp_n().end(), Compare_key_chksum);
    sort(Ikey_grp_e().begin(), Ikey_grp_e().end(), Compare_key_chksum);
    break;
  case COMPARE_N_L:
    sort(Ikey_grp_n().begin(), Ikey_grp_n().end(), Compare_key_chksum);
    sort(Ikey_grp_l().begin(), Ikey_grp_l().end(), Compare_key_chksum);
    break;
  case COMPARE_F_L:
    sort(Ikey_grp_f().begin(), Ikey_grp_f().end(), Compare_key_chksum);
    sort(Ikey_grp_l().begin(), Ikey_grp_l().end(), Compare_key_chksum);
    break;
  case COMPARE_L:
    sort(Ikey_grp_l().begin(), Ikey_grp_l().end(), Compare_key_chksum);
    sort(Ikey_grp_e().begin(), Ikey_grp_e().end(), Compare_key_chksum);
    break;
  default:
    printf("FIND_MATCH::sort, NOT SUPPORTED COMPARE KIND\n");
    fprintf(Logfile(), "FIND_MATCH::sort, NOT SUPPORTED COMPARE KIND\n");
    break;
  }
}

void
FIND_MATCH::Sort(VTXT_KIND kind)
{
  switch (kind) {
  case VTXT_CURRENT:
    sort(Ci_vec().begin(), Ci_vec().end(), Compare_checksum);
    break;
  case VTXT_BASELINE:
  case VTXT_NBASE:
  case VTXT_FBASE:
  case VTXT_LBASE:
  case VTXT_EBASE:
    sort(Bi_vec().begin(), Bi_vec().end(), Compare_checksum);
    break;
  case SIMP_CURRENT:
    sort(Ci_simpdiff().begin(), Ci_simpdiff().end(), Compare_checksum);
    break;
  case SIMP_BASELINE:
    sort(Bi_simpdiff().begin(), Bi_simpdiff().end(), Compare_checksum);
    break;
  case FILT_CURRENT:
    sort(Ci_filtdiff().begin(), Ci_filtdiff().end(), Compare_checksum);
    break;
  case FILT_BASELINE:
    sort(Bi_filtdiff().begin(), Bi_filtdiff().end(), Compare_checksum);
    break;
  default:
    printf("FIND_MATCH::sort, NOT SUPPORTED VTXT KIND\n");
    fprintf(Logfile(), "FIND_MATCH::sort, NOT SUPPORTED VTXT KIND\n");
    break;
  }
}

// =============================================================================
//
// Change_to_current_scan_fpath: if parameter fpath is a baseline scan file path, this method will replace it to current scan file path
// (baseline and current scan file path is different due to CI(push) and CD(merge) scan use different project path)
//
// =============================================================================
char*
FIND_MATCH::Change_to_current_scan_fpath(char *fpath) {
  if((Current_project_path() != NULL) && (Baseline_project_path() != NULL) &&
    (strcmp(Baseline_project_path(), Current_project_path()) != 0)) {
    string fp(fpath);
    size_t pos = fp.find(Baseline_project_path());
    if(pos == 0) {
      // fpath is baseline scan file path, change it to current scan file path
      fp.replace(pos, strlen(Baseline_project_path()), "");
      string current_fpath(Current_project_path());
      current_fpath += fp;
      strcpy(fpath, current_fpath.c_str());
    }
  }
  return fpath;
}

string&
FIND_MATCH::Remove_fpath_prefix(string &fpath, char *prefix) {
  if(prefix != NULL) {
    size_t pos = fpath.find(prefix);
    if(pos == 0) {
      fpath.replace(pos, strlen(prefix), "");
      pos = fpath.find("/");
      // remove the slash at the beginning
      if(pos == 0) {
        fpath.replace(pos, 1, "");
      }
    }
  }
  return fpath;
}

char*
FIND_MATCH::Remove_last_slash(char* fpath) {
  if(fpath != NULL) {
    string fp(fpath);
    size_t pos = fp.rfind('/');
    if(pos == fp.size()-1) {
      fp.replace(pos, 1, "");
      strcpy(fpath, fp.c_str());
    }
  }
  return fpath;
}

void
FIND_MATCH::Push_back(CHECKSUM_ISSUES ci, VTXT_KIND kind)
{
  switch (kind) {
  case VTXT_CURRENT:
    Ci_vec().push_back(ci);
    break;
  case VTXT_BASELINE:
  case VTXT_NBASE:
  case VTXT_FBASE:
  case VTXT_LBASE:
  case VTXT_EBASE:
    Bi_vec().push_back(ci);
    break;
  case SIMP_CURRENT:
    Ci_simpdiff().push_back(ci);
    break;
  case SIMP_BASELINE:
    Bi_simpdiff().push_back(ci);
    break;
  case FILT_CURRENT:
    Ci_filtdiff().push_back(ci);
    break;
  case FILT_BASELINE:
    Bi_filtdiff().push_back(ci);
    break;
  case SRC_FILE_JSON:
    Src_f_json_vec().push_back(ci);
    break;
  default:
    printf("FIND_MATCH::Push_back, NOT SUPPORTED VTXT KIND\n");
    fprintf(Logfile(), "FIND_MATCH::Push_back, NOT SUPPORTED VTXT KIND\n");
    break;
  }
}


void
FIND_MATCH::Push_back(FID_PATH fp)
{
  Enter_glb_fp(fp.Fid(), fp.Path());  // enter global fid_path 
}


FILE*
FIND_MATCH::Read_vtxt_filehdr(char *vtxt_file, INT& start_ln, VTXT_KIND kind, FP_VEC& mf)
{
  Manage *m = Manager();
  FILE   *input;

  if (vtxt_file == NULL) return NULL;
  New_vtxt_id();
  input = fopen(vtxt_file, "r");
  if (input == NULL) {
    fprintf(stderr, "%s does not exist\n", vtxt_file);
    fprintf(Logfile(), "%s does not exist\n", vtxt_file);
    exit(1);
  }
  start_ln = m->cvt2csv(input, this, kind, mf);
  if (start_ln <= 0) {
    fprintf(stderr, "file conversion error\n");
    fprintf(Logfile(), "file conversion error\n");
    exit(1);
  }
  return input;
}


void
FIND_MATCH::Read_vtxt_file(char *vtxt_file, VTXT_KIND kind, FP_VEC& mf)
{
  Manage *m = Manager();
  FILE   *input;
  INT     start_ln;

  input = Read_vtxt_filehdr(vtxt_file, start_ln, kind, mf);

  if (input == NULL) {
    return;
  }
  else {
    Hash_issue(vtxt_file, start_ln, kind);
    fclose(input);
  }
  Sort(kind);
}

void
FIND_MATCH::Verify_fid_path_consistency(void)
{
  // all entries in the GLB_VEC should be the same
  assert(Glb_fp().All_defby(BASE_VTXTID));
}


// =============================================================================
//
// Parse_src_file_json: parse the source_files.json to get file path and calculate
//                      the checksum of it for filtering.
//
// =============================================================================
char *
Manage::Parse_src_file_json(char *file_path, char dlimiter_beg, char dlimiter_end, FIND_MATCH *fm, VTXT_KIND kind)
{
  int  i, j = 0;
  int  len = strlen(file_path);
  char pstr[len] = {0};
  size_t sz = STR_MALLOC_SZ;
  size_t chksum = 0;

  // skip the first useless "\"" 
  file_path++;
  while (i <= len) {
    if (file_path[i] != dlimiter_end) {
      pstr[j] = file_path[i];
      i++;
      j++;
    } else {
      pstr[j+1] = '\0';
      char *tmp_str = (char *)malloc(j+1);
      if (tmp_str == 0) {
        handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory");
      }

      strcpy(tmp_str, pstr);
      string fp(tmp_str);

      // get relative file path to calculate checksum
      fp = fm->Remove_fpath_prefix(fp, fm->Current_project_path());
      chksum = hash<string>{}(fp);
      CHECKSUM_ISSUES ci(chksum, tmp_str);
      fm->Push_back(ci, kind);

      fprintf(fm->Logfile(), "file_path %s\n", fp.c_str());
      fprintf(fm->Logfile(), "checksum of file_path %ld\n", chksum);

      free(tmp_str);
      // init pstr with 0 for next using, avoid memory error.
      memset(pstr, 0, j);
      // skip the useless "\",\"" in the middle
      i += 3;
      j = 0;
    }
  }

  return (char *)0;
}


// =============================================================================
//
// Read_src_file_json: read and parse the source_files.json for filtering DSR on
//                     changed file list.
//
// ["/home/jun/xc5/release/xcalclient/executable/xcalbuild/linux/include/__xvsa_common.h"
// ,"/home/jun/xc5/test/basic/aob.c","/home/jun/xc5/test/basic/dbf.c"]
//                               
// =============================================================================
INT
FIND_MATCH::Read_src_file_json(char *src_file_json, VTXT_KIND kind, CI_VEC& sf_vec)
{
  Manage *m = Manager();
  FILE   *input;
  char   *file_path;
  char   *delimiter;
  bool   done = false;

  if (src_file_json == NULL) return -1;
  
  input = fopen(src_file_json, "r");
  if (input == NULL) {
    fprintf(stderr, "%s does not exist\n", src_file_json);
    fprintf(Logfile(), "%s does not exist\n", src_file_json);
    exit(1);
  }

  file_path = m->get_varlen_str(input, '[', ']');
  char *one_file_path = m->Parse_src_file_json(file_path, '\"', '\"', this, kind);
  if (one_file_path == (char *)-1)
    m->handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file - read source files json error\n");

  fclose(input);
}

// =============================================================================
//
// FIND_MATCH::Read_files, reads contents of three key input files and store
//                         the content inside FIND_MATCH members
//
// =============================================================================
void
FIND_MATCH::Read_files(void)
{
  Read_gdiff_file();
  //Read_vtxt_file(Baseline_vtxt(), VTXT_BASELINE, B_fid_path());
  //Read_vtxt_file(Fbaseline_vtxt(), VTXT_FBASE, F_fid_path());
  Read_vtxt_file(Ebaseline_vtxt(), VTXT_EBASE, E_fid_path());
  Read_vtxt_file(Lbaseline_vtxt(), VTXT_LBASE, L_fid_path());
  Read_vtxt_file(Nbaseline_vtxt(), VTXT_NBASE, N_fid_path());
  //Verify_fid_path_consistency();
  Read_vtxt_file(Current_vtxt(), VTXT_CURRENT, C_fid_path());
  Read_src_file_json(Src_file_json(), SRC_FILE_JSON, Src_f_json_vec());
  fprintf(Logfile(), "%sDUMP AFTER FIND_MATCH::Read_files\n%s",SEPARATOR_d, SEPARATOR_d);
  Print(Logfile());
}


// =============================================================================
//
// FIND_MATCH::filt_diff, when partial scan, filtering the issues from the file 
//                        be changed in source_files.json. 
//                        if in the source_files.json do diff as usual, if not,
//                        filtering issues to Existing.
//
// =============================================================================
BOOL
FIND_MATCH::Filt_diff(char *issue, FP_VEC& fid_path, FP_VEC& c_fid_path)
{
  if (issue == NULL) return false;

  int  issue_len = strlen(issue);
  char unique_id[issue_len] = {0}; 
  char ikey[issue_len]      = {0}; 
  char fname[issue_len]     = {0}; 
  char fid_ln[issue_len]    = {0};
  int  fid = 0;
  int  base_fid = 0;
  int  base_ln = 0;
  char *fpath = NULL;
  size_t fpath_chksum = 0;

  sscanf(issue, "%[^,],%[^,],%[^,],%[^,]", unique_id, ikey, fname, fid_ln);
  sscanf(fid_ln, "[%d:%d]", &base_fid, &base_ln);
  // Find the fid in current c_fid_path based on fname.
  // Because when one project be built may has the same file name in different path. 
  // Need use the full path to find and compare fid in c_fid_path and source_files.json.
  // use full path to find fid in current c_fid_path, avoid the same file name in different path.
  fpath = Find_fpath(fid_path, base_fid);
  if (fpath == NULL) {
    return false;
  }

  fpath = Change_to_current_scan_fpath(fpath);
  
  fid = Find_fid(c_fid_path, fpath);
  
  // Get the file path based on fid and calculate the checksum of relative fpath for comparing
  for (FP_VEC::iterator iter = c_fid_path.begin(); iter != c_fid_path.end(); iter++) {
    if ((*iter).Fid() == fid) {
      string tmp_str((*iter).Path());
      // get relative file path to calculate checksum
      tmp_str = Remove_fpath_prefix(tmp_str, Current_project_path());
      fpath_chksum = hash<string>{}(tmp_str);
      break;
    }
  }

  // compare with change file list with checksum, if equal, return true.
  for (CI_VEC::iterator iter = Src_f_json_vec().begin(); iter != Src_f_json_vec().end(); iter++) {
    if ((*iter).Checksum() == fpath_chksum) return true;
  }

  return false;
}

//
// Simple_diff move the new issues to curkind tab and the fixed to basekind tab
//
#define UID_LEN 20
void
FIND_MATCH::Simple_diff(CI_VEC& iterB, CI_VEC& iterC, VTXT_KIND basekind,
                        VTXT_KIND curkind, FP_VEC& b_fid_path, FP_VEC& c_fid_path)
{
  int iterb = 0;
  int iterc = 0;
  int countb = 0;
  int countc = 0;
  int iterB_size = iterB.size();
  int iterC_size = iterC.size();
  char *tmp_b_issue;
  char *tmp_c_issue;

  while (iterb + countb < iterB_size && iterc + countc < iterC_size) {
    if (iterB[iterb].Checksum() > iterC[iterc].Checksum()) {
      tmp_c_issue = iterC[iterc].Giveup();
      CHECKSUM_ISSUES ci(iterC[iterc].Checksum(), tmp_c_issue);
      // if partial scan and file not in change file list, move issue to Existing
      // filter based on diff kind, so just filter one time.
      if (curkind == SIMP_CURRENT && Partial_scan() && !Filt_diff(tmp_c_issue, c_fid_path, c_fid_path))
        Push_back(ci, VTXT_EBASE);
      else
        Push_back(ci, curkind);
      iterC.erase(iterC.begin() + iterc);
      countc++;
    } else if (iterB[iterb].Checksum() < iterC[iterc].Checksum()) {
      tmp_b_issue = iterB[iterb].Giveup();
      CHECKSUM_ISSUES ci(0, tmp_b_issue);  // will reset checksum later
      // if partial scan and file not in change file list, move issue to Existing
      // filter based on diff kind, so just filter one time.
      if (basekind == SIMP_BASELINE && Partial_scan() && !Filt_diff(tmp_b_issue, b_fid_path, c_fid_path))
        Push_back(ci, VTXT_EBASE);
      else
        Push_back(ci, basekind);
      iterB.erase(iterB.begin() + iterb);
      countb++;
    } else {
      if (curkind == FILT_CURRENT) {
        char unique_id[UID_LEN] = {0};
        sscanf(iterB[iterb].Issue(), "%[^,]", unique_id);
        string uid(unique_id);
        uid.replace(uid.find("["), 1, "");
        uid.replace(uid.find("]"), 1, "");
        size_t tmp_chksum = iterC[iterc].Checksum();
        string tmp_str(iterC[iterc].Giveup());
        tmp_str.replace(1, strlen(uid.c_str()), uid.c_str(), strlen(uid.c_str()));
        CHECKSUM_ISSUES ci(tmp_chksum, tmp_str.c_str());
        Push_back(ci, SIMP_CURRENT);
        iterC.erase(iterC.begin() + iterc);
        iterb++;
        countc++;
      } else {
        iterb++;
        iterc++;
      }
    }
  } // while loop

  iterb = iterb + countb;
  if (iterb < iterB_size) {
    // iterate and move them into SIMP_BASELINE vector
    for (; iterb < iterB_size; ++iterb) {
      tmp_b_issue = iterB[iterb].Giveup();
      CHECKSUM_ISSUES ci(0, tmp_b_issue); // will reset checksum later
      // if partial scan and file not in change file list, move issue to Existing
      if (basekind == SIMP_BASELINE && Partial_scan() && !Filt_diff(tmp_b_issue, b_fid_path, c_fid_path))
        Push_back(ci, VTXT_EBASE);
      else
        Push_back(ci, basekind);
    }
  }
  iterc = iterc + countc;
  if (iterc < iterC_size) {
    // iterate and move them into SIMP_CURRENT vector
    for (; iterc < iterC_size; ++iterc) {
      tmp_c_issue = iterC[iterc].Giveup();
      CHECKSUM_ISSUES ci(iterC[iterc].Checksum(), tmp_c_issue);
      // if partial scan and file not in change file list, move issue to Existing
      if (curkind == SIMP_CURRENT && Partial_scan() && !Filt_diff(tmp_c_issue, c_fid_path, c_fid_path))
        Push_back(ci, VTXT_EBASE);
      else
        Push_back(ci, curkind);
    }
  }
  fprintf(Logfile(), "%sDUMP AFTER SIMPLE DIFF\n%s\n", SEPARATOR_d, SEPARATOR_d);
  Print(Logfile());
}


// =============================================================================
//
// Fname2fid: Store the fid of the LINE_MATCH::Fname() into the same object
//
// =============================================================================
void
FIND_MATCH::Fname2fid(FP_VEC& fid_path)
{
  LM_VEC::iterator iter1;
  for (iter1 = Lm_vec().begin(); iter1 != Lm_vec().end(); iter1++) {
    char *fname = (*iter1)->Fname();
    INT fid = Find_fid(fid_path, fname);
    (*iter1)->Set_file_id(fid);
  }
}


// =============================================================================
//
// Find_cur_ln: find the current line number based on the baseline fileID
//              and line number
//
// =============================================================================
INT
FIND_MATCH::Find_cur_ln(INT base_fid, INT base_ln)
{
  INT cur_ln = 0;
  LM_VEC::iterator iter1;
  for (iter1 = Lm_vec().begin(); iter1 != Lm_vec().end(); iter1++) {
    if (base_fid == (*iter1)->File_id()) {
      LP_VEC::iterator iter2;
      for (iter2 = (*iter1)->Line_map().begin();
           iter2 != (*iter1)->Line_map().end(); iter2++) {
        if (base_ln == iter2->Old_ln()) {
          cur_ln = iter2->New_ln();
          break;
        }
      }
      if (cur_ln == 0) {
        switch ((*iter1)->Magic().Operation()) {
        case OPER_INSERT:
          if (base_ln >= (*iter1)->Magic().Ln_limit() - (*iter1)->Magic().Ln_change())
            cur_ln = base_ln + (*iter1)->Magic().Ln_change();
          break;
        case OPER_DELETE:
          if (base_ln >= (*iter1)->Magic().Ln_limit())
            cur_ln = base_ln - (*iter1)->Magic().Ln_change();
          break;
        default:
          break;
        } // apply the line change
      } // current line is not set
    } // found the match file_id
  } // iterate through the Line Match Vector
  return cur_ln;
}


// =============================================================================
//
// Replace_fid: update fid with the unified fid on the cur_issue
//
// =============================================================================
void
FIND_MATCH::Replace_fid(VTXT_ISSUE& cur_issue, INT lnkid)
{
  INT togid = INVALID_GLBID;
  INT base_fid = cur_issue.Filenum();

  if (lnkid == 0)
    return;
  togid = Glb_fp().Get_glb_id(lnkid, base_fid);
  if (togid != INVALID_GLBID) {
    cur_issue.Filenum(togid);
  }

  if (!cur_issue.Pn_vec().empty()) {
    _PN_VEC::iterator iter;
    for (iter = cur_issue.Pn_vec().begin();
         iter != cur_issue.Pn_vec().end(); ++iter) {
      togid = INVALID_GLBID;
      base_fid = iter->File_id();
      togid = Glb_fp().Get_glb_id(lnkid, base_fid);
      if (togid != INVALID_GLBID) {
        iter->File_id(togid);
      }
    } // iterate through the issue path_nodes
  } // if the issue path_node list is not empty
}

char *
FIND_MATCH::Issue_key_ln_map(char *ikey, int str_sz)
{
  // Match and update lineno in issue_key.
  char k_fn1[str_sz] = {0};
  char k_ln1[str_sz] = {0};
  char k_fn2[str_sz] = {0};
  char k_ln2[str_sz] = {0};

  char tmp1[str_sz] = {0};
  char tmp2[str_sz] = {0};
  char tmp3[str_sz] = {0};
  char tmp4[str_sz] = {0};
  char tmp5[str_sz] = {0};

  string tmp_str = ikey;
  string k_val;
  if (strstr(ikey, "[") != NULL) {
    k_val = tmp_str.replace(tmp_str.find("["), 1, "");
    if (strstr(ikey, "]") != NULL) {
      k_val = k_val.replace(k_val.find("]"), 1, "");
    }
  }
  int colon_no  = 0;
  int position  = 0;
  int atsign_no = 0;
  while ( (position = k_val.find(":", position)) != string::npos ) {
    position++;
    colon_no++;
  }
  position = 0;
  while ( (position = k_val.find("@", position)) != string::npos ) {
    position++;
    atsign_no++;
  }

  int k_fid  = 0;
  int k_fid2 = 0;
  int k_ln_change  = 0;
  int k_ln_change2 = 0;
  assert(0 < atsign_no < 5); // if ikey format error, assert! 
  switch (atsign_no) {
  case 1:
    if (colon_no == 1) {
      sscanf(k_val.c_str(), "%[^@]@%[^@]", tmp1, tmp2);
      if (strlen(tmp1) == 0) {
        sscanf(k_val.c_str(), "@%[^@]", tmp2);
        fprintf(Logfile(), "var is empty, skip var.\n filename_ln is %s\n", tmp2);
      }
      sscanf(tmp2, "%[^:]:%s", k_fn1, k_ln1);
      k_fid = Find_fid(E_fid_path(), k_fn1);
      if (k_fid != 0 && strlen(k_ln1) > 0) {
        k_ln_change = Find_cur_ln(k_fid, stoi(k_ln1));
        if (k_ln_change == 0)
          k_ln_change = stoi(k_ln1);
        sprintf(ikey, "%s@%s:%d", tmp1, k_fn1, k_ln_change);
      }
    }
    break;
  case 2:
    if (colon_no == 1) {
      sscanf(k_val.c_str(), "%[^@]@%[^@]@%[^@]", tmp1, tmp2, tmp3);
      if (strlen(tmp1) == 0) {
        sscanf(k_val.c_str(), "@%[^@]@%[^@]", tmp2, tmp3);
        fprintf(Logfile(), "var is empty, skip var.\n filename_ln is %s\n", tmp3);
      }

      sscanf(tmp3, "%[^:]:%s", k_fn1, k_ln1);
      k_fid = Find_fid(E_fid_path(), k_fn1);
      if (k_fid != 0 && strlen(k_ln1) > 0) {
        k_ln_change = Find_cur_ln(k_fid, stoi(k_ln1));
        if (k_ln_change == 0)
          k_ln_change = stoi(k_ln1);
        sprintf(ikey, "%s@%s@%s:%d", tmp1, tmp2, k_fn1, k_ln_change);
      }
    }
    if (colon_no == 2) {
      sscanf(k_val.c_str(), "%[^@]@%[^@]@%[^@]", tmp1, tmp2, tmp3);
      if (strlen(tmp1) == 0) {
        sscanf(k_val.c_str(), "@%[^@]@%[^@]", tmp2, tmp3);
        fprintf(Logfile(), "var is empty, skip var.\n filename_ln is %s\n", tmp3);
      }

      sscanf(tmp2, "%[^:]:%s", k_fn1, k_ln1);
      sscanf(tmp3, "%[^:]:%s", k_fn2, k_ln2);
      k_fid = Find_fid(E_fid_path(), k_fn1);
      if (k_fid != 0 && strlen(k_ln1) > 0) {
        k_ln_change = Find_cur_ln(k_fid, stoi(k_ln1));
        if (k_ln_change == 0)
          k_ln_change = stoi(k_ln1);
      }
      k_fid2 = Find_fid(E_fid_path(), k_fn2);
      if (k_fid2 != 0 && strlen(k_ln2) > 0) {
        k_ln_change2 = Find_cur_ln(k_fid2, stoi(k_ln2));
        if (k_ln_change2 == 0)
          k_ln_change2 = stoi(k_ln2);
        sprintf(ikey, "%s@%s:%d@%s:%d", tmp1, k_fn1, k_ln_change, k_fn2, k_ln_change2);
      }
    }
    break;
  case 3:
    if (colon_no == 1) {
      sscanf(k_val.c_str(), "%[^@]@%[^@]@%[^@]@%[^@]", tmp1, tmp2, tmp3, tmp4);
      if (strlen(tmp1) == 0) {
        sscanf(k_val.c_str(), "@%[^@]@%[^@]@%[^@]", tmp2, tmp3, tmp4);
        fprintf(Logfile(), "var is empty, skip var.\n filename_ln is %s\n", tmp4);
      }

      sscanf(tmp4, "%[^:]:%s", k_fn1, k_ln1);
      k_fid = Find_fid(E_fid_path(), k_fn1);
      if (k_fid != 0 && strlen(k_ln1) > 0) {
        k_ln_change = Find_cur_ln(k_fid, stoi(k_ln1));
        if (k_ln_change == 0)
          k_ln_change = stoi(k_ln1);
        sprintf(ikey, "%s@%s@%s@%s:%d", tmp1, tmp2, tmp3, k_fn1, k_ln_change);
      }
    }
    if (colon_no == 2) {
      sscanf(k_val.c_str(), "%[^@]@%[^@]@%[^@]@%[^@]", tmp1, tmp2, tmp3, tmp4);
      if (strlen(tmp1) == 0) {
        sscanf(k_val.c_str(), "@%[^@]@%[^@]@%[^@]", tmp2, tmp3, tmp4);
        fprintf(Logfile(), "var is empty, skip var.\n filename_ln is %s\n", tmp4);
      }

      sscanf(tmp3, "%[^:]:%s", k_fn1, k_ln1);
      sscanf(tmp4, "%[^:]:%s", k_fn2, k_ln2);
      k_fid = Find_fid(E_fid_path(), k_fn1);
      if (k_fid != 0 && strlen(k_ln1) > 0) {
        k_ln_change = Find_cur_ln(k_fid, stoi(k_ln1));
        if (k_ln_change == 0)
          k_ln_change = stoi(k_ln1);
      }
      k_fid2 = Find_fid(E_fid_path(), k_fn2);
      if (k_fid2 != 0 && strlen(k_ln2) > 0) {
        k_ln_change2 = Find_cur_ln(k_fid2, stoi(k_ln2));
        if (k_ln_change2 == 0)
          k_ln_change2 = stoi(k_ln2);
        sprintf(ikey, "%s@%s@%s:%d@%s:%d", tmp1, tmp2, k_fn1, k_ln_change, k_fn2, k_ln_change2);
      }
    }
    break;
  case 4:
    if (colon_no == 1) {
      sscanf(k_val.c_str(), "%[^@]@%[^@]@%[^@]@%[^@]@%[^@]", tmp1, tmp2, tmp3, tmp4, tmp5);
      if (strlen(tmp1) == 0) {
        sscanf(k_val.c_str(), "@%[^@]@%[^@]@%[^@]@%[^@]", tmp2, tmp3, tmp4, tmp5);
        fprintf(Logfile(), "var is empty, skip var.\n filename_ln is %s\n", tmp5);
      }
      
      sscanf(tmp5, "%[^:]:%s", k_fn1, k_ln1);
      k_fid = Find_fid(E_fid_path(), k_fn1);
      if (k_fid != 0 && strlen(k_ln1) > 0) {
        k_ln_change = Find_cur_ln(k_fid, stoi(k_ln1));
        if (k_ln_change == 0)
          k_ln_change = stoi(k_ln1);
        sprintf(ikey, "%s@%s@%s@%s@%s:%d", tmp1, tmp2, tmp3, tmp4, k_fn1, k_ln_change);
      }
    }
    if (colon_no == 2) {
      sscanf(k_val.c_str(), "%[^@]@%[^@]@%[^@]@%[^@]@%[^@]", tmp1, tmp2, tmp3, tmp4, tmp5);
      if (strlen(tmp1) == 0) {
        sscanf(k_val.c_str(), "@%[^@]@%[^@]@%[^@]@%[^@]", tmp2, tmp3, tmp4, tmp5);
        fprintf(Logfile(), "var is empty, skip var.\n filename_ln is %s\n", tmp5);
      }

      sscanf(tmp4, "%[^:]:%s", k_fn1, k_ln1);
      sscanf(tmp5, "%[^:]:%s", k_fn2, k_ln2);
      k_fid = Find_fid(E_fid_path(), k_fn1);
      if (k_fid != 0 && strlen(k_ln1) > 0) {
        k_ln_change = Find_cur_ln(k_fid, stoi(k_ln1));
        if (k_ln_change == 0)
          k_ln_change = stoi(k_ln1);
      }
      k_fid2 = Find_fid(E_fid_path(), k_fn2);
      if (k_fid2 != 0 && strlen(k_ln2) > 0) {
        k_ln_change2 = Find_cur_ln(k_fid2, stoi(k_ln2));
        if (k_ln_change2 == 0)
          k_ln_change2 = stoi(k_ln2);
        sprintf(ikey, "%s@%s@%s@%s:%d@%s:%d", tmp1, tmp2, tmp3, k_fn1, k_ln_change, k_fn2, k_ln_change2);
      }
    }
    break;
  default:
    break;
  }
  return ikey;
}

// =============================================================================
//
// Parse_replace_fid_ln: perform in the SIMP_BASELINE vector for one file
//
// =============================================================================
char *
FIND_MATCH::Parse_replace_fid_ln(char *issue, INT lnkid, Manage *manage, BOOL partial_scan)
{

  // Format string for builtin issues and RBC issues
  int  fmt_len = 100;
  char builtin_fmt[fmt_len];
  char rbc_fmt[fmt_len];
  char w_builtin_fmt[fmt_len];
  char w_rbc_fmt[fmt_len];
  if (manage->Ver_cmp(0, 6, 0) >= 0 && manage->Ver_cmp(0, 7, 2) < 0) {
    strcpy(builtin_fmt, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],#%[^#]#,%s");
    strcpy(rbc_fmt, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],#%[^#]#,%s");
    strcpy(w_builtin_fmt, "%s,[%s],%s,[%s],%s,%s,%s,%s,%s,%s,%s,#%s#,[%s]");
    strcpy(w_rbc_fmt, "%s,[%s],%s,[%s],%s,%s,%s,%s,%s,%s,%s,%s,%s,#%s#,[%s]");
  } else {
    strcpy(builtin_fmt, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%s");
    strcpy(rbc_fmt, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%s");
    strcpy(w_builtin_fmt, "%s,[%s],%s,[%s],%s,%s,%s,%s,%s,%s,%s,%s,[%s]");
    strcpy(w_rbc_fmt, "%s,[%s],%s,[%s],%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,[%s]");
  }

  PATH_NODE  pn;
  int   str_sz = strlen(issue) + 1; // the length of input issue.

  char  unique_id[str_sz] = {0};
  char  ikey[str_sz] = {0};
  char  fname[str_sz] = {0};
#define FIDLNLEN 32
  char  fid_ln[FIDLNLEN] = {0};
  char  dcat[FIDLNLEN] = {0};
  char  confd[FIDLNLEN] = {0};
  char  rn[FIDLNLEN] = {0};
  char  hd_rbc[FIDLNLEN] = {0};
  char  hd_1[FIDLNLEN] = {0};
  char  hd_2[FIDLNLEN] = {0};
  char  hd_3[FIDLNLEN] = {0};
  char  hd_cert[FIDLNLEN] = {0};
  char  vn[str_sz] = {0};
  char  fn[str_sz] = {0};
  char  issue_path[str_sz] = {0};
  BOOL  use_builtin_fmt = FALSE;
  BOOL  use_rbc_fmt = FALSE;
  char  new_issue_path[str_sz] = {0};
  new_issue_path[0] = '\0';
  char *str = (char *)malloc(str_sz + BUFLEN);  // to be freed by the caller
  INT   togid = INVALID_GLBID;

  // check str != NULL
  strcpy(str, issue);
  if ((strstr(issue, "RBC") == NULL) && (strstr(issue, "GJB") == NULL)) {
    // parse builtin issue.
    use_builtin_fmt = TRUE;
    sscanf(str, builtin_fmt, unique_id, ikey, fname, fid_ln, dcat, confd, rn, hd_1, hd_2, hd_3, vn, fn, issue_path);
  } else {
    // parse RBC issue.
    use_rbc_fmt = TRUE;
    sscanf(str, rbc_fmt, unique_id, ikey, fname, fid_ln, dcat, confd, hd_rbc, hd_1, hd_2, hd_3, hd_cert, rn, vn, fn, issue_path);
  }

  // Match and update lineno in issue_key.
  char *tmp_ikey = Issue_key_ln_map(ikey, str_sz);
  strcpy(ikey, tmp_ikey);

  // Match and update lineno in [fid:ln] section.
  INT base_fid;
  INT base_ln;
  INT partial_base_fid;
  sscanf(fid_ln, "[%d:%d]", &base_fid, &base_ln);
  INT line_change = Find_cur_ln(base_fid, base_ln);
  if (line_change == 0)
    line_change = base_ln;
  if (lnkid != 0)
    togid = Glb_fp().Get_glb_id(lnkid, base_fid);
  // when do Partial DSR, need update fid.
  if (partial_scan) {
    char *tmp_fname = NULL;
    // use full path to find fid in current fid_path, avoid the same file name in different path.
    tmp_fname = Find_fpath(E_fid_path(), base_fid);
    tmp_fname = Change_to_current_scan_fpath(tmp_fname);
    partial_base_fid = Find_fid(C_fid_path(), tmp_fname);
    sprintf(fid_ln, "%d:%d", (togid != INVALID_GLBID) ? togid : partial_base_fid, line_change);
  } else {
    sprintf(fid_ln, "%d:%d", (togid != INVALID_GLBID) ? togid : base_fid, line_change);
  }

  // Match and update lineno in variable issue path.
  std::string str_line2(issue_path);
  std::regex line_patten2(R"~((-1|\d+)\:(-1|\d+):(-1|\d+):(-1|\d+))~");
  std::sregex_iterator iter2(str_line2.begin(), str_line2.end(), line_patten2);
  std::sregex_iterator end2;
  INT linecnt = 0;
  for (; iter2 != end2; ++iter2) {
    INT base_fid = stoi((*iter2)[1]);
    INT base_ln  = stoi((*iter2)[2]);
    INT base_cln = stoi((*iter2)[3]);
    INT base_msg = stoi((*iter2)[4]);
    char fid_lnx[FIDLNLEN];
    if (base_ln != -1) {
      line_change = Find_cur_ln(base_fid, base_ln);
      if (line_change == 0)
        line_change = base_ln;
    } else {
      line_change = base_ln;
    }
    if (lnkid) {
      if (base_fid != -1) {
        togid = Glb_fp().Get_glb_id(lnkid, base_fid);
      } else {
        togid = base_fid;
      }
    }
    if (linecnt++ == 0) {
      if (partial_scan)
        sprintf(fid_lnx, "%d:%d:%d:%d", (togid != INVALID_GLBID) ? togid : partial_base_fid, line_change, base_cln, base_msg);
      else
        sprintf(fid_lnx, "%d:%d:%d:%d", (togid != INVALID_GLBID) ? togid : base_fid, line_change, base_cln, base_msg);
    } else {
      if (partial_scan)
        sprintf(fid_lnx, ",%d:%d:%d:%d", (togid != INVALID_GLBID) ? togid : partial_base_fid, line_change, base_cln, base_msg);
      else
        sprintf(fid_lnx, ",%d:%d:%d:%d", (togid != INVALID_GLBID) ? togid : base_fid, line_change, base_cln, base_msg);
    }
    strcat(new_issue_path, fid_lnx);
  }

  if (use_builtin_fmt)
    sprintf(str, w_builtin_fmt, unique_id, ikey, fname, fid_ln, dcat, confd, rn, hd_1, hd_2, hd_3, vn, fn, new_issue_path);
  if (use_rbc_fmt)
    sprintf(str, w_rbc_fmt, unique_id, ikey, fname, fid_ln, dcat, confd, hd_rbc, hd_1, hd_2, hd_3, hd_cert, rn, vn, fn, new_issue_path);
    
  return str; // this str has already been modified
}


// =============================================================================
//
// Update_lineno_diff: repleace line number for each file in the Bi_simpdiff w/
//                     the new line number in the current version
//
// =============================================================================
void
FIND_MATCH::Update_lineno_diff(Manage *manage, FP_VEC& b_fid_path, FP_VEC& c_fid_path)
{
  char   *issue;
  size_t  checksum;
  CI_VEC::iterator iterb;
  CI_VEC::iterator iterc;

  if (!Bi_simpdiff().empty() && !Ci_simpdiff().empty()) {

    Fname2fid(E_fid_path()); // Do it when need update lineno and diff.

    for ( iterb = Bi_simpdiff().begin(); iterb != Bi_simpdiff().end(); ++iterb ) {
      //TODO: later will use an enum value replace magic number 0
      issue = Parse_replace_fid_ln(iterb->Issue(), 0, manage, Partial_scan());
      if (issue != NULL) {
        char unique_id[20] = {0};
        int  len = strlen(issue) + 1;
        char *tmp_issue = (char*)malloc(len);
        if (tmp_issue == 0) {
          Manager()->handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory");
        }
        sscanf(issue, "%[^,],%s", unique_id, tmp_issue); // before hash one issue, delete unique_id
        string new_issue(tmp_issue);
        checksum = hash<string>{}(new_issue);
        iterb->Set_checksum(checksum);
        free(issue);
        free(tmp_issue);
      }
    }
    Sort(SIMP_BASELINE);
    Simple_diff(Bi_simpdiff(), Ci_simpdiff(), FILT_BASELINE, FILT_CURRENT, b_fid_path, c_fid_path);
  }

  if (!Bi_simpdiff().empty() && Ci_simpdiff().empty()) {
    // all issues from iterb are fix.
    for (iterb = Bi_simpdiff().begin(); iterb != Bi_simpdiff().end(); ++iterb) {
      CHECKSUM_ISSUES ci(iterb->Checksum(), iterb->Giveup());
      Push_back(ci, FILT_BASELINE);
    }
  }
  if (Bi_simpdiff().empty() && !Ci_simpdiff().empty()) {
    // all issues from iterc are new.
    for (iterc = Ci_simpdiff().begin(); iterc != Ci_simpdiff().end(); ++iterc) {
      CHECKSUM_ISSUES ci(iterc->Checksum(), iterc->Giveup());
      Push_back(ci, FILT_CURRENT);
    }
  }
  fprintf(Logfile(), "%sDUMP AFTER UPDATE LINENO\n%s\n", SEPARATOR_d, SEPARATOR_d);
  Print(Logfile());
}


// =============================================================================
//
// Ikey_hash_count: hash and count issue key for grouping and diff issue key
//
// =============================================================================
void
FIND_MATCH::Ikey_hash_count(CI_VEC& ci_vec, IG_VEC& ig_vec, BOOL lnkid)
{
  for (int ci_idx = 0; ci_idx < ci_vec.size(); ci_idx++) {
    if (ci_vec[ci_idx].Issue() != NULL) {
      int str_sz = strlen(ci_vec[ci_idx].Issue()) + 1; // the length of input issue.
      char unique_id[20] = {0};
      char ikey[str_sz] = {0};

      sscanf(ci_vec[ci_idx].Issue(), "%[^,],%[^]]", unique_id, ikey);
      // Match and update lineno in issue_key.
      if (lnkid) {
        char *tmp_ikey = Issue_key_ln_map(ikey, str_sz);
        strcpy(ikey, tmp_ikey);
      }
      if (strstr(ikey, "[") != NULL) {
        string tmp_k(ikey);
        tmp_k.replace(tmp_k.find("["), 1, "");
        //tmp_k.replace(tmp_k.find("]"), 1, "");
        strcpy(ikey, tmp_k.c_str());
      }

      std::string str_ikey(ikey);
      size_t checksum = hash<string>{}(str_ikey);
      
      int vec_size = ig_vec.size();
      if (vec_size == 0) {
        IKEY_GRP ig;
        ig.Set_ipath_num();
        ig.Set_ikey_chksum(checksum);
        ig.Set_issue(ci_vec[ci_idx].Giveup());
        ig_vec.push_back(ig);
      } else {
        int ig_idx = 0;
        for (; ig_idx < vec_size; ig_idx++) {
          if (ig_vec[ig_idx].Ikey_chksum() == checksum) {
            ig_vec[ig_idx].Set_ipath_num();
            ig_vec[ig_idx].Set_issue(ci_vec[ci_idx].Giveup());
            break;
          }
        }
        if (ig_idx == vec_size) {
          IKEY_GRP ig;
          ig.Set_ipath_num();
          ig.Set_ikey_chksum(checksum);
          ig.Set_issue(ci_vec[ci_idx].Giveup());
          ig_vec.push_back(ig);
        }
      }
    }
  }
}


void
FIND_MATCH::Push_back_issue(vector<char*>& vec1, vector<char*>& vec2, VTXT_KIND kind)
{
  vector<char*>::iterator iter_i;
  char unique_id[20] = {0};
  sscanf(vec2[0], "%[^,],", unique_id);
  string uid(unique_id);
  uid.replace(uid.find("["), 1, "");
  uid.replace(uid.find("]"), 1, "");
  // when move issue to L, replace the uniqueID with the first appear uniqueID.
  for (iter_i = vec1.begin(); iter_i != vec1.end(); iter_i++) {
    string tmp_str(*iter_i);
    tmp_str.replace(1, strlen(uid.c_str()), uid.c_str(), strlen(uid.c_str()));
    CHECKSUM_ISSUES ci(0, tmp_str.c_str());
    Push_back(ci, kind);
  }
}

void
FIND_MATCH::Push_back_issue(vector<char*>& vec, VTXT_KIND kind)
{
  vector<char*>::iterator iter_i;
  // just move issue to related vector, no need replace uniqueID
  for (iter_i = vec.begin(); iter_i != vec.end(); iter_i++) {
    CHECKSUM_ISSUES ci(0, (*iter_i));
    Push_back(ci, kind);
  }
}

void
FIND_MATCH::Order_vec_diff(IG_VEC& iter1, IG_VEC& iter2, IG_VEC& iter3, COMPARE_KIND kind, VTXT_KIND kind1,
		           VTXT_KIND kind2, VTXT_KIND kind3, VTXT_KIND kind4, const char* E_scan_id)
{
  fprintf(Logfile(), "\nCOMPARE mode is %d\n", kind);
  IG_VEC::iterator iter_1 = iter1.begin();
  IG_VEC::iterator iter_2 = iter2.begin();
  IG_VEC::iterator iter_3 = iter3.begin();

  // this condition compare N/F/E all
  if (kind == COMPARE_N_F_E) {
    // this loop compare N/E
    while (iter_1 != iter1.end() && iter_3 != iter3.end()) {
      if (iter_1->Ikey_chksum() < iter_3->Ikey_chksum()) {
        iter_1++;
      } else if (iter_1->Ikey_chksum() > iter_3->Ikey_chksum()) {
        iter_3++;
      } else if (iter_1->Ikey_chksum() == iter_3->Ikey_chksum()) {
        if (iter_1->Ipath_num() != 0) {
          Push_back_issue(iter_1->Issue(), iter_3->Issue(), SIMP_CURRENT);
          iter_3->Set_ipath_num(0); // reset the num of issue grp is 0
          iter_1->Set_ipath_num(0); // reset the num of issue grp is 0
        }
        iter_3++;
        iter_1++;
      }
    }

    iter_3 = iter3.begin();
    // this loop compare F/E
    while (iter_2 != iter2.end() && iter_3 != iter3.end()) {
      if (iter_2->Ikey_chksum() < iter_3->Ikey_chksum()) {
        iter_2++;
      } else if (iter_2->Ikey_chksum() > iter_3->Ikey_chksum()) {
        iter_3++;
      } else if (iter_2->Ikey_chksum() == iter_3->Ikey_chksum()) {
        if (iter_2->Ipath_num() != 0) {
          iter_3->Set_ipath_num(0); // reset the num of issue grp is 0
          iter_2->Set_ipath_num(0); // reset the num of issue grp is 0
        }
        iter_3++;
        iter_2++;
      }
    }
  }

  iter_1 = iter1.begin();
  iter_2 = iter2.begin();
  while (iter_1 != iter1.end() && iter_2 != iter2.end()) {
    if (iter_1->Ikey_chksum() < iter_2->Ikey_chksum()) {
      iter_1++;
    } else if (iter_1->Ikey_chksum() > iter_2->Ikey_chksum()) {
      iter_2++;
    } else if (iter_1->Ikey_chksum() == iter_2->Ikey_chksum()) {
      if (iter_1->Ipath_num() != 0) {
        Push_back_issue(iter_1->Issue(), iter_2->Issue(), SIMP_CURRENT);
        if (kind == COMPARE_N_E) {
          // also add existing issues to line number change issues.
          Push_back_issue(iter_2->Issue(), SIMP_CURRENT);
        }
      }
      iter_1->Set_ipath_num(0); // reset the num of issue grp is 0
      iter_2->Set_ipath_num(0); // reset the num of issue grp is 0
      iter_1++;
      iter_2++;
    }
  } // while loop

  // if the vector of Line number change is not empty, need group it too
  // when issues of each vector is not empty at last, move these to related vector for writing results
  if (!Ci_simpdiff().empty()) {
    if (Ci_simpdiff()[0].Issue() != NULL) {
      Ikey_hash_count(Ci_simpdiff(), Ikey_grp_l(), false);
      Sort(COMPARE_L);
    }
  }
  int vec_l_size = Ikey_grp_l().size();
  fprintf(Logfile(), "\nThe size of vec of line number change %d\n", vec_l_size);
  int idx1 = 0, idx2 = 0, idx3 = 0, idx4 = 0;
  iter_1 = iter1.begin();
  iter_2 = iter2.begin();
  iter_3 = iter3.begin();

  // move remaining issues to related vector for writing results
  while (iter_1 < iter1.end() && idx1 < vec_l_size) {
    if (iter_1->Ipath_num() != 0) {
      if (iter_1->Ikey_chksum() < Ikey_grp_l()[idx1].Ikey_chksum()) {
        Push_back_issue(iter_1->Issue(), kind2);
	iter_1->Set_ipath_num(0);
        iter_1++;
      } else if (iter_1->Ikey_chksum() > Ikey_grp_l()[idx1].Ikey_chksum()) {
        idx1++;
      } else {
        if (Ikey_grp_l()[idx1].Ipath_num() != 0) {
          Push_back_issue(Ikey_grp_l()[idx1].Issue(), Ikey_grp_l()[idx1].Issue(), SIMP_CURRENT);
          Ikey_grp_l()[idx1].Set_ipath_num(0);
        }
	iter_1->Set_ipath_num(0);
        iter_1++;
        idx1++;
      }
    } else {
      iter_1++;
    }
  }
  if (iter_1 != iter1.end()) {
    for (;iter_1 < iter1.end(); iter_1++) {
      if (iter_1->Ipath_num() != 0) {
        Push_back_issue(iter_1->Issue(), kind2);
	iter_1->Set_ipath_num(0);
      }
    }
  }

  while (iter_2 < iter2.end() && idx2 < vec_l_size) {
    if (iter_2->Ipath_num() != 0) {
      if (iter_2->Ikey_chksum() < Ikey_grp_l()[idx2].Ikey_chksum()) {
        Push_back_issue(iter_2->Issue(), kind3);
	iter_2->Set_ipath_num(0);
        iter_2++;
      } else if (iter_2->Ikey_chksum() > Ikey_grp_l()[idx2].Ikey_chksum()) {
        idx2++;
      } else {
        if (Ikey_grp_l()[idx2].Ipath_num() != 0) {
          Push_back_issue(Ikey_grp_l()[idx2].Issue(), iter_2->Issue(), SIMP_CURRENT);
          Ikey_grp_l()[idx2].Set_ipath_num(0);
        }
	iter_2->Set_ipath_num(0);
        iter_2++;
        idx2++;
      }
    } else {
      iter_2++;
    }
  }
  if (iter_2 != iter2.end()) {
    for (;iter_2 < iter2.end(); iter_2++) {
      if (iter_2->Ipath_num() != 0) {
        Push_back_issue(iter_2->Issue(), kind3);
	iter_2->Set_ipath_num(0);
      }
    }
  }

  if (kind == COMPARE_N_F_E) {
    while (iter_3 < iter3.end() && idx3 < vec_l_size) {
      if (iter_3->Ipath_num() != 0) {
        if (iter_3->Ikey_chksum() < Ikey_grp_l()[idx3].Ikey_chksum()) {
          Push_back_issue(iter_3->Issue(), kind4);
	  iter_3->Set_ipath_num(0);
          iter_3++;
        } else if (iter_3->Ikey_chksum() > Ikey_grp_l()[idx3].Ikey_chksum()) {
          idx3++;
        } else {
          if (Ikey_grp_l()[idx3].Ipath_num() != 0) {
            Push_back_issue(Ikey_grp_l()[idx3].Issue(), iter_3->Issue(), SIMP_CURRENT);
            Ikey_grp_l()[idx3].Set_ipath_num(0);
          }
	  iter_3->Set_ipath_num(0);
          iter_3++;
          idx3++;
        }
      } else {
        iter_3++;
      }
    }
    if (iter_3 != iter3.end()) {
      for (;iter_3 < iter3.end(); iter_3++) {
        if (iter_3->Ipath_num() != 0) {
          Push_back_issue(iter_3->Issue(), kind4);
	  iter_3->Set_ipath_num(0);
        }
      }
    }
  }
  for (;idx4 < vec_l_size; idx4++) {
    if (Ikey_grp_l()[idx4].Ipath_num() != 0) {
      Push_back_issue(Ikey_grp_l()[idx4].Issue(), SIMP_CURRENT);
    }
  }

}



// =============================================================================
//
// Contain_valid_issue: used to check if the vector has the valid issue.
//                 if contains valid issue return true, else return false.
//
// =============================================================================
BOOL
FIND_MATCH::Contain_valid_issue(CI_VEC& issue_vec)
{
  int vec_size = (int)issue_vec.size();
  if (vec_size > 0) {
    for (int i = 0; i < vec_size; i++) {
      if (issue_vec[i].Issue() != NULL) {
        return true;
      }
    }
  }

  return false;
}

// =============================================================================
//
// Group_diff_results: After issues diff, group the issues to the same issuegrp
//                     from ntxt, ftxt and etxt
//
//                     For one grp:
//                     When one issue group(key) is new, the issue grp is 'N'
//                     When one issue group(key) is fixed, the issue grp is 'F'
//                     Whatever issue path be changed, the issue grp is 'L'
//                     If no any changed, the issue grp is 'E'
//
// =============================================================================
INT
FIND_MATCH::Group_diff_results(const char* E_scan_id)
{
  int N_size = (int)Ci_filtdiff().size();
  int F_size = (int)Bi_filtdiff().size();
  int L_size = (int)Ci_simpdiff().size();
  int E_size = (int)Bi_vec().size();
  fprintf(Logfile(), "\nThe size of N vec %d\n", N_size);
  fprintf(Logfile(), "\nThe size of F vec %d\n", F_size);
  fprintf(Logfile(), "\nThe size of L vec %d\n", L_size);
  fprintf(Logfile(), "\nThe size of E vec %d\n", E_size);
  // when N/F/E are not empty, if one issue key from N & E & F, it should be 'L'
  if (!Bi_filtdiff().empty() && !Ci_filtdiff().empty() && !Bi_vec().empty()) {
    if (Contain_valid_issue(Bi_filtdiff()) && Contain_valid_issue(Ci_filtdiff()) && Contain_valid_issue(Bi_vec())) {
        Ikey_hash_count(Ci_filtdiff(), Ikey_grp_n(), false);
        Ikey_hash_count(Bi_filtdiff(), Ikey_grp_f(), true);
        Ikey_hash_count(Bi_vec(), Ikey_grp_e(), true);
        Sort(COMPARE_N_F_E);
        Order_vec_diff(Ikey_grp_n(), Ikey_grp_f(), Ikey_grp_e(), COMPARE_N_F_E,
                       SIMP_CURRENT, FILT_CURRENT, FILT_BASELINE, VTXT_EBASE, E_scan_id);
        fprintf(Logfile(), "%sDUMP AFTER GROUP DIFF RESULTS\n%s\n", SEPARATOR_d, SEPARATOR_d);
        Print(Logfile());
        return 0;
    }
  }

  // when N/F are not empty, if one issue key from N & F, it should be 'L'
  if (!Bi_filtdiff().empty() && !Ci_filtdiff().empty()) {
    if (Contain_valid_issue(Bi_filtdiff()) && Contain_valid_issue(Ci_filtdiff())) {
        Ikey_hash_count(Ci_filtdiff(), Ikey_grp_n(), false);
        Ikey_hash_count(Bi_filtdiff(), Ikey_grp_f(), true);
        Sort(COMPARE_N_F);
        Order_vec_diff(Ikey_grp_n(), Ikey_grp_f(), Ikey_grp_e(), COMPARE_N_F,
                       SIMP_CURRENT, FILT_CURRENT, FILT_BASELINE, VTXT_EBASE, E_scan_id);
        fprintf(Logfile(), "%sDUMP AFTER GROUP DIFF RESULTS\n%s\n", SEPARATOR_d, SEPARATOR_d);
        Print(Logfile());
        return 0;
    }
  }

  // when N/E are not empty, if one issue key from N & E, it should be 'L'
  if (!Ci_filtdiff().empty() && !Bi_vec().empty()) {
    if (Contain_valid_issue(Ci_filtdiff()) && Contain_valid_issue(Bi_vec())) {
        Ikey_hash_count(Ci_filtdiff(), Ikey_grp_n(), false);
        Ikey_hash_count(Bi_vec(), Ikey_grp_e(), true);
        Sort(COMPARE_N_E);
        Order_vec_diff(Ikey_grp_n(), Ikey_grp_e(), Ikey_grp_f(), COMPARE_N_E,
                       SIMP_CURRENT, FILT_CURRENT, VTXT_EBASE, FILT_BASELINE, E_scan_id);
        fprintf(Logfile(), "%sDUMP AFTER GROUP DIFF RESULTS\n%s\n", SEPARATOR_d, SEPARATOR_d);
        Print(Logfile());
        return 0;
    }
  }

  // when F/E are not empty, if one issue key from F & E, it should be 'L'
  if (!Bi_filtdiff().empty() && !Bi_vec().empty()) {
    if (Contain_valid_issue(Bi_filtdiff()) && Contain_valid_issue(Bi_vec())) {
        Ikey_hash_count(Bi_filtdiff(), Ikey_grp_f(), true);
        Ikey_hash_count(Bi_vec(), Ikey_grp_e(), true);
        Sort(COMPARE_F_E);
        Order_vec_diff(Ikey_grp_e(), Ikey_grp_f(), Ikey_grp_n(), COMPARE_F_E,
                       SIMP_CURRENT, VTXT_EBASE, FILT_BASELINE, FILT_CURRENT, E_scan_id);
        fprintf(Logfile(), "%sDUMP AFTER GROUP DIFF RESULTS\n%s\n", SEPARATOR_d, SEPARATOR_d);
        Print(Logfile());
        return 0;
    }
  }

  // when N/L are not empty, if one issue key from N & L, it should be 'L'
  if (!Ci_filtdiff().empty() && !Ci_simpdiff().empty()) {
    if (Contain_valid_issue(Ci_filtdiff()) && Contain_valid_issue(Ci_simpdiff())) {
        Ikey_hash_count(Ci_filtdiff(), Ikey_grp_n(), false);
        Ikey_hash_count(Ci_simpdiff(), Ikey_grp_l(), false);
        Sort(COMPARE_N_L);
        Order_vec_diff(Ikey_grp_n(), Ikey_grp_l(), Ikey_grp_f(), COMPARE_N_L,
                       SIMP_CURRENT, FILT_CURRENT, SIMP_CURRENT, FILT_BASELINE, E_scan_id);
        fprintf(Logfile(), "%sDUMP AFTER GROUP DIFF RESULTS\n%s\n", SEPARATOR_d, SEPARATOR_d);
        Print(Logfile());
        return 0;
    }
  }

  // when F/L are not empty, if one issue key from F & L, it should be 'L'
  if (!Bi_filtdiff().empty() && !Ci_simpdiff().empty()) {
    if (Contain_valid_issue(Bi_filtdiff()) && Contain_valid_issue(Ci_simpdiff())) {
        Ikey_hash_count(Bi_filtdiff(), Ikey_grp_f(), true);
        Ikey_hash_count(Ci_simpdiff(), Ikey_grp_l(), false);
        Sort(COMPARE_F_L);
        Order_vec_diff(Ikey_grp_f(), Ikey_grp_l(), Ikey_grp_n(), COMPARE_F_L,
                       SIMP_CURRENT, FILT_BASELINE, SIMP_CURRENT, FILT_BASELINE, E_scan_id);
        fprintf(Logfile(), "%sDUMP AFTER GROUP DIFF RESULTS\n%s\n", SEPARATOR_d, SEPARATOR_d);
        Print(Logfile());
        return 0;
    }
  }

  // when L/E are not empty, if one issue key from L & E, it should be 'L'
  if (!Ci_simpdiff().empty() && !Bi_vec().empty()) {
    if (Contain_valid_issue(Ci_simpdiff()) && Contain_valid_issue(Bi_vec())) {
        Ikey_hash_count(Ci_simpdiff(), Ikey_grp_l(), false);
        Ikey_hash_count(Bi_vec(), Ikey_grp_e(), true);
        Sort(COMPARE_L);
        Order_vec_diff(Ikey_grp_l(), Ikey_grp_e(), Ikey_grp_n(), COMPARE_L,
                       SIMP_CURRENT, SIMP_CURRENT, VTXT_EBASE, FILT_CURRENT, E_scan_id);
        fprintf(Logfile(), "%sDUMP AFTER GROUP DIFF RESULTS\n%s\n", SEPARATOR_d, SEPARATOR_d);
        Print(Logfile());
        return 0;
    }
  }
}


// =============================================================================
//
// Write_files: Write final diff results to local file as output.
//
//              Issues remain in VTXT_CURRENT  are EQ those in VTXT_BASELINE
//              Issues exist  in SIMP_BASELINE are 'L', line changed
//              Issues exist  in FILT_CURRENT  are 'N', new
//              Issues exist  in FILE_BASELINE are 'F', fixed
//
// =============================================================================
void
FIND_MATCH::Write_files(FP_VEC& iterf, CI_VEC& iterc, const char *fn, const char* a, const char* s, const char* v, const char* m, Manage* manage)
{
  FILE *output_file = fopen(fn, "w");
  
  // Write fid_path part to otxt file.
  if (manage->Ver_cmp(0, 6, 0) >= 0 && manage->Ver_cmp(0, 7, 2) < 0)
    fprintf(output_file, "{\"%s\", %.5s, %s}\n", a, s, v);
  else
    fprintf(output_file, "{\"%s\", %.5s, %s,%s}\n", a, s, v, m);

  fprintf(output_file, "[\n"); // Write "[" as the start of fid_path.
  INT linecnt = 0;
  for ( FP_VEC::iterator iter1 = iterf.begin(); iter1 != iterf.end(); iter1++ ) {
    if (linecnt++ == 0) {
      fprintf(output_file, "  {\n");
    }
    else {
      fprintf(output_file, ",\n  {\n");
    }
    fprintf(output_file, "  \"fid\": %d,\n", (*iter1).Fid());
    fprintf(output_file, "  \"path\": \"%s\"\n", Change_to_current_scan_fpath((*iter1).Path()));
    fprintf(output_file, "  }");
  }

  fprintf(output_file, "\n]\n"); // Write "]" as the end of file_path.

  // Write all issues if it's not empty.
  if (!iterc.empty()) {
    for ( CI_VEC::iterator iter2 = iterc.begin(); iter2 != iterc.end(); iter2++ ) {
      if ( iter2->Issue() != NULL ) {
        fprintf(output_file, "%s\n", iter2->Issue());
      }
    }
  }

  fclose(output_file); 
}

// =============================================================================
// =============================================================================
char * Manage::skip_dlimiter(char *path, char d1, char d2)
{
  int j;
  char c;

  // we are guaranteed that path will end with ']' per previous call to get_varlen_str
  while (*path != d1 && *path != d2) {
    path++;
  }
  return path;
}


// =============================================================================
// =============================================================================
void Manage::skip_dlimiter(FILE *f, char d)
{
  int j;
  char c;
  j = fscanf(f, "%c", &c);
  if (d != c) {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file token error");
  }
}


// =============================================================================
// =============================================================================
FILE_PATH *Manage::make_fpath(char *s, int strtab_ofs, int id) 
{
  FILE_PATH *fp = (FILE_PATH *)malloc(sizeof(FILE_PATH));
  if (fp == 0) {
    handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory during file path");
  }
  fp->S(s); fp->Ofs(strtab_ofs); fp->Id(id);
  return fp; 
}


// =============================================================================
// =============================================================================
int Manage::get_1path_node(FILE *f, const char dlimiter, PATH_NODE &pn)
{
  // a path from core consist of a triple separated by PN_SEPERATOR
  int fid, line, pinfoid;
  int i = fscanf(f, "%d", &fid);
  if (i == EOF) {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : File ID error\n");
  }

  skip_dlimiter(f, PN_SEPARATOR);

  i = fscanf(f, "%d", &line);
  if (i == EOF) {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : line number error\n");
  }

  skip_dlimiter(f, PN_SEPARATOR);

  i = fscanf(f, "%d", &pinfoid);
  if (i == EOF) {
        handle_error((long)E_CSV_INVALID_INPUT_FILE," : path_info error\n");
  }

  pn.File_id(fid);
  pn.Line_num(line);
  pn.Node_desc(pinfoid);
  DBG_PRINTD("%d, ", fid);
  DBG_PRINTD("%d, ", line);
  DBG_PRINTD("%d\n", pinfoid);

  char c;   // either ",", "." or "]" expected
  i = fscanf(f, "%c", &c);

  if (c == PN_SEPARATOR)
    return 1;


  if (c == ']')
    return 0;

  return i;

}

// =============================================================================
// =============================================================================
void Manage::init_str_tab(const STR_TAB_T t)
{
  if (Strtab_sz(t) == 0) {
    // if empty, get memory and initialize first entry to be null
    char *p = (char *)malloc(Strtab_max(t));
    if (p == 0) {
      handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory\n");
    }
    // string table first entry is always null, our convention also add '\n' for Java sake
    Strtab(t, p);
    Strtab(t, '\0', JAVA_STRING_TERM);
    Strtab_sz(t, 2);
  }
  return;
}


// =============================================================================
// =============================================================================
void Manage::resize_str_tab(const STR_TAB_T t, const int len)
{
  // grow strtab
  char *p;
  bool done = false;
  int sz;

  do {
    sz = Strtab_grow_max(t);
    if ((sz - Strtab_sz(t)) > len)
      done = true;
  } while (!done);

  p = (char *)realloc((void *)Strtab(t), sz);
  if (p == NULL) {
    handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory\n");
  }
  Strtab(t, p);
  return;
}

// =============================================================================
// =============================================================================
int Manage::insert_str(const STR_TAB_T t,  const char *str)
{
  init_str_tab(t);
  int len = strlen(str)+1;
  if ((Strtab_sz(t) + len) >= Strtab_max(t)) {
    resize_str_tab(t, len);
  }
  strcpy((char *)(Strtab(t) + Strtab_sz(t)), str);
  DBG_PRINTDD("%s +%4x+\n", str,  Strtab_sz(t));
  int ret = Strtab_sz(t);
  Strtab_sz(t, Strtab_sz(t) + strlen(str)+1);
  return ret;
}


// =============================================================================
//
// returns NULL on error
//
// =============================================================================
char *Manage::get_varlen_str(FILE *in, char dlimiter_beg, char dlimiter_end)
{
  char *pstr = 0;
  size_t sz = STR_MALLOC_SZ;
  int i = 0;

  pstr = (char *)calloc(sz, sizeof(char));
  if (pstr == 0) {
    handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory");
  }

  int j = fscanf(in, "%c", &pstr[0]);

  if (j == EOF)  // done with conversion in reality
    return  (char *)-1;

  if (j != 1) {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file read error");
  }

  if (pstr[0] != dlimiter_beg) {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file token error");
  }

  while (i != sz) {
    if ((fscanf(in, "%c", &pstr[i])) == 1) {
      if (pstr[i] == dlimiter_end) {
        pstr[i] = '\0';
        //fprintf(match.Logfile(), "var_string_name:%s\n", pstr);
        return pstr;
      }

      i++;
      if (i == sz) {
    // buffer full, realloc
    char *p = (char *)realloc(pstr, (sz+sz));
    if (p == NULL) {
      handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory\n");
    }

    pstr = p;
    sz = sz*2;
      }
    }
  }

  return (char *)0;
}


// =============================================================================
//
// get_path_str: Used to parse fid & path in vtxt top part, get fid & path mapping.
//
// =============================================================================
FILE_PATH *Manage::get_path_str(char *path, char dlimiter_beg, char dlimiter_end)
{
  assert(path != 0);
  // path should now be consists of string enclosed with dlimiter_beg and dlimiter_end
  // we do not need to worry about "\0' in between
  
  char *start_path = path;
  while (path != 0 && *path != dlimiter_beg && *path != '\0') {
    // skip to first char in path group
    path++;
  }
  
  if (path == 0 || *path == 0 || *path == dlimiter_end) {
   
  }
  
  path++;
  // inside one path group
  // get to one space after ':'
  while (*path != ':')
    path++;
  
  // get true fid in .vtxt used in path_node of vtxt
  // skip blank
  path++;
  if (*path == ' ') path++;
  // form the numeric fid value
  int true_fid = 0;
  while (*path >= '0' && *path <= '9') {
    true_fid = true_fid * 10 + ((*path)-'0');
    path++;
  }

  path++;
  while (*path != ':')
    path++;

  if (*++path != ' ') {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file token error");
  }
  path++;

  // skip the first quote to get path str.
  if (*path == '"') path++;

  // start of one path that ends at '"'
  int len = 0;
  while (path[len] != '"') {
    len++;
  }
  char *s = (char *)calloc(len+1, sizeof(char));
  if (s == 0) {
    handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory");
  }
  strncpy(s, path, len);

  FILE_PATH *filepath = make_fpath(s, path-start_path+len, true_fid);
  return filepath;  // caller must free this filepath
}

// =============================================================================
//
// validate_file_attr: validate file attribute V for first scan(No DSR)
//                     validate file attribute N/L/E/F for second scan(DSR)
//
// =============================================================================
#define ATTR_LEN 100
BOOL
Manage::validate_file_attr(VTXT_KIND kind, char *attr)
{
  Manage     manage;
  FIND_MATCH match(&manage);
  char a[ATTR_LEN];
  char scan_id[ATTR_LEN];
  char version[ATTR_LEN];
  char scanmode[ATTR_LEN];
  int  maj_ver  = 0;
  int  min_ver  = 0;
  int  mmin_ver = 0;
  sscanf(attr, "%[^,], %[^,], %[^,],%s", a, scan_id, version, scanmode);
  sscanf(version, "%d.%d.%d", &maj_ver, &min_ver, &mmin_ver);
  Major_ver(maj_ver); Minor_ver(min_ver); MMinor_ver(mmin_ver);

  switch (kind) {
  case VTXT_NBASE:
    N_attr_scanid(scan_id);
    return a[1] == 'N'; break;
  case VTXT_LBASE:
    L_attr_scanid(scan_id);
    return a[1] == 'L'; break;
  case VTXT_EBASE:
    E_attr_scanid(scan_id);
    return a[1] == 'E'; break;
  case VTXT_FBASE:
    F_attr_scanid(scan_id);
    return a[1] == 'F'; break;
  case VTXT_BASELINE:
  case VTXT_CURRENT:
    V_attr_scanid(scan_id);
    Version(version);
    Scanmode(scanmode);
    return a[1] == 'V'; break;
  default:
    return FALSE;
    break;
  }
}

// =============================================================================
//
// Scan through filepath table and count the number of lines it takes
//
// =============================================================================
int Manage::cvt2csv(FILE *in, FIND_MATCH *fm,  VTXT_KIND kind, FP_VEC &fpv)
{
  assert(in != 0);

  char c;
  int  j;
  int  max_fileid = 0;
  int  start_ln = 0;
  char *ignore;
  char *path = (char *)0;
  char *fileattr = (char *)0;
  bool done = false;

  //vector< pair<int, char*> >  str_idx_tab;  // vector of <offset>
  //vector< pair<int, string> >  str_idx_tab;  // vector of <offset>
  fileattr = get_varlen_str(in, '{', '}');
  skip_dlimiter(in, '\n');
  if (fileattr == (char *)-1) // missing file attribute N, L, E, V, F
    return 0;
  if (validate_file_attr(kind, fileattr) == FALSE)
    return 0;

  // first prtion is path names, enclosed with '[' and ']'
  // path will be broken up into an array of paths
  path = get_varlen_str(in, '[', ']');
  if (path == (char *)-1) // missing path table
    return 0;

  do {
    // path delimiters are "{}" pair
    FILE_PATH *one_path = get_path_str(path, '{', '}');
    if (one_path->S() == (char *)-1)   // read end of file, error
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file - read path error\n");

    path = path + one_path->Ofs();
    path = skip_dlimiter(path, ',', '\0');

    if (*path != ',') {
      if (*path == '\0') {  // end of path was ']' has been replaced with '\0'
        // end of paths portion
        skip_dlimiter(in, '\n');
        done = true;
      }
    }

    char *var_path = one_path->S();
    int   fid = one_path->Id();
    // make a copy here.  Push_back does not know what to clone
    char *path = Clone_data(var_path);
    FID_PATH fp(fid, path);
    fpv.push_back(fp);
    fm->Push_back(fp);
    free(one_path->S());
    free(one_path);

    max_fileid++;

  } while (!done);

  start_ln = 4 * max_fileid + 3;
  if (start_ln > 0) {
    return start_ln;
  }
  return -1;
}

// =============================================================================
//
// Entry point for vtxt_diff
//
// =============================================================================
int main(int argc, char **argv)
{
  Manage     manage;
  FIND_MATCH match(&manage);
  int input_f = 0; // the number of input files, V or N/L/E/F txt files.

  clock_t vtxt_diff_start = clock();
  input_f = match.Process_option(argc, argv);
  match.Read_files(); 

  if (input_f == 1) {
    match.Write_files(match.C_fid_path(), match.Ci_vec(), N_TXT, ATTR_TXT_N, manage.V_attr_scanid(), manage.Version(), manage.Scanmode(), &manage);
    match.Write_files(match.C_fid_path(), match.Ci_filtdiff(), F_TXT, ATTR_TXT_F, manage.V_attr_scanid(), manage.Version(), manage.Scanmode(), &manage);
    match.Write_files(match.C_fid_path(), match.Ci_filtdiff(), L_TXT, ATTR_TXT_L, manage.V_attr_scanid(), manage.Version(), manage.Scanmode(), &manage);
    match.Write_files(match.C_fid_path(), match.Ci_filtdiff(), E_TXT, ATTR_TXT_E, manage.V_attr_scanid(), manage.Version(), manage.Scanmode(), &manage);
  }
  if (input_f == 5) {
    match.Simple_diff(match.Bi_vec(), match.Ci_vec(), SIMP_BASELINE, SIMP_CURRENT, match.E_fid_path(), match.C_fid_path());
    match.Update_lineno_diff(&manage, match.E_fid_path(), match.C_fid_path());
    // TODO: refactor this logic in release 2.1, simplify full flow and logic.
    match.Group_diff_results(manage.E_attr_scanid());

    match.Write_files(match.E_fid_path(), match.Bi_filtdiff(), F_TXT, ATTR_TXT_F, manage.E_attr_scanid(), manage.Version(), manage.Scanmode(), &manage);
    match.Write_files(match.E_fid_path(), match.Bi_vec(), E_TXT, ATTR_TXT_E, manage.E_attr_scanid(), manage.Version(), manage.Scanmode(), &manage);
    match.Write_files(match.C_fid_path(), match.Ci_filtdiff(), N_TXT, ATTR_TXT_N, manage.V_attr_scanid(), manage.Version(), manage.Scanmode(), &manage);
    match.Write_files(match.C_fid_path(), match.Ci_simpdiff(), L_TXT, ATTR_TXT_L, manage.E_attr_scanid(), manage.Version(), manage.Scanmode(), &manage);
  }

  // Add one logic to count the time usage of vtxt_diff, and write it to logfile when use "-d" option
  clock_t vtxt_diff_end = clock();
  match.Vtxt_diff_time(static_cast<double>(vtxt_diff_end - vtxt_diff_start)/CLOCKS_PER_SEC);
  if (match.Logfile() != stdout) {
    fprintf(match.Logfile(), "\nThe time usage of vtxt_diff is %lfs \n", match.Vtxt_diff_time());
    fprintf(match.Logfile(), "If the partial scan: %d\n", match.Partial_scan());
    fclose(match.Logfile());
  }
  return 0;
}
