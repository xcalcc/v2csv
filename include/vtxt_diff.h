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

#ifndef VTXT_DIFF_H
#define VTXT_DIFF_H

#include <vector>
#include "commondefs.h"
#include "filepath.h"

#define STRING_LENTH 64

#define F_TXT "xvsa-xfa-dummy.ftxt" // DSR output file include fixed issues
#define N_TXT "xvsa-xfa-dummy.ntxt" // DSR output file include new   issues
#define L_TXT "xvsa-xfa-dummy.ltxt" // DSR output file include line no changed issues
#define E_TXT "xvsa-xfa-dummy.etxt" // DSR output file include no change issues
#define M_TXT "xvsa-xfa-dummy.mtxt" // Merged output file from multiple vtxt files

#define ATTR_TXT_N "N"  // File attribute when write ntxt file header
#define ATTR_TXT_L "L"  // File attribute when write ltxt file header
#define ATTR_TXT_E "E"  // File attribute when write etxt file header
#define ATTR_TXT_F "F"  // File attribute when write ftxt file header

/*
typedef struct {
  char *cmplx;         // complexity in vtxt
//char *ec;            // error code in vtxt in [ec@fn1:ln1]
//char *fn1;           // file name  in vtxt in [ec@fn1:ln1]
//INT  ln1;            // line no    in vtxt in [ec@fn1:ln1]
  char *fn;            // file name  in vtxt
  INT  fid2;           // file id    in vtxt in [fid2:ln2]
  INT  ln2;            // line no    in vtxt in [fid2:ln2]
  char *cat;           // category   in vtxt default is Vul
  char *dm;            // D or M     in vtxt
  char *hc;            // hard code  in vtxt default is [1,0,0]
  char *vn;            // var name   in vtxt
  char *fn;            // func name  in vtxt
} regular_part;

typedef struct {
  regular_part rgpart; // regular part data
  char         *rbc;   // hard code str "RBC"
  char         *cec;   // cert error code in vtxt
  char         *cert;  // hard code str "CERT"
  vector<>     path;   // nested store line str
} cert_part;

type struct {
  regular_part rgpart; // regular part data
  char         *bec;   // builtin error code
  vector<>     path;   // nested store line str
} builtin_part;

class ISSUE {
  bool cert;           // mark this issue as CERT 
  bool builtin;        // mark this issue as BUILTIN
  union issue_part {
    builtin_part *blt;
    cert_part    *cpt;
  };
};
*/

class Manage;
class VTXT_ISSUE;

typedef enum {
  OPER_INSERT = 1,
  OPER_DELETE = 2,
} OPER;

typedef enum {
  INVALID_VTXTID = 0,
  BASE_VTXTID    = INVALID_VTXTID+1,
} VTXTID;

typedef enum {        // TODO: This enum is temporary enum for 2.0 release, need refact it in next release
  COMPARE_N_F_E = 1,  // This kind is one flag to group issues from New, Fixed and Existing
  COMPARE_N_F   = 2,  // This kind is one flag to group issues from New, Fixed
  COMPARE_N_E   = 3,  // This kind is one flag to group issues from New, Existing
  COMPARE_F_E   = 4,  // This kind is one flag to group issues from Fixed, Existing
  COMPARE_N_L   = 5,  // This kind is one flag to group issues from New, line change
  COMPARE_F_L   = 6,  // This kind is one flag to group issues from Fixed, line change
  COMPARE_L     = 7,  // This kind is one flag to group issues from Line number change
} COMPARE_KIND;

class LINEMAP {
private:
  INT  _old_ln;
  INT  _new_ln;
#if 0
  LINEMAP(void);                          // REQUIRED UNDEFINED UNWANTED methods
  LINEMAP(const LINEMAP&);              // REQUIRED UNDEFINED UNWANTED methods
  LINEMAP& operator = (const LINEMAP&); // REQUIRED UNDEFINED UNWANTED methods
#endif
public:
  LINEMAP(INT ol, INT nl) : _old_ln(ol), _new_ln(nl) { }
  ~LINEMAP(void) {}
  
  INT   Old_ln(void)     	  { return _old_ln; }
  void  Set_old_ln(INT o) 	  {  _old_ln = o; }
  INT   New_ln(void)     	  { return _new_ln; }
  void  Set_new_ln(INT n)         {  _new_ln = n; }
  void  Print(FILE *fp);
};

class MAGIC_PAIR {
  INT   _ln_limit;
  //INT   _last_change;
  OPER  _operation;
  INT   _ln_change;
#if 0
  MAGIC_PAIR(void);                           // REQUIRED UNDEFINED UNWANTED methods
  MAGIC_PAIR(const MAGIC_PAIR&);              // REQUIRED UNDEFINED UNWANTED methods
  MAGIC_PAIR& operator = (const MAGIC_PAIR&); // REQUIRED UNDEFINED UNWANTED methods
#endif
public:
  MAGIC_PAIR(INT ll, INT lchange, char *opr) : _ln_limit(ll),
                                               _ln_change(lchange)
                           { _operation=(opr[0] == '+')? OPER_INSERT : OPER_DELETE; }
  ~MAGIC_PAIR(void) {}

  INT   Ln_limit(void)             { return _ln_limit; }
  //INT   Last_change(void)          { return _last_change; }
  OPER  Operation(void)            { return _operation; }
  INT   Ln_change(void)            { return _ln_change; }
  void  Print(FILE *fp);
};

typedef vector<LINEMAP> LP_VEC;

class LINE_MATCH {
private:
  char       *_fname;
  INT         _file_id;
  MAGIC_PAIR  _magic;
  LP_VEC      _line_map;

#if 0
  LINE_MATCH(void);                           // REQUIRED UNDEFINED UNWANTED methods
  LINE_MATCH(const LINE_MATCH&);              // REQUIRED UNDEFINED UNWANTED methods
  LINE_MATCH& operator = (const LINE_MATCH&); // REQUIRED UNDEFINED UNWANTED methods
#endif

  void        Set_fname(char * fname) { _fname = Clone_data(fname); }
  
public:

  LINE_MATCH(char *fname, MAGIC_PAIR mp) : _magic(mp), _file_id(0) { Set_fname(fname); }
  LINE_MATCH(char *fname, INT ll, INT lc, char *opr) : _magic(ll, lc, opr) { Set_fname(fname); Set_file_id(0); }
  ~LINE_MATCH(void) { if (_fname) free(_fname); }

  char       *Fname(void)             { return _fname; }
  void        Set_file_id(INT fid)    { _file_id = fid; }
  INT         File_id(void)           { return _file_id; }
  MAGIC_PAIR& Magic(void)             { return _magic; }
  LP_VEC&     Line_map(void)          { return _line_map; }
  void        Push_back(LINEMAP  lp)  { _line_map.push_back(lp); }
  void        Print(FILE *fp);
//  void Read_ln(char *f);
};

typedef vector<LINE_MATCH *> LM_VEC;

class CHECKSUM_ISSUES {
private:
  //INT     _start_ln;
  size_t  _checksum;
  char   *_issue;

#if 0
  CHECKSUM_ISSUES(void);                      // REQUIRED UNDEFINED UNWANTED methods
  CHECKSUM_ISSUES(const CHECKSUM_ISSUES&);    // REQUIRED UNDEFINED UNWANTED methods
  CHECKSUM_ISSUES& operator = (const CHECKSUM_ISSUES&); // REQUIRED UNDEFINED UNWANTED methods
#endif

public:
  CHECKSUM_ISSUES(size_t chksum, string is):
    _checksum(chksum) { _issue = Clone_data((char *)is.c_str()); }
  CHECKSUM_ISSUES(size_t chksum, char *is): _checksum(chksum), _issue(is) {}
  //~CHECKSUM_ISSUES(void) { if (_issue) free(_issue); }
  ~CHECKSUM_ISSUES(void) { }

 // INT    Start_ln(void)              { return _start_ln; }
  size_t Checksum(void)              { return _checksum; }
  void   Set_checksum(size_t c)      { _checksum = c; }
  char  *Issue(void)                 { return _issue; }
  // Giveup give up _issue to caller
  char  *Giveup(void)                { char* sav = _issue; _issue=NULL; return sav; }
  void   Print(FILE *fp);
};

typedef vector<CHECKSUM_ISSUES > CI_VEC;
BOOL    Compare_checksum(CHECKSUM_ISSUES c1, CHECKSUM_ISSUES c2) {
  return (c1.Checksum() < c2.Checksum());
}

class IKEY_GRP {
private:
  INT            _ipath_num;   // the number of issue path of one issue group
  size_t         _ikey_chksum; // checksum of issue key from one issue group
  vector<char*>  _issue;       // one issue path

public:
  IKEY_GRP(): _ipath_num(0) {}
  IKEY_GRP(INT num, size_t chksum): _ipath_num(num), _ikey_chksum(chksum) {}

  void           Set_ipath_num(void)       { _ipath_num++; }
  void           Set_ipath_num(int n)      { _ipath_num = n; }
  INT            Ipath_num(void)           { return _ipath_num; }
  void           Set_ikey_chksum(size_t c) { _ikey_chksum = c; }
  size_t         Ikey_chksum(void)         { return _ikey_chksum; }
  void           Set_issue(char* i)        { _issue.push_back(i); }
  vector<char*>& Issue(void)               { return _issue; }
};

typedef vector<IKEY_GRP> IG_VEC;
BOOL    Compare_key_chksum(IKEY_GRP c1, IKEY_GRP c2) {
  return (c1.Ikey_chksum() < c2.Ikey_chksum());
}


class FIND_MATCH {
private:
  char	  *_git_diff_results;
  char 	  *_current_vtxt;
  char    *_baseline_vtxt;
  char    *_nbaseline_vtxt;
  char    *_fbaseline_vtxt;
  char    *_lbaseline_vtxt;
  char    *_ebaseline_vtxt;
  Manage  *_manager;
  LM_VEC   _lm_vec;          // Line map imported from git diff
  CI_VEC   _ci_vec;          // Current scan vtxt Hashed Issue List
  CI_VEC   _bi_vec;          // Baseline scan vtxt Hashed Issue List
  CI_VEC   _ci_simpdiff;     // Issue added in current scan w/o screening
  CI_VEC   _bi_simpdiff;     // Issue fixed in Baseline scan w/o screening
  CI_VEC   _ci_filtdiff;     // Issue added in current scan post filtering
  CI_VEC   _bi_filtdiff;     // Issue fixed in Baseline scan post filtering
  FP_VEC   _c_fid_path;      // FID_PATH vector of current scan
  FP_VEC   _b_fid_path;      // FID_PATH vector of baseline scan
  FP_VEC   _e_fid_path;      // FID_PATH vector of existing scan
  FP_VEC   _l_fid_path;      // FID_PATH vector of line change scan
  FP_VEC   _n_fid_path;      // FID_PATH vector of new issues scan
  FP_VEC   _f_fid_path;      // FID_PATH vector of fix issues scan
  IG_VEC   _ikey_grp_n;      // IKEY_GRP vector of new issues before writing to ntxt
  IG_VEC   _ikey_grp_f;      // IKEY_GRP vector of fix issues before writing to ftxt
  IG_VEC   _ikey_grp_e;      // IKEY_GRP vector of existing issues before writing to etxt
  IG_VEC   _ikey_grp_l;      // IKEY_GRP vector of line no change issues before writing to etxt
  GLB_FP   _glb_fp;          // Global Fid_Path 
  INT      _vtxt_id;
  char    *_src_file_json;   // read source_files.json file when partial scan
  BOOL     _partial_scan;    // When project build has no clean, DSR do partial diff
  CI_VEC   _src_f_json_vec;  // reuse CI_VEC to store chksum & file path to vec
  char    *_baseline_project_path;   //baseline project path (CI/CD will map to two project in xcalscan product)
  char    *_current_project_path;    //current project path


  LM_VEC&  Lm_vec(void)      { return _lm_vec; }

  FIND_MATCH(const FIND_MATCH&);              // REQUIRED UNDEFINED UNWANTED methods
  FIND_MATCH& operator = (const FIND_MATCH&); // REQUIRED UNDEFINED UNWANTED methods

  char    *Git_diff_results(void)         { return _git_diff_results; }
  char    *Baseline_vtxt(void)            { return _baseline_vtxt; }
  char    *Nbaseline_vtxt(void)           { return _nbaseline_vtxt; }
  char    *Fbaseline_vtxt(void)           { return _fbaseline_vtxt; }
  char    *Lbaseline_vtxt(void)           { return _lbaseline_vtxt; }
  char    *Ebaseline_vtxt(void)           { return _ebaseline_vtxt; }
  char    *Current_vtxt(void)             { return _current_vtxt; }

  GLB_FP&  Glb_fp(void)                   { return _glb_fp; }
  INT      Enter_glb_fp(INT fid, char *p) { _glb_fp.Enter_glb_fp(Vtxt_id(), fid, p); }
  INT      New_vtxt_id(void)              { ++_vtxt_id; return _vtxt_id; }
  INT      Vtxt_id(void)                  { return _vtxt_id; }
  void     Verify_fid_path_consistency(void);

  Manage  *Manager(void)                  { return _manager; }
  void     Push_back(LINE_MATCH *lm)      { _lm_vec.push_back(lm); }
  void     Sort(VTXT_KIND kind);
  void     Sort(COMPARE_KIND kind);
  INT      Find_cur_ln(INT fid, INT base_ln);

  //void     Make_pair(size_t chksum, string is) { make_pair(chksum, is); }

  void     Print_option_guide(char *arg) {
    printf("Unrecognized Option: \"%s\"\n", arg);
    printf("Usage: [The first  scan(no DSR)] ./vtxt_diff -c xvsa-xfa-dummy.mtxt \n");
    printf("Usage: [The second scan(DSR)]    ./vtxt_diff -g git_diff_line_map -n xvsa-xfa-dummy.ntxt -l xvsa-xfa-dummy.ltxt -e xvsa-xfa-dummy.etxt -c xvsa-xfa-dummy.mtxt [ -d ${log_file_path} ] [-b baseline_project_path] [-o current_project_path(should use with -b option together)]\n");
  }

  void     Read_gdiff_file(void);
  void     Regex_match(string s);

  FILE    *Read_vtxt_filehdr(char *vtxt_file, INT& istart_line, VTXT_KIND k, FP_VEC& mf);
  void     Read_vtxt_file(char *vtxt_file, VTXT_KIND kind, FP_VEC& mf);
  void     Hash_issue(char *fp, INT sl, VTXT_KIND kind);

  void     Fname2fid(FP_VEC& fid_path); // map fname to fid in LINEMAP results.
  char    *Src_file_json(void)            { return _src_file_json; }
  BOOL     Filt_diff(char *issue, FP_VEC& fid_path, FP_VEC& c_fid_path);
  int      Read_src_file_json(char *src_file_json, VTXT_KIND kind, CI_VEC& sf_vec);


public:
  FIND_MATCH(Manage *m):_git_diff_results(NULL),
                        _baseline_vtxt(NULL),
                        _nbaseline_vtxt(NULL),
                        _fbaseline_vtxt(NULL),
                        _lbaseline_vtxt(NULL),
                        _ebaseline_vtxt(NULL),
                        _current_vtxt(NULL),
                        _logfile(stdout),
                        _vtxt_id(INVALID_VTXTID),
                        _manager(m),
                        _src_file_json(NULL),
                        _partial_scan(false),
                        _baseline_project_path(NULL),
                        _current_project_path(NULL) {}


  FILE    *_logfile;         // Log file to store debug print to log file
  double   _vtxt_diff_time;  // time usage of vtxt_diff, write it to log file default
  FILE    *Logfile(void)             { return _logfile; }
  void     Vtxt_diff_time(double t)  { _vtxt_diff_time = t; }
  double   Vtxt_diff_time(void)      { return _vtxt_diff_time; }
  CI_VEC&  Ci_vec(void)              { return _ci_vec; }
  CI_VEC&  Bi_vec(void)              { return _bi_vec; }
  CI_VEC&  Ci_simpdiff(void)         { return _ci_simpdiff; }
  CI_VEC&  Bi_simpdiff(void)         { return _bi_simpdiff; }
  CI_VEC&  Ci_filtdiff(void)         { return _ci_filtdiff; }
  CI_VEC&  Bi_filtdiff(void)         { return _bi_filtdiff; }
  FP_VEC&  C_fid_path(void)          { return _c_fid_path; }
  FP_VEC&  B_fid_path(void)          { return _b_fid_path; }
  FP_VEC&  E_fid_path(void)          { return _e_fid_path; }
  FP_VEC&  L_fid_path(void)          { return _l_fid_path; }
  FP_VEC&  N_fid_path(void)          { return _n_fid_path; }
  FP_VEC&  F_fid_path(void)          { return _f_fid_path; }
  IG_VEC&  Ikey_grp_n(void)          { return _ikey_grp_n; }
  IG_VEC&  Ikey_grp_f(void)          { return _ikey_grp_f; }
  IG_VEC&  Ikey_grp_e(void)          { return _ikey_grp_e; }
  IG_VEC&  Ikey_grp_l(void)          { return _ikey_grp_l; }
  CI_VEC&  Src_f_json_vec(void)      { return _src_f_json_vec; }
  void     B_C_Fid_path_cmp(void);
  int      Get_path_node(char *issue, char dlimiter);

  ifstream Open_file(char *f); // use ifstream to Getline()
  void     Replace_fid(VTXT_ISSUE& cur_issue, INT lnkid);
  char    *Parse_replace_fid_ln(char *issue, INT lnkid, Manage *m, BOOL partial_scan);
  char    *Issue_key_ln_map(char *, int);
  void     Print(FILE *fp);
  void     Push_back(FID_PATH fp);
  void     Push_back(CHECKSUM_ISSUES ci, VTXT_KIND kind);
  void     Read_files(void);
  void     Simple_diff(CI_VEC& iterB, CI_VEC& iterC, VTXT_KIND basekind, VTXT_KIND curkind, FP_VEC& b_fid_path, FP_VEC& c_fid_path);
  void     Update_lineno_diff(Manage *m, FP_VEC& b_fid_path, FP_VEC& c_fid_path);
  BOOL     Contain_valid_issue(CI_VEC& issue_vec);
  INT      Group_diff_results(const char*);
  void     Order_vec_diff(IG_VEC&, IG_VEC&, IG_VEC&, COMPARE_KIND, VTXT_KIND, VTXT_KIND, VTXT_KIND, VTXT_KIND, const char*);
  void     Push_back_issue(vector<char*>&, VTXT_KIND);
  void     Push_back_issue(vector<char*>&, vector<char*>&, VTXT_KIND);
  void     Ikey_hash_count(CI_VEC&, IG_VEC&, BOOL);
  void     Write_files(FP_VEC& iterf, CI_VEC& iterc, const char *fn, const char *attr=NULL, const char *scanid=NULL, const char *version=NULL, const char *scanmode=NULL, Manage *m=NULL);
  BOOL     Partial_scan(void)             { return _partial_scan; }
  char    *Baseline_project_path(void)    { return _baseline_project_path; }
  char    *Current_project_path(void)     { return _current_project_path; }
  char    *Change_to_current_scan_fpath(char *fpath);
  string&  Remove_fpath_prefix(string &fpath, char *prefix);
  char    *Remove_last_slash(char *fpath);

  int      Process_option(int argc, char **argv) {
    if (argc < 3) {
	printf("Usage: [The first  scan(no DSR)] ./vtxt_diff -c xvsa-xfa-dummy.mtxt \n");
+	printf("Usage: [The second scan(DSR)]    ./vtxt_diff -g git_diff_line_map -n xvsa-xfa-dummy.ntxt -l xvsa-xfa-dummy.ltxt -e xvsa-xfa-dummy.etxt -c xvsa-xfa-dummy.mtxt [ -d ${log_file_path} ] [-b baseline_project_path] [-o current_project_path(should use with -b option together)]\n");
	exit(0);
    }

    int   input_f = 0;
    char *_logname;
    bool baseline_project_path_exist = false;
    bool current_project_path_exist = false;
    for (int i = 1; i < argc; i++) {
      if (argv[i][0] == '-') {
        switch (argv[i][1]) {
        //case 'b':
        //  _baseline_vtxt = argv[i+1];
        //  ++i;
        //  break;
        case 'c':
          _current_vtxt = argv[i+1];
          ++i;
          ++input_f;
          break;
        case 'e':
          _ebaseline_vtxt = argv[i+1];
          ++i;
          ++input_f;
          break;
        case 'g':
          _git_diff_results = argv[i+1];
          ++i;
          ++input_f;   
          break;
        case 'l':
          _lbaseline_vtxt = argv[i+1];
          ++i;
          ++input_f;
          break;
        case 'n':
          _nbaseline_vtxt = argv[i+1];
          ++i;
          ++input_f;
          break;
        case 'd':
	  if (argv[i+1] == NULL) return 1;
	  _logname = strcat((char *)argv[i+1], "/VTXTDIFF.log");
          _logfile = fopen(_logname, "w");
          ++i;
          break;
        case 'p':
          _partial_scan=true;
          _src_file_json = argv[i+1];
          ++i;
          break;
        case 'b':
          baseline_project_path_exist = true;
          _baseline_project_path = Remove_last_slash((char *)argv[i+1]);
          ++i;
          break;
         case 'o':
          current_project_path_exist = true;
          _current_project_path = Remove_last_slash((char *)argv[i+1]);
          ++i;
          break;  
        default:
          Print_option_guide(argv[i]);
          return -1;
        }
      } else {
        Print_option_guide(argv[i]);
        return -1;
      }
    }
    if(((baseline_project_path_exist == true) && (current_project_path_exist == false)) ||
      ((baseline_project_path_exist == false) && (current_project_path_exist == true))) {
      printf("-b and -o option should be used together\n");
      return -1;
    }
    return input_f;
  }
};

#endif
