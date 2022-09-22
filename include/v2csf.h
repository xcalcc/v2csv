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

// ====================================================================
// ====================================================================
//
// Module: v2_csv.h
//
// ====================================================================
//


#ifndef V2_CSV_H
#define V2_CSV_H

#include <stdio.h>
#include <stdlib.h>
#include <vector>

#include "rule_desc_blt.h"  // builtin rules info
#include "rule_desc_std.h"  // CERT standard rules info (C, C++, Java)
#include "vtxt_hdr.h"       // vtxt file hdr definition

using namespace std;

#define MAX_DEFECT_NAME 10
#define MAX_NODES       20 // really is 200, divide by 10 to use for complexity
#define STR_MALLOC_SZ   32
#define SCAN_ID_SZ       5

#ifndef NULL
#define NULL             '\0'
#endif

typedef enum DFT_CATEGORY {
  Vul            = 0,           // vulnerable
  Perf           = 1,           // performance
  Bad_practice   = 2,
  Correctness    = 3,
  Robustness     = 4,
  MAX_DFT        = 5,
} DFT_CATEGORY;

typedef struct {
  DFT_CATEGORY cat;
  char         name[MAX_DEFECT_NAME];
} DFT_CAT;

typedef enum CONFIDENCE_LVL {
  may_be   = 0,
  definite = 1,
  annotate = 2,
  MAX_CONF = 3,
} CONF_LVL;

typedef enum ISSUE_GRP_STATUS {
  S_NEW = '0',
  S_OLD = '1',
  S_IGNORE = '2',
  MAX_STATUS = '3',
} I_GRP_S;

typedef enum CI_CD_MODE {
  UNKNOWN = 0,
  CI_MODE = 1,
  CD_MODE = 2,
  TRIAL   = 3,
} CICD_M;

//
// we do not dictate number of string tables in the interface
// i.e. each type of index could be pointing to different string tables
// or all index could point to the same table
// number of string table(s) is implementation defined
// however, it has to be consistent between consumer and producer


typedef int IKEY_ID;  // key index to issue key string table
typedef int FILE_ID;  // File name index to prog string table
typedef int FUNC_ID;  // function name index to prog string table
typedef int VAR_ID;   // variable name index to prog string table


DFT_CAT dft_type[MAX_DFT] = { {Vul, "Vul"}, {Perf, "Perf"} };

typedef struct {
  CONF_LVL    lvl;
  const char *sym;  
} CONF_INFO;

CONF_INFO conf_type[MAX_CONF] = {
                   { may_be,   "M" },
                   { definite, "D" },
                   { annotate, "A" }
                 };


class PATH_NODE {
private:
  FILE_ID  file_id;
  int      line_num;
  int      col_num;
  int      node_num;
  int      node_desc;    // msg_id that describes flow node characteristics
                         // table index from msg_desc
public:
  PATH_NODE() : file_id(0), line_num(0), col_num(0), node_desc(0) {}
  PATH_NODE(const FILE_ID id, int l, int c, int nd) :
            file_id(id), line_num(l), col_num(0), node_desc(nd) {}
  FILE_ID  File_id(void)        { return file_id; }
  int      Line_num(void)       { return line_num; }
  int      Node_desc(void)      { return node_desc; }
  void     File_id(FILE_ID f)   { file_id = f; }
  void     Line_num(int l)      { line_num = l; }
  void     Node_desc (int nd)   { node_desc = nd; }
  int      Col_num(void)        { return col_num; }
  void     Col_num(int cd)      { col_num = cd; }
  void     Node_num(int n)      { node_num = n; }
  int      Node_num(void)       { return node_num; }
  int      get_1path_node(FILE *, const char, PATH_NODE &); 
};

typedef vector<PATH_NODE> PN_VEC;
 
class ISSUE_PATH {
private:
  char    *unique_id;  // unique ID for each issue path.
  PN_VEC   var_path;   // variable length part of issue path.

public:
  ISSUE_PATH(char *uid): unique_id(uid) {}

  void     Unique_id(char *i)      { unique_id = i; }
  char    *Unique_id(void)         { return unique_id; }
  PN_VEC&  Var_path(void)          { return var_path; }
  void     Push_back(PATH_NODE pn) { var_path.push_back(pn); }
};

typedef vector<ISSUE_PATH> IP_VEC;


class CHECKSUM {
private:
  size_t   checksum;

public:
  CHECKSUM(size_t chksum): checksum(chksum) {}
  size_t   Checusum(void)         { return checksum; }
  void     Set_checksum(size_t c) { checksum = c; }
};

typedef vector<CHECKSUM> CHK_VEC;

// This portion pertains to input .v text file
//
class GRP_INFO {
  // a specific group's defect info
  char     *unique_id;
  char     *ikey;
  IKEY_ID   ikey_id;
  INT64     seq_idx;
  FILE_ID   file_id;
  FUNC_ID   func_id;
  VAR_ID    var_id;
  DFT_CAT   cat;
  char      certainty;  // certainty of issue grp (D or M)
  char      status;     // DSR status (N/F/P ignored etc)
  char      rule_set;   // which rule set
  DFT_TYPE *dft_ent;
  int       grp_cplx;   // complexity of this group
  int       num_dft;
  int       num_path;   // the number of issue path in one group, default is 1
  int       avg_numnode;
  PATH_NODE src;
  PATH_NODE sink;
  int       acc_cplx;
  int       criticality;
  INT32     timestamp;
  char     *cmr_name; // store Customize Rule name

public:
  GRP_INFO() : num_dft(0), num_path(0), grp_cplx(0) {}
  GRP_INFO(IKEY_ID i, FILE_ID f, FUNC_ID fun, VAR_ID v, DFT_TYPE *d)
    : ikey_id(i), file_id(f), func_id(fun), var_id(v), dft_ent(d),
      grp_cplx(0), rule_set(0), num_dft(0), num_path(0), certainty('M'),
      status(S_NEW), avg_numnode(0), acc_cplx(0), criticality(0), timestamp(0) {}

  void       Unique_id(char *i)   { unique_id = i; }
  char      *Unique_id(void)      { return unique_id; }
  void       Ikey(char *k)        { ikey = k; }
  char      *Ikey(void)           { return ikey; }
  int        Num_dft(void)        { return num_dft; }
  void       Inc_num_dft(void)    { num_dft++; }
  int        Num_path(void)       { return num_path; }
  void       Inc_num_path(void)   { num_path++; }
  char       Rule_set(void)       { return rule_set; }
  void       Rule_set(char r)     { rule_set = r; }
  void       Ikey_id(IKEY_ID i)   { ikey_id = i; }
  IKEY_ID    Ikey_id(void)        { return ikey_id; }
  void       Func_id(FUNC_ID fn)  { func_id = fn; }
  FUNC_ID    Func_id(void)        { return func_id; }
  void       Var_id(VAR_ID v)     { var_id = v; }
  VAR_ID     Var_id(void)         { return var_id; }
  void       Dft_ent(DFT_TYPE *e) { dft_ent = e; }
  CONST_STR  Rulename()           { return dft_ent->Str_db(); }
  char       Cmr_name(char *u)    { cmr_name = u; }
  char      *Cmr_name(void)       { return cmr_name; }
  int        Sevr(void)           { return dft_ent->Sevr(); }
  int        Likely(void)         { return dft_ent->Like(); }
  int        Rcost(void)          { return dft_ent->Cost(); }
  void       Certainty(char c)    { certainty = c; }
  char       Certainty(void)      { return certainty; }
  char       Status(void)         { return status; }
  void       Status(char c)       { status = c; }
  I_ATTR     Src_sink(void)       { return dft_ent->Iattr(); }
  void       Src(PATH_NODE n)     { src = n; }
  PATH_NODE& Src(void)            { return src; }
  PATH_NODE& Sink(void)           { return sink; }
  void       Sink(PATH_NODE n)    { sink = n; }
  void       Grp_cplx(int c)      { grp_cplx = c; }
  int        Grp_cplx(void)       { return grp_cplx; }
  int        Avg_numnode(void)    { return avg_numnode; }
  void       Avg_numnode(int n)   { avg_numnode = n; }
  int        Acc_cplx(void)       { return acc_cplx; }
  void       Criticality(int a)   { criticality = a; }
  int        Criticality(void)    { return criticality; }
  void       Acc_cplx(int a)      { acc_cplx = a; }
  INT32      Timestamp(void)      { return 0xABBA; }
  INT64      Seq_idx(void)        { return seq_idx; }
  void       Seq_idx(INT64 s)     { seq_idx = s; }
  
  char *Dft_cat_name(DFT_CATEGORY c) { return dft_type[c].name; } // TODO - SC
};

typedef vector<GRP_INFO> GI_VEC;

#define PN_SEPARATOR ':'
#define PN_TRUNC_SEPARATOR '.'


// end of input .v text file

#define OUTFILE_CSF ".csf"
#define DSR_EXT     ".otxt"

#define ATTR_N "N"  // attribute of ntxt file
#define ATTR_L "L"  // attribute of ltxt file
#define ATTR_F "F"  // attribute of ftxt file
#define ATTR_E "E"  // attribute of etxt file
#define ATTR_P "P"  // attribute of P

// This portion pertains to output .csv text file
//
#define CSV_MAGIC       "XC5,"   // , for csv format
#define CSV_MAGIC_LEN   (4)
#define CSV_VERSION     "081,"
#define CSV_VERSION_LEN (4)      // file offset to PATH strings table
#define CSV_STR_OFS_LEN (4+4)    // file offset to file/func/var strings table &
                                 // file offset to group_id strings table

class SCAN_SUMMARY
{
  INT32 issuegrp_f_num;       // total number of fix issue groups (same issue_key)
  INT32 issuegrp_n_num;       // total number of new issue groups (same issue_key)
  INT32 issuegrp_p_num;       // total number of partial change issue groups (same issue_key)
  INT32 total_cplx;           // project issues complexity for this scan
  char *scan_id;
  INT32 cicd_mode;            // 1st byte CI/CD mode
  INT64 reserve0;
  INT64 reserve1;
  INT64 reserve2;

 public:
  SCAN_SUMMARY() : issuegrp_f_num(0), issuegrp_n_num(0), issuegrp_p_num(0),
	           total_cplx(0), cicd_mode(0) {}

  void  Issue_f_num(INT32 n)     { issuegrp_f_num = n; }
  INT32 Issue_f_num(void)        { return issuegrp_f_num; }
  void  Issue_n_num(INT32 n)     { issuegrp_n_num = n; }
  INT32 Issue_n_num(void)        { return issuegrp_n_num; }
  void  Issue_p_num(INT32 n)     { issuegrp_p_num = n; }
  INT32 Issue_p_num(void)        { return issuegrp_p_num; }
  void  Total_cplx(INT32 t)      { total_cplx = t; }
  INT32 Total_cplx(void)         { return total_cplx; }
  void  Scan_id(char *s)         { scan_id = s; }
  char *Scan_id(void)            { return scan_id; }
  void  CICD_mode(INT32 n)       { cicd_mode = n; }
  INT32 CICD_mode(void)          { return cicd_mode; }
};

typedef enum STR_TAB_T {
  Path               = 0,
  Prog_name          = 1, // func name, var name etc
  Issue_key          = 2, // issue key
  Grp_hdr_f_rec      = 3, // fixed group header
  Grp_hdr_n_rec      = 4, // new group header
  Grp_hdr_p_rec      = 5, // partial changed group header include PN, PF, L.
  Grp_hdr_e_rec      = 6, // existing group header
  Issue_n_p_rec      = 7, // issue records inclued N, PN, PF, L.
  Issue_e_rec        = 8, // issue records inclued E.
  Commit_id          = 9, // baseline and current commit id

} STR_TYPE_T;
#define MAX_STR_TAB_T  10

class XC5_hdr
{
  char          magic[CSV_MAGIC_LEN + CSV_VERSION_LEN];
  INT64         pathname_tab;         // file offset of pathname table
  INT64         progname_tab;         // file offset of func/var names
  INT64         issuekey_tab;         // file offset of issue key table
  INT64         issuegp_f_hdr;        // file offset of fixed issue group header
  INT64         issuegp_n_hdr;        // file offset of new issue group header
  INT64         issuegp_p_hdr;        // file offset of partial issue group header = PN + PF + L tab
  INT64         issues_tab;           // file offset to issue records = N + PN + PF + L

  SCAN_SUMMARY  summary;
 public:
};


#define CSV_SEPARATOR    ','
#define JAVA_STRING_TERM '\n'
#define NO_NAME_VAR_STR  "$noname"
#define INCLUDE_PATH     "../"

typedef union Name4_idx {
  INT32 name;
  char  name_c[4];
} NAME4_IDX;

typedef union {
  INT64 name;
  char  name_c[8];
} NAME8_IDX;

typedef union {
  char* name;
  char  name_c[8];
} NAMEC_IDX;

typedef struct {
  INT32 who     :  3;
  INT32 where   :  5;
  INT32 which   :  8;
  INT32 what    : 15;
  INT32 visible :  1;
 public:
  void  Who(const int w)      { who = w; }
  void  Where(const int w)    { where = w; }
  void  Which(const int w)    { which = w; }
  void  What(const int w)     { what = w; }
  void  Visible(const int v)  { visible = v; }
} ERR_CODE;


typedef union {
  ERR_CODE code;
  INT32    val;
} ERR_CODE_T;

#define  E_CSV_INVALID_INPUT_FILE   0
#define  E_CSV_OUT_OF_MEMORY        1
#define  E_CSV_INVALID_OUTPUT_FILE  2
#define  E_CSV_SIZE                 3

extern INT32 Csv_errcode(INT c);

class STR_TAB
{
  int   _sz;       
  int   _max;   // malloc'd buf size
  char *_tab;
  long  _pos;   // position in output file
 public:

  int   Sz(void)                 { return _sz; }
  void  Sz(int s)                { _sz = s; }
  int   Max(void)                { return _max; }
  void  Max(int m)               { _max = m; }
  void  Tab(char *t)             { _tab = t; }
  char* Tab(void)                { return _tab; }
  char  Tab(int i)               { return _tab[i]; }
  void  Pos(long p)              { _pos = p; }
  long  Pos(void)                { return _pos; }
  int   End(void)                { return _sz; }
  int   Begin(void)              { return 2; }
  void  Tabputc(char c)          { assert(_tab != 0); *_tab = c; }
  void  Tabput2c(char c, char d) { assert(_tab != 0); *_tab = c; *(_tab+1) = d;}
};

class FILE_PATH
{
  char  *s;           // the path string itself
  int    ofs;         // offset from begin of path string table
  int    id;          // path id as input from json or core
 public:
  FILE_PATH(int i, char *str) : id(i), s(str) {}
  //~FILE_PATH(void) { if(s) free(s); }
  char  *S(void)                   { return s; }
  void   S( char *str)             { s = str; }
  int    Ofs(void)                 { return ofs; }
  void   Ofs(int o)                { ofs = o; }
  int    Id(void)                  { return id; }
  void   Id(int i)                 { id = i; }
};

typedef vector<FILE_PATH> FP_VEC;


class Manage
{
  char            *outfile;
  char            *prevfile;   // previous dsr vtxt
  char            *hostpath;   // host path of project
  char            *targetpath;
  INT32            errcode;
  bool             option_use_index;
  bool             trace;
  bool             ignore_h;  // ignore the issue from header file
  char             src_sink;  // holder for src and/or sink of the group
  SCAN_SUMMARY     s_summary;
  //  int              issuegrp_num;
  //  int              total_cplx;
  PATH_NODE        src;       // holder for src in one path
  PATH_NODE        sink;      // holder for sink in one path
  char             n_scan_id[SCAN_ID_SZ+1];
  char             l_scan_id[SCAN_ID_SZ+1];
  char             e_scan_id[SCAN_ID_SZ+1];
  char             f_scan_id[SCAN_ID_SZ+1];
  STR_TAB          strtab[MAX_STR_TAB_T];
  GRP_INFO        *grp_info_n;
  GRP_INFO        *grp_info_l;
  GRP_INFO        *grp_info_f;
  GRP_INFO        *grp_info_e;
  GI_VEC           issuegrp_n;     // store issue group of N issues.
  GI_VEC           issuegrp_l;     // store issue group of L issues.
  GI_VEC           issuegrp_f;     // store issue group of F issues.
  GI_VEC           issuegrp_e;     // store issue group of E issues.
  PN_VEC           pn_tab_n;
  PN_VEC           pn_tab_l;
  PN_VEC           pn_tab_f;
  PN_VEC           pn_tab_e;
  IP_VEC           issue_path_n;   // store uniqueID and issue path vec of N issues.
  IP_VEC           issue_path_l;   // store uniqueID and issue path vec of L issues.
  IP_VEC           issue_path_e;   // store uniqueID and issue path vec of E issues.
  IP_VEC           issue_path_f;   // store uniqueID and issue path vec of F issues.
  FP_VEC           fid_path_n;     // store fid and path of N issues.
  FP_VEC           fid_path_l;     // store fid and path of L issues.
  FP_VEC           fid_path_f;     // store fid and path of F issues.
  FP_VEC           fid_path_e;     // store fid and path of E issues.
  CHK_VEC          chk_vec_n;
  CHK_VEC          chk_vec_l;
  CHK_VEC          chk_vec_f;
  CHK_VEC          chk_vec_e;
  pair<int, char>  grp_instance;
  int              num_e;              // count number of E issues.
  int              num_l;              // count number of L issues.
  int              num_f;              // count number of F issues.
  int              num_n;              // count number of N issues.
  long             pos_n_p_issue_path; // locate the end of N & P issue path record
  long             pos_e_issue_path;   // locate the end of E issue path record
  long             pos_f_issuegrp;     // locate the end of f issue grp
  long             pos_n_issuegrp;     // locate the end of n issue grp
  long             pos_p_issuegrp;     // locate the end of p issue grp
  long             pos_e_issuegrp;     // locate the end of e issue grp
  int              seq_num;            // the number of seq for each N issuegrp
  int              major_ver;          // 1st level version for version control
  int              minor_ver;          // 2nd level version for version control
  int              mminor_ver;         // 3rd level version for version control
  double           read_E_time;
  double           read_L_time;
  double           read_F_time;
  double           read_N_time;
  double           dump_csf_time;
  double           dump_E_time;
  double           dump_L_time;
  double           dump_F_time;
  double           dump_N_time;
  char            *base_commit_id;    // baseline commit ID for DSR
  char            *curr_commit_id;    // current  commit ID for DSR
  long             pos_commit_id;     // locate the end of baseline and current commit ID
  int              path_limit;        // set the limit of issue trace path

 public:
  Manage() : num_e(0), num_l(0), num_f(0), num_n(0), pos_n_p_issue_path(0), pos_e_issue_path(0), seq_num(0),
             pos_f_issuegrp(0), pos_n_issuegrp(0), pos_p_issuegrp(0), pos_e_issuegrp(0), hostpath(0),
             option_use_index(true), trace(false), ignore_h(false), major_ver(0), minor_ver(0), mminor_ver(0), base_commit_id(0), curr_commit_id(0), pos_commit_id(0), path_limit(100) { Init(0); Init(1); Init(2); }

  void  Outfile(char *o)              { outfile = o; }
  void  Prevfile(char *p)             { prevfile = p; }
  void  Hostpath(char *p)             { hostpath = p; }
  void  Targetpath(char *p)           { targetpath = p; }
  char *Hostpath(void)                { return hostpath; }
  char *Targetpath(void)              { return targetpath; }
  void  Strtab_sz(int t, int i)       { strtab[t].Sz(i); }
  int   Strtab_sz(int t)              { assert(t >= 0 && t < MAX_STR_TAB_T);
                                        return strtab[t].Sz(); }
  int   Strtab_max(int t)             { assert(t >= 0 && t < MAX_STR_TAB_T);
                                        return strtab[t].Max(); }
  char *Strtab(int t)                 { assert(t >= 0 && t < MAX_STR_TAB_T);
                                        return strtab[t].Tab(); }
  void  Strtab(int t, char *s)        { assert(t >= 0 && t < MAX_STR_TAB_T);
                                        strtab[t].Tab(s); }
  void  Strtab(int t, char c, char d) { assert(t >= 0 && t < MAX_STR_TAB_T);
					strtab[t].Tabput2c(c, d); }
  char  Strtab(int t, int i)          { return strtab[t].Tab(i); }
  int   Strtab_grow_max(int t)        { assert(t >= 0 && t < MAX_STR_TAB_T);
                                        int tmp = strtab[t].Max();
                                        strtab[t].Max(tmp * 2);
                                        return strtab[t].Max(); }
  void  Strtab_pos(int t, long p)     { assert(t >= 0 && t < MAX_STR_TAB_T);
                                        strtab[t].Pos(p); }
  long  Strtab_pos(int t)             { assert(t >= 0 && t < MAX_STR_TAB_T);
                                        return strtab[t].Pos(); }
  int   remove_outfile()              { return remove(outfile); }
  void  handle_error(const int err, const char *msg2)
                                      { fprintf(stderr, "%8x, %s\n", Code(err), msg2),
                                        (void)remove_outfile(), exit(EXIT_FAILURE); }
  void  handle_error(const char *msg) { fprintf(stderr, "%s\n", msg),
                                        (void)remove_outfile(), exit(EXIT_FAILURE); }
  void  Trace(bool b)                 { b = true; }
  bool  Trace()                       { return trace; }
  void  Ignore_h(bool h)              { ignore_h = h; }
  bool  Ignore_h()                    { return ignore_h; }
  void  Issuegrp_f_num(int n)         { s_summary.Issue_f_num(n); }
  int   Issuegrp_f_num(void)          { return s_summary.Issue_f_num(); }
  void  Issuegrp_n_num(int n)         { s_summary.Issue_n_num(n); }
  int   Issuegrp_n_num(void)          { return s_summary.Issue_n_num(); }
  void  Issuegrp_p_num(int n)         { s_summary.Issue_p_num(n); }
  int   Issuegrp_p_num(void)          { return s_summary.Issue_p_num(); }
  int   Proj_cplx()                   { return s_summary.Total_cplx(); }
  // proj_cplx must be div by issuegrp_num for actual use
  void  Proj_cplx(int i)              { s_summary.Total_cplx(i); }
  char  Src_sink(void)                { return src_sink; }
  void  Scanid(char *s)               { s_summary.Scan_id(s); }
  char *Scanid(void)                  { return s_summary.Scan_id(); }
  void  CICDmode(int m)               { s_summary.CICD_mode(m); }
  int   CICDmode(void)                { return s_summary.CICD_mode(); }
  void  Src_sink(char s)              { src_sink = s; }

  void             skip_issue(FILE *);
  int              check_grp(IKEY_ID, GI_VEC&);
  int              cvt2csv(FILE *, FILE *, char *, char *, GRP_INFO *, GI_VEC&, IP_VEC&, vector< pair<int, int> >, bool);
  void             skip_dlimiter(FILE *f, char d);
  char*            skip_dlimiter(char *f, char d1, char d2);
  int              get_1path_node(FILE *, const char, PATH_NODE&, bool);
  char*            get_varlen_str(FILE *, char, char, char);
  long             put_hdr(FILE *);
  void             mark_hdr(FILE *);
  FILE_PATH       *get_path_str(char *p, char, char);
  void             init_str_tab(const STR_TAB_T t);
  void             put_str_tab(FILE *, const STR_TAB_T t, long);
  void             resize_str_tab(const STR_TAB_T t, const int len);  // exit on error
  pair<int, bool>  insert_name_str(const STR_TAB_T t, const char *);
  int              insert_str(const STR_TAB_T t, const char *);
  int              find_str(const STR_TAB_T t, const char *);
  void             Init(int t) { strtab[t].Sz(0); strtab[t].Pos(-1);
                                 strtab[t].Max(STR_MALLOC_SZ); }
  INT32            Code(int c)           { return Csv_errcode(c); }
  void             N_scan_id(char *s)      { strncpy(n_scan_id, s, 5); }
  void             L_scan_id(char *s)      { strncpy(l_scan_id, s, 5); }
  void             E_scan_id(char *s)      { strncpy(e_scan_id, s, 5); }
  void             F_scan_id(char *s)      { strncpy(f_scan_id, s, 5); }
  char            *N_scan_id(void)         { return n_scan_id; }
  char            *L_scan_id(void)         { return l_scan_id; }
  char            *E_scan_id(void)         { return e_scan_id; }
  char            *F_scan_id(void)         { return f_scan_id; }
  FILE_PATH       *make_fpath(char *, int, int);
  int              get_fid(int);
  void             build_strtab_hdr(FILE *);
#ifdef PRECOMP   
  DFT_TYPE*        fill_precompute(const int, const int);
#endif
  void             create_issue_grp(char *, char *, int, char *, char *, char *, char *, char*, char *, DFT_TYPE*, char, GRP_INFO *, GI_VEC&);
  void             update_grp(IKEY_ID, int, GI_VEC&);
  void             update_grp(IKEY_ID, char, GI_VEC&);   // update M, D etc
  pair<int, char>  fill_issue_grp(FILE *, char *, char *, char *, GRP_INFO *, GI_VEC&);
  bool             update_src(FILE_ID, int, int, int, GI_VEC::iterator);
  bool             update_sink(FILE_ID, int, int, int, GI_VEC::iterator);
  int              eval_to_num(char *);
  void             Push_back_n(CHECKSUM chksm)    { chk_vec_n.push_back(chksm); }
  void             Push_back_l(CHECKSUM chksm)    { chk_vec_l.push_back(chksm); }
  void             Push_back_f(CHECKSUM chksm)    { chk_vec_f.push_back(chksm); }
  void             Push_back_e(CHECKSUM chksm)    { chk_vec_e.push_back(chksm); }
  void             Push_back_fp_n(FILE_PATH fp)   { fid_path_n.push_back(fp); }
  void             Push_back_fp_l(FILE_PATH fp)   { fid_path_l.push_back(fp); }
  void             Push_back_fp_e(FILE_PATH fp)   { fid_path_e.push_back(fp); }
  void             Push_back_fp_f(FILE_PATH fp)   { fid_path_f.push_back(fp); }
  GRP_INFO*        Grp_info_n(void)               { grp_info_n = new GRP_INFO; return grp_info_n; }
  GRP_INFO*        Grp_info_l(void)               { grp_info_l = new GRP_INFO; return grp_info_l; }
  GRP_INFO*        Grp_info_f(void)               { grp_info_f = new GRP_INFO; return grp_info_f; }
  GRP_INFO*        Grp_info_e(void)               { grp_info_e = new GRP_INFO; return grp_info_e; }
  GI_VEC&          Issuegrp_n(void)               { return issuegrp_n; }
  GI_VEC&          Issuegrp_l(void)               { return issuegrp_l; }
  GI_VEC&          Issuegrp_f(void)               { return issuegrp_f; }
  GI_VEC&          Issuegrp_e(void)               { return issuegrp_e; }
  FP_VEC&          Fid_path_n(void)               { return fid_path_n; }
  FP_VEC&          Fid_path_l(void)               { return fid_path_l; }
  FP_VEC&          Fid_path_f(void)               { return fid_path_f; }
  FP_VEC&          Fid_path_e(void)               { return fid_path_e; }
  IP_VEC&          Issue_path_n(void)             { return issue_path_n; }
  IP_VEC&          Issue_path_l(void)             { return issue_path_l; }
  IP_VEC&          Issue_path_f(void)             { return issue_path_f; }
  IP_VEC&          Issue_path_e(void)             { return issue_path_e; }
  PN_VEC&          Pn_tab_n(void)                 { return pn_tab_n;}
  PN_VEC&          Pn_tab_l(void)                 { return pn_tab_l;}
  PN_VEC&          Pn_tab_f(void)                 { return pn_tab_f;}
  PN_VEC&          Pn_tab_e(void)                 { return pn_tab_e;}
  int              Num_e(void)                    { return num_e; }
  int              Num_l(void)                    { return num_l; }
  int              Num_f(void)                    { return num_f; }
  int              Num_n(void)                    { return num_n; }
  void             Set_seq_num(void)              { seq_num++; }
  int              Seq_num(void)                  { return seq_num; }
  long             Pos_n_p_issue_path(void)       { return pos_n_p_issue_path; }
  long             Pos_e_issue_path(void)         { return pos_e_issue_path; }
  long             Pos_f_issuegrp(void)           { return pos_f_issuegrp; }
  long             Pos_n_issuegrp(void)           { return pos_n_issuegrp; }
  long             Pos_p_issuegrp(void)           { return pos_p_issuegrp; }
  long             Pos_e_issuegrp(void)           { return pos_e_issuegrp; }
  long             Pos_commit_id(void)            { return pos_commit_id; }
//  int              Num_node_e(void)             { return pn_tab_e.Node_num(); }
//  int              Num_node_l(void)             { return pn_tab_l.Node_num(); }
//  int              Num_node_f(void)             { return pn_tab_f.Node_num(); }
//  int              Num_node_n(void)             { return pn_tab_n.Node_num(); }
  void             Set_num_e(int e)               { num_e = e; }
  void             Set_num_l(int l)               { num_l = l; }
  void             Set_num_f(int f)               { num_f = f; }
  void             Set_num_n(int n)               { num_n = n; }
  void             Set_pos_n_p_issue_path(long n) { pos_n_p_issue_path = n; }
  void             Set_pos_e_issue_path(long n)   { pos_e_issue_path = n; }
  void             Set_pos_f_issuegrp(long n)     { pos_f_issuegrp = n; }
  void             Set_pos_n_issuegrp(long n)     { pos_n_issuegrp = n; }
  void             Set_pos_p_issuegrp(long n)     { pos_p_issuegrp = n; }
  void             Set_pos_e_issuegrp(long n)     { pos_e_issuegrp = n; }
  void             Set_pos_commit_id(long n)      { pos_commit_id  = n; }
  void             dump_issuekey(FILE *, char *, GI_VEC&);
  void             dump_f_issuekey(FILE *, char *, GI_VEC&);
  void             dump_issuepath(FILE *, char*, GI_VEC&, IP_VEC&, vector< pair<int, int> >);
  void             dump_single_issuekey(FILE *, GI_VEC::iterator, char *);
  void             dump_f_single_issuekey(FILE *, GI_VEC::iterator, char *);
  void             Compare_dump_issuegrp(FILE *, char *, GI_VEC&, IP_VEC&, vector< pair<int, int> >); 
  void             Dump_csf(FILE *, long);
  void             Dft_num(GI_VEC&, vector< pair<char*, int> >&);
  void             Dump_log(char *);
  void             Dump_commit_id(FILE *);
  vector< pair<char*, int> >   dft_num_n;   // count the number of N each type defect for log
  vector< pair<char*, int> >   dft_num_l;   // count the number of L each type defect for log
  vector< pair<char*, int> >   dft_num_e;   // count the numerb of E each type defect for log
  vector< pair<char*, int> >   dft_num_f;   // count the number of F each type defect for log
  vector< pair<char*, int> >&  Dft_num_n(void)  { return dft_num_n; } 
  vector< pair<char*, int> >&  Dft_num_l(void)  { return dft_num_l; }
  vector< pair<char*, int> >&  Dft_num_e(void)  { return dft_num_e; }
  vector< pair<char*, int> >&  Dft_num_f(void)  { return dft_num_f; }
  vector< pair<int, int> >     str_idx_tab_n;  // vector of N <offset>
  vector< pair<int, int> >     str_idx_tab_l;  // vector of L <offset>
  vector< pair<int, int> >     str_idx_tab_e;  // vector of E <offset>
  vector< pair<int, int> >     str_idx_tab_f;  // vector of F <offset>
  //void             dump_issuekey(FILE *, char *, vector<GRP_INFO>);
  //GRP_INFO&        Grp_info(void)        { return grp_info; }
  //GI_VEC&          Issuegrp(void)        { return issuegrp; }
  void             Read_E_time(double t)   { read_E_time = t; }
  void             Read_L_time(double t)   { read_L_time = t; }
  void             Read_F_time(double t)   { read_F_time = t; }
  void             Read_N_time(double t)   { read_N_time = t; }
  double           Read_E_time(void)       { return read_E_time; }
  double           Read_L_time(void)       { return read_L_time; }
  double           Read_F_time(void)       { return read_F_time; }
  double           Read_N_time(void)       { return read_N_time; }
  void             Dump_csf_time(double t) { dump_csf_time = t; }
  double           Dump_csf_time(void)     { return dump_csf_time; }
  void             Dump_E_time(double t)   { dump_E_time = t; }
  void             Dump_L_time(double t)   { dump_L_time = t; }
  void             Dump_F_time(double t)   { dump_F_time = t; }
  void             Dump_N_time(double t)   { dump_N_time = t; }
  double           Dump_E_time(void)       { return dump_E_time; }
  double           Dump_L_time(void)       { return dump_L_time; }
  double           Dump_F_time(void)       { return dump_F_time; }
  double           Dump_N_time(void)       { return dump_N_time; }
  void             Base_commit_id(char *i) { base_commit_id = i; }
  char            *Base_commit_id(void)    { return base_commit_id; }
  void             Curr_commit_id(char *i) { curr_commit_id = i; }
  char            *Curr_commit_id(void)    { return curr_commit_id; }
  void             Set_path_limit(int n)   { path_limit = n; }
  int              Dump_path_limit(void)   { return path_limit; }

  void             Major_ver(int v)        { major_ver = v; }
  int              Major_ver(void)         { return major_ver; }
  void             Minor_ver(int v)        { minor_ver = v; }
  int              Minor_ver(void)         { return minor_ver; }
  void             MMinor_ver(int v)       { mminor_ver = v; }
  int              MMinor_ver(void)        { return mminor_ver; }
  int              Ver_cmp(int maj, int min, int mmin) {
    if (maj > major_ver) return -1;
    if (maj < major_ver) return 1;
    if (min > minor_ver) return -1;
    if (min < minor_ver) return 1;
    return (mminor_ver - mmin);
  }

  bool digest_path (FILE *, FILE *);

};


#ifdef DEBUG_ON
#define DBG_PRINTS(s)          printf("%s\n", s)
#define DBG_PRINT_FS(f, s)     printf(f, s);
#define DBG_PRINTD(f, s)       printf(f, s);
#define DBG_PRINTDD(f, s1, s2) printf(f, s1, s2);
#define DBG_PRINTDDD(f, s1, s2, s3) printf(f, s1, s2, s3);
#else
#define DBG_PRINTS(s)
#define DBG_PRINT_FS(f, s)
#define DBG_PRINTD(f, s)
#define DBG_PRINTDD(f, s1, s2)
#define DBG_PRINTDDD(f, s1, s2, s3)
#endif


#endif // V2_CSV_H
