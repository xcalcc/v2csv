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

#include "rule_desc_blt.h"
#include "rule_desc_std.h"  // CERT standard rules info (C, C++, Java)
#include "filepath.h"

#define DEBUG_MAIN

using namespace std;

#ifndef NULL
#define NULL             '\0'
#endif

#ifndef DFT_CONF_H
#define DFT_CONF_H

#define STR_MALLOC_SZ    4
#define MAX_DEFECT_NAME  10
#define SCAN_ID_SZ       5
#define VERSION_SZ       5
#define SCANMODE_SZ      64

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

#define PN_SEPARATOR ':'
#define PN_TRUNC_SEPARATOR '.'

#endif // DFT_CONF_H

typedef enum ISSUE_GRP_STATUS {
  S_NEW = '0',
  S_OLD = '1',
  S_IGNORE = '2',
  MAX_STATUS = '3',
} I_GRP_S;


//
// we do not dictate number of string tables in the interface
// i.e. each type of index could be pointing to different string tables
// or all index could point to the same table
// number of string table(s) is implementation defined
// however, it has to be consistent between consumer and producer


typedef int FILE_ID;  // File name index to prog string table
typedef int IKEY_ID;  // key index to issue key string table
typedef int FUNC_ID;  // function name index to prog string table
typedef int VAR_ID;   // variable name index to prog string table


DFT_CAT dft_type[MAX_DFT] = { {Vul, "Vul"}, {Perf, "Perf"} };

typedef struct {
  CONF_LVL  _lvl;
  char     *_sym;  
} CONF_INFO;

CONF_INFO conf_type[MAX_CONF] = {
  { may_be,   (char*)"M" },
  { definite, (char*)"D" },
  { annotate, (char*)"A" }
};


class PATH_NODE {
private:
  FILE_ID  _file_id;
  int      _line_num;
  int      _col_num;
  int      _node_desc;    // msg_id that describes flow node characteristics
                          // table index from msg_desc

//  PATH_NODE(void);                          // REQUIRED UNDEFINED UNWANTED methods
//  PATH_NODE(const PATH_NODE&);              // REQUIRED UNDEFINED UNWANTED methods
//  PATH_NODE& operator = (const PATH_NODE&); // REQUIRED UNDEFINED UNWANTED methods

public:
  PATH_NODE() : _file_id(0), _line_num(0), _col_num(0), _node_desc(0) {}
  PATH_NODE(const FILE_ID id, int l, int c, int nd) :
                              _file_id(id), _line_num(l), _col_num(0), _node_desc(nd) {}
  FILE_ID  File_id(void)      { return _file_id; }
  int      Line_num()         { return _line_num; }
  int      Node_desc()        { return _node_desc; }
  void     File_id(FILE_ID f) { _file_id = f; }
  void     Line_num(int l)    { _line_num = l; }
  void     Node_desc (int nd) { _node_desc = nd; }
  int      Col_num(void)      { return _col_num; }
  int      get_1path_node(FILE *, const char, PATH_NODE &); 
};


typedef vector<PATH_NODE> PATH_NODES;


// This portion pertains to input .v text file
//
class GRP_INFO {
  // a specific group's defect info
  IKEY_ID   ikey_id;
  FILE_ID   file_id;
  FUNC_ID   func_id;
  VAR_ID    var_id;
  DFT_CAT   cat;
  INT8      status;     // DSR status (new, old, ignored etc)
  char      rule_set;   // which rule set
  DFT_TYPE *dft_ent;
  int       grp_cplx;   // complexity of this group
  int       num_dft;
  PATH_NODE src;
  PATH_NODE sink;
  INT32     timestamp;
  
public:
  GRP_INFO() : num_dft(0), grp_cplx(0) {}
  GRP_INFO(IKEY_ID i, FILE_ID f, FUNC_ID fun, VAR_ID v, DFT_TYPE d)
    : ikey_id(i), file_id(f), func_id(fun), var_id(v),
    grp_cplx(0), rule_set(0), num_dft(0), status(S_NEW) {}
  int      Num_dft(void)         { return num_dft; }
  void     Inc_num_dft(void)     { num_dft++; }
  I_GRP_S  Status(void)          { return (I_GRP_S)status; }
  void     Status(I_GRP_S s)     { status = (INT8)S_NEW; }
  char     Rule_set(void)        { return rule_set; }
  void     Rule_set(char r)      { rule_set = r; }
  void     Ikey_id(IKEY_ID i)    { ikey_id = i; }
  IKEY_ID  Ikey_id(void)         { return ikey_id; }
  void     Func_id(FUNC_ID fn)   { func_id = fn; }
  FUNC_ID  Func_id(void)         { return func_id; }
  void     Var_id(VAR_ID v)      { var_id = v; }
  VAR_ID   Var_id(void)          { return var_id; }
  void     Dft_ent(DFT_TYPE *e)  { dft_ent = e; }
  CONST_STR Rulename()           { return dft_ent->Str_db(); }
  int       Sevr(void)           { return dft_ent->Sevr(); }
  int       Likely(void)         { return dft_ent->Like(); }
  int       Rcost(void)          { return dft_ent->Cost(); }
  void      Src(PATH_NODE n)     { src = n; }
  PATH_NODE Src(void)            { return src; }
  PATH_NODE Sink(void)           { return sink; }
  void      Sink(PATH_NODE n)    { sink = n; }
  void      Acc_cplx(int c)      { grp_cplx = c; }
  int       Acc_cplx(void)       { return 5678; }  // TODO - SC
  INT32     Timestamp(void)      { return 0xABBA; }
  
  char *Dft_cat_name(DFT_CATEGORY c) { return dft_type[c].name; } // TODO - SC
};

// end of input .v text file

#define OUTFILE_EXT ".csv"

// This portion pertains to output .csv text file
//
#define CSV_MAGIC       "XC5,"   // , for csv format
#define CSV_MAGIC_LEN   (4)
#define CSV_VERSION     "0.7"
#define CSV_VERSION_LEN (4)      // file offset to PATH strings table
#define CSV_STR_OFS_LEN (4+4)    // file offset to file/func/var strings table &
                                 // file offset to gro`up_id strings table


class SCAN_SUMMARY
{
  INT32 issuegrp_num;    // total number of issue groups (same issue_key)
  INT32 total_cplx;      // project issues complexity for this scan
  INT64 reserve0;
  INT64 reserve1;
  INT64 reserve2;
 public:
  void  Issuegrp_num(INT32 n)       { issuegrp_num = n; }
  INT32 Issuegrp_num(void)          { return issuegrp_num; }
  void  Total_cplx(INT32 t)         { total_cplx = t; }
  INT32 Total_cplx(void)            { return total_cplx; }
};

typedef enum STR_TAB_T {
  Path               = 0,
  Prog_name          = 1, // func name, var name etc
  Issue_key          = 2, // issue key
  Grp_hdr_rec        = 3, // group header records
  Issue_rec          = 4, // issue records
} STR_TYPE_T;
#define MAX_STR_TAB_T  5

class XC5_hdr
{
  char          magic[CSV_MAGIC_LEN + CSV_VERSION_LEN];
  INT64         pathname_tab;        // file offset of pathname table
  INT64         progname_tab;        // file offset of func/var names
  INT64         issuekey_tab;        // file offset of issue key table
  INT64         issuegp_hdr;         // file offset of issue group header
  INT64         issues_tab;          // file offset to issue records  
  SCAN_SUMMARY  summary;
 public:
};


#define CSV_SEPARATOR    ','
#define JAVA_STRING_TERM '\n'
#define NO_NAME_VAR_STR  "$noname"


typedef union Name4_idx {
  INT32 name;
  char  name_c[4];
} NAME4_IDX;

typedef union {
  INT64 name;
  char  name_c[8];
} NAME8_IDX;


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


#ifndef CSVERRCODE_H
#define CSVERRCODE_H

#define  E_CSV_INVALID_INPUT_FILE   0
#define  E_CSV_OUT_OF_MEMORY        1
#define  E_CSV_INVALID_OUTPUT_FILE  2
#define  E_CSV_SIZE                 3
#define  E_CSV_INVALID_INPUT_STRING 4
#define  E_CSV_CONFLICT_STLFILTER   5

extern INT32 Csv_errcode(INT c);

#endif

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
  char  *S(void)                   { return s; }
  void   S(char *str)              { s = str; }
  int    Ofs(void)                 { return ofs; }
  void   Ofs(int o)                { ofs = o; }
  int    Id(void)                  { return id; }
  void   Id(int i)                 { id = i; }
};

class FIND_MATCH;

class Manage {
private:
  char          *outfile;
  INT32          errcode;
  bool           option_use_index;
  bool           trace;
  char           src_sink;  // holder for src and/or sink of the group
  SCAN_SUMMARY   s_summary;
  int            issuegrp_num;
  PATH_NODE      src;       // holder for src in one path
  PATH_NODE      sink;      // holder for sink in one path
  char           n_attr_scanid[SCAN_ID_SZ + 1];    // store attr and scanID from ntxt
  char           l_attr_scanid[SCAN_ID_SZ + 1];    // store attr and scanID from ltxt
  char           e_attr_scanid[SCAN_ID_SZ + 1];    // store attr and scanID from etxt
  char           f_attr_scanid[SCAN_ID_SZ + 1];    // store attr and scanID from ftxt
  char           v_attr_scanid[SCAN_ID_SZ + 1];    // store attr and scanID from vtxt
  char           version[VERSION_SZ + 1];          // store file version from vtxt
  char           scanmode[SCANMODE_SZ];            // store scan mode from vtxt
  int            major_ver;                        // 1st level version for version control
  int            minor_ver;                        // 2nd level version for version control
  int            mminor_ver;                       // 3rd level version for version control

  STR_TAB                  strtab[MAX_STR_TAB_T];
  vector<GRP_INFO>         issuegrp;

 public:
 Manage() : issuegrp_num(0), major_ver(0), minor_ver(0), mminor_ver(0),
  option_use_index(true), trace(false){ Init(0); Init(1); Init(2); } 
  void  Outfile(char *o)              { outfile = o; }
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
  int   Proj_cplx()                   { return s_summary.Total_cplx(); }
  void  Issuegrp_num(int n)           { issuegrp_num = n; }
  int   Issuegrp_num(void)            { return issuegrp_num; }
  char  Src_sink(void)                { return src_sink; }
  void  Src_sink(char s)              { src_sink = s; }
  void  N_attr_scanid(char *n)        { strncpy(n_attr_scanid, n, 5); }
  void  L_attr_scanid(char *l)        { strncpy(l_attr_scanid, l, 5); }
  void  E_attr_scanid(char *e)        { strncpy(e_attr_scanid, e, 5); }
  void  F_attr_scanid(char *f)        { strncpy(f_attr_scanid, f, 5); }
  void  V_attr_scanid(char *n)        { strncpy(v_attr_scanid, n, 5); }
  char *N_attr_scanid(void)           { return n_attr_scanid; }
  char *L_attr_scanid(void)           { return l_attr_scanid; }
  char *E_attr_scanid(void)           { return e_attr_scanid; }
  char *F_attr_scanid(void)           { return f_attr_scanid; }
  char *V_attr_scanid(void)           { return v_attr_scanid; }
  void  Version(char *v)              { strncpy(version, v, 5); }
  char *Version(void)                 { return version; }
  void  Scanmode(char *s)             { strncpy(scanmode, s, 64); }
  char *Scanmode(void)                { return scanmode; }
  void  Major_ver(int v)              { major_ver = v; }
  int   Major_ver(void)               { return major_ver; }
  void  Minor_ver(int v)              { minor_ver = v; }
  int   Minor_ver(void)               { return minor_ver; }
  void  MMinor_ver(int v)             { mminor_ver = v; }
  int   MMinor_ver(void)              { return mminor_ver; }
  int   Ver_cmp(int maj, int min, int mmin) {
    if (maj > major_ver) return -1;
    if (maj < major_ver) return 1;
    if (min > minor_ver) return -1;
    if (min < minor_ver) return 1;
    return (mminor_ver - mmin);
  }

  void             skip_dlimiter(FILE *f, char d);
  char*            skip_dlimiter(char *f, char d1, char d2);
  int              cvt2csv(FILE *, FIND_MATCH *fm, VTXT_KIND k, FP_VEC &mf);
  int              get_1path_node(FILE *, const char, PATH_NODE&);
  char*            get_varlen_str(FILE *, char, char);
  char*            Parse_src_file_json(char *, char, char, FIND_MATCH *, VTXT_KIND);
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
  INT32            Code(int c) { return Csv_errcode(c); }
  FILE_PATH       *make_fpath(char *, int, int);
  int              get_fid(int);
  void             build_strtab_hdr(FILE *);
  void             create_issue_grp(int, char *, char *, char *, char *, DFT_TYPE*, char);
  void             update_grp(IKEY_ID, int, int);
  pair<int, char>  fill_issue_grp(FILE *, char *);
  bool             update_src(FILE_ID, int, int, int);
  bool             update_sink(FILE_ID, int, int, int);
  BOOL             validate_file_attr(VTXT_KIND, char *);
  void             Print(FILE *fp);

  int digest_path (FILE *);

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
