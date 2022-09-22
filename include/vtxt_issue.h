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

// =============================================================================
// =============================================================================
//
// Module: vtxt_issue.h
//
// Description:
//
// =============================================================================
// =============================================================================
//

#ifndef VTXTISSUE_H
#define VTXTISSUE_H

#include "commondefs.h"
#include "srcpos.h"

#ifndef DFT_CONF_H
#define DFT_CONF_H

#define MAX_DEFECT_NAME  10

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

extern DFT_CAT dft_type[];

typedef enum CONFIDENCE_LVL {
  may_be   = 0,
  definite = 1,
  annotate = 2,
  MAX_CONF = 3,
} CONF_LVL;

typedef struct {
  CONF_LVL  _lvl;
  char     *_sym;  
} CONF_INFO;

extern CONF_INFO conf_type[];

#define STR_MALLOC_SZ    4
#define PN_SEPARATOR ':'
#define PN_TRUNC_SEPARATOR '.'

typedef struct _err_code {
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

typedef union _err_code_t {
  ERR_CODE code;
  INT32    val;
} ERR_CODE_T;

class FILE_PATH {
  char  *s;           // the path string itself
  int    ofs;         // offset from begin of path string table
  int    id;          // path id as input from json or core
public:
  char  *S(void)                    { return s; }
  void   S(char *str)               { s = str; }
  int    Ofs(void)                  { return ofs; }
  void   Ofs(int o)                 { ofs = o; }
  int    Id(void)                   { return id; }
  void   Id(int i)                  { id = i; }
};

#endif // DFT_CONF_H

typedef enum {
  ACTION_NONE       = 0,
  ACTION_FOUT_STL   = 1,    // filtered out stl 
  ACTION_OFNAM      = 2,    // the print function will print only the FNAME
  ACTION_FOUT_MAYBE = 4
} ACTION;


class _PATH_NODE {
private:
  SRCPOS _loc;
  INT    _node_num;
  INT    _node_desc;         // msg_id that describes flow node characteristics
                             // table index from msg_desc
public:
  _PATH_NODE() : _loc(0), _node_desc(0) {File_id(0); Line_num(0); Col_num(0);}
  _PATH_NODE(const INT id, INT l, INT c, INT nd) :
    _node_desc(nd) {File_id(id); Line_num(l); Col_num(c); }
  void  File_id(INT fileid)  { SRCPOS_filenum(_loc) = fileid;  }
  void  Line_num(INT linenum){ SRCPOS_linenum(_loc) = linenum; }
  void  Col_num(INT colnum)  { SRCPOS_column(_loc) = colnum; }
  void  Node_num(INT n)      { _node_num = n; }
  void  Node_desc(INT nd)    { _node_desc = nd; }

  INT   File_id(void) const  { return SRCPOS_filenum(_loc);  }
  INT   Line_num(void) const { return SRCPOS_linenum(_loc);  }
  INT   Col_num(void) const  { return SRCPOS_column(_loc);   }
  INT   Node_desc()          { return _node_desc; }
  INT   Node_num(void)       { return _node_num; }
};

using namespace std;
typedef vector<_PATH_NODE> _PN_VEC;


class VTXT_ISSUE {
private:
  char      *_unique_id;
  char      *_issue_key;
  char      *_file_name;
  SRCPOS     _start_spos;
  SRCPOS     _end_spos;      // remove it?
  DFT_CAT    _dft_cat;       // defect category, such as "Vul", vtxtlib.h
  CONF_INFO  _conf_info;     // confidence info, vtxtlib.h
  char      *_rule_code;     // DBF, UIV, RBC, etc
  char      *_fco_sens;      // [1, 0, 0] flow,context,object sensitivity
  char       _rule_set;      // 'X' or 'S'
  char      *_rule_type;     // "CERT", "MSR", "GJB" or "CMR(Customize Rule)"
  char      *_error_code;    // FIO34-C
  char      *_variable_name;
  char      *_function_name;
  _PN_VEC    _pn_vec;        // vector of PATH_NODEs
  ACTION     _action;        // what action against it

  VTXT_ISSUE(const VTXT_ISSUE&);            // no copy constructor
  VTXT_ISSUE& operator=(const VTXT_ISSUE&); // no assign operator

public:
  void    Unique_id(char *uid)   { _unique_id = Clone_data(uid);   }
  void    Issue_key(char *ikey)  { _issue_key = Clone_data(ikey);  }
  void    Fname(char *fname)     { _file_name = Clone_data(fname); }
  void    Filenum(INT fileid)    { SRCPOS_filenum(_start_spos) = fileid;  }
  void    Linenum(INT linenum)   { SRCPOS_linenum(_start_spos) = linenum; }
  void    Dft_cat_name(char *dft){ strcpy(_dft_cat.name, dft); }
  void    Conf_info_sym(char *s) { _conf_info._sym = Clone_data(s); }
  void    Rule_code(char *dftid) { _rule_code = Clone_data(dftid); }
  void    Fco_sens(char *fco)    { _fco_sens = Clone_data(fco); }
  void    Rule_set(char rs)      { _rule_set = rs; }
  void    Rule_type(char *rt)    { _rule_type = Clone_data(rt); }
  void    Error_code(char *dftid){ _error_code = Clone_data(dftid); }
  void    Vname(char *v)         { _variable_name = Clone_data(v);  }
  void    Pname(char *p)         { _function_name = Clone_data(p);  }
  void    Action(ACTION a)       { _action = (ACTION) ((INT)_action|(INT)a); }

  char   *Unique_id(void) const  { return _unique_id; }
  char   *Key(void) const        { return _issue_key; }
  char   *Fname(void) const      { return _file_name; }
  INT     Filenum(void) const    { return SRCPOS_filenum(_start_spos);  }
  INT     Linenum(void) const    { return SRCPOS_linenum(_start_spos);  }
  char   *Dft_cat_name(void)const{ return (char *)_dft_cat.name;  }
  char   *Conf_info_sym(void)const{return (char *)_conf_info._sym; }
  char   *Rule_code(void) const  { return _rule_code; }
  char   *Fco_sens(void) const   { return _fco_sens; }
  char    Rule_set(void) const   { return _rule_set;   }
  char   *Rule_type(void) const  { return _rule_type; }
  char   *Error_code(void) const { return _error_code; }
  char   *Vname(void) const      { return _variable_name; }
  char   *Pname(void) const      { return _function_name; }
  ACTION  Action(void) const     { return _action; }
  BOOL    Filt_stl(void) const   { return (_action & ACTION_FOUT_STL) != 0; }
  BOOL    Filt_maybe(void) const { return (_action & ACTION_FOUT_MAYBE) != 0; }
  BOOL    Filtered(void) const   { return Filt_stl() || Filt_maybe(); }
  void    Push_back(_PATH_NODE pn){ _pn_vec.push_back(pn); }
  _PN_VEC& Pn_vec(void)           { return _pn_vec; }

  // helper functions
  BOOL    Is_builtin(void) const { return _rule_set == 'X'; }
  BOOL    Is_cert(void) const    { return _rule_set == 'S'; }
  BOOL    Is_standard(void) const{ return Is_cert();   }
  BOOL    Is_user(void) const    { return _rule_set == 'U'; }
  BOOL    Is_rbc(void) const     { return strcmp(_rule_code, "RBC") == 0;    }

  void    Print_fix_portion(FILE *fp, BOOL old_version);
  void    Print_var_portion(FILE *fp);

public:
  VTXT_ISSUE(void):_unique_id(NULL), _issue_key(NULL), _file_name(NULL),
                   _rule_code(NULL), _fco_sens(NULL), _rule_set('\0'), _rule_type(NULL),
                   _error_code(NULL), _variable_name(NULL), _function_name(NULL) {
    _conf_info._sym = NULL;
  }
  ~VTXT_ISSUE(void) {
    if (_unique_id != NULL) free(_unique_id);
    if (_issue_key != NULL) free(_issue_key);
    if (_file_name != NULL) free(_file_name);
    if (_conf_info._sym != NULL) free(_conf_info._sym);
    if (_rule_code != NULL) free(_rule_code);
    if (_fco_sens  != NULL) free(_fco_sens);
    if (_rule_type != NULL) free(_rule_type);
    if (_error_code!= NULL) free(_error_code);
    if (_variable_name != NULL) free(_variable_name);
    if (_function_name != NULL) free(_function_name);
  }

  void    Verify(void);
  void    Print(FILE *fp, BOOL old_version) {
    if (! Filtered()) {
      Print_fix_portion(fp, old_version);
      Print_var_portion(fp);
    }
  }
};

typedef vector <VTXT_ISSUE> VISSUE_VEC;

#endif // VTXTISSUE_H
