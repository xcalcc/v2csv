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
// Module: v2csf.cxx
//
// convert .v text format to .csv file with normalized string indices
//
// =============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <assert.h>
#include <time.h>

#include "rule_desc_blt.h"
#include "v2csf.h"
#include "logging.h"

#define PATH_INC

using namespace std;

int get_defect_idx(char *rule_str, DFT_MAP_TAB defect_tab)
{
  int i;
  switch (defect_tab) {
  case BLT_TAB:
    for (i = 0; i < MAX_BLTIN_SZ; i++) {
      if (strcmp(defect_blt_vec[i].dstr_c, rule_str) == 0)
	break;
    }
    assert(i <= MAX_BLTIN_SZ);
    return i;
  case STD_TAB:
    for (i = 0; i < MAX_STD_SZ; i++) {
      if (strcmp(defect_std_vec[i].dstr_c, rule_str) == 0)
	break;
    }
    assert(i <= MAX_STD_SZ);
    return i;
  case USD_TAB:
    assert(0);
  default:
    assert(0);
  }
  assert(0);
  return -1;
}


INT Manage::eval_to_num(char *c_str)
{
  int val = 0;
  int sz = strlen(c_str);
  int i;
  char c;

  for (i = 0; i < sz; i++) {
    c = c_str[i];
    if (c < '0' || c > '9') {
      handle_error(E_CSV_INVALID_INPUT_FILE, " : Illegal character, numeric expected");
    }
    val = val * 10 + (c_str[i] - '0');
  }
  return val;
}


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


void Manage::skip_dlimiter(FILE *f, char d)
{
  int j;
  char c;
  j = fscanf(f, "%c", &c);
  if (d != c) {
    //handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file token error");
  }
}

FILE_PATH *Manage::make_fpath(char *s, int strtab_ofs, int id)
{
  FILE_PATH *fp = (FILE_PATH *)malloc(sizeof(FILE_PATH));
  if (fp == 0) {
    handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory during file path");
  }
  fp->S(s); fp->Ofs(strtab_ofs); fp->Id(id);
  return fp;
}


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
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file token error 1");
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

// returns NULL on error
char *Manage::get_varlen_str(FILE *in, char dlimiter_beg, char dlimiter_end, char paired_exception)
{
  // for function name, it is possible that the beginning delimiter may appear inside the good string as pairs
  // e.g. "[]". We can assume that when it happens, it will be in consecutive position
  // in these case, it is obviously not the end delimiter
  char *pstr = 0;
  size_t sz = STR_MALLOC_SZ;
  int i = 0;
  // whether dlimiter_beg and dlimiter_end is same, such as both use #
  bool same_be_dlimiter = true; 
  int nest_level = 0;

  if(dlimiter_beg != dlimiter_end) {
    same_be_dlimiter = false;
  }

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
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file token error 2");
  }

  if(!same_be_dlimiter) {
    ++nest_level;
  }

  while (i != sz) {
    if ((fscanf(in, "%c", &pstr[i])) == 1) {
      if ((!same_be_dlimiter) && (pstr[i] == dlimiter_beg)) {
        ++nest_level;
      }
      if ((!same_be_dlimiter) && (pstr[i] == dlimiter_end)) {
        --nest_level;
      }
      if (pstr[i] == dlimiter_end) {
	// check if exception case in case the string may have exception pairs (such as []
	if (nest_level == 0 && !((pstr[i-1] == dlimiter_beg) && (dlimiter_beg == paired_exception))) {
	  pstr[i] = '\0';
	  return pstr;  
	}
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

int Manage::get_1path_node(FILE *f, const char dlimiter, PATH_NODE &pn, bool skip)
{
  // a path from core consist of a triple separated by PN_SEPERATOR
  int fid, line, cline, pinfoid;
  // get fid
  int i = fscanf(f, "%d", &fid);
  if (i == EOF) {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : File ID error\n");
  }

  skip_dlimiter(f, PN_SEPARATOR);
  // get line number
  i = fscanf(f, "%d", &line);
  if (i == EOF) {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : line number error\n");
  }
  
  skip_dlimiter(f, PN_SEPARATOR);
  // get column number
  i = fscanf(f, "%d", &cline);
  if (i == EOF) {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : column line number error\n");
  }
  
  skip_dlimiter(f, PN_SEPARATOR);

  // get path info id
  i = fscanf(f, "%d", &pinfoid);
  if (i == EOF) {
        handle_error((long)E_CSV_INVALID_INPUT_FILE," : path_info error\n");
  }
	
  if (!skip) {
    pn.File_id(fid);
    pn.Line_num(line);
    pn.Col_num(cline);
    pn.Node_desc(pinfoid);
  }
  
  char c;   // either ",", "." or "]" expected
  i = fscanf(f, "%c", &c);

  if (c == PN_SEPARATOR) 
    return 1;


  if (c == ']')
    return 0;

  return i;
  
}


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


// returns index (while it is a string table, .csv view is a table, hence use index
int Manage::find_str(const STR_TAB_T t, const char *str)
{
  assert(str);
  if (Strtab_sz(t) == 0)
    return strtab[t].End();

  char *pstrtab = Strtab(t) + strtab[t].Begin();  // first 2 chars are null + newline
  int len = strlen(str);
  do {
    int i = strlen(pstrtab);
    if (len == i) {
      if (strcmp(str, pstrtab) == 0) {
        return (pstrtab - Strtab(t));
      }
    }
    pstrtab = pstrtab + i + 1;
  } while (pstrtab < (Strtab(t) + Strtab_sz(t)));
  return strtab[t].End();  // if not found, return end() as in STL iterators 
}

// temp - SC
int include_severity = 0;
// 
  

pair<int, bool>Manage::insert_name_str(const STR_TAB_T t, const char *name)
{
  // we now use the same strtab for all strings, this can be changed if needed
  // so that, say, file, path, var and func can have separate string tables
  init_str_tab(t);

  int len = strlen(name)+1;
  if ((Strtab_sz(t) + len) >= Strtab_max(t)) {
    resize_str_tab(t, len);
  }   

  int idx = find_str(t, name);
  if (idx == strtab[t].End()) {
    // not found
    strcpy((char *)(Strtab(t) + Strtab_sz(t)), name);
    // for Java, we end a string not with null, but JAVA_END_STRING_CHAR
    int ret = Strtab_sz(t);
    Strtab_sz(t, Strtab_sz(t) + strlen(name)+1);
    return make_pair(ret, true);   // new
  }
  return make_pair(idx, false);  // existing 
}

// always add, do not care about duplication
int Manage::insert_str(const STR_TAB_T t,  const char *str)
{
  init_str_tab(t);
  int len = strlen(str)+1;
  if ((Strtab_sz(t) + len) >= Strtab_max(t)) {
    resize_str_tab(t, len);
  }   

  int idx = find_str(t, str);
  if (idx == strtab[t].End()) {
    strcpy((char *)(Strtab(t) + Strtab_sz(t)), str);
    int ret = Strtab_sz(t);
    Strtab_sz(t, Strtab_sz(t) + strlen(str)+1);
    return ret;
  }
  return idx;
}

#ifdef PRECOMP
DFT_TYPE *fill_precompute(const int index, const DFT_MAP_TAB rule_cat)
{
  DFT_TYPE *ret = (DFT_TYPE *)0;
  switch (rule_cat) {
  case BLT_TAB:
    assert(index >=0 && index < MAX_BLT_SZ);
    ret = &defect_blt_vec[index];
    break;
  case STD_TAB:
    assert(index >=0 && index < MAX_STD_SZ);
    ret = &defect_std_vec[index];
  case USD_TAB:
    // not there yet (user define rule)
    assert(0);
  default:
    assert(0);
  }
  return ret;
}
#endif


bool Manage::update_src(FILE_ID fid, int line, int col, int desc, GI_VEC::iterator iter)
{
  // validity of source or sink is decided during create_issue_grp (s_s)
  // will need to be set correctly based on that when finally inserted into group rec
  if (Src_sink() == SINK_ONLY) {
    (*iter).Src().File_id(0);
    (*iter).Src().Line_num(0);
    (*iter).Src().Col_num(0);
    (*iter).Src().Node_desc(0);
    return false;
  }
  (*iter).Src().File_id(fid);
  (*iter).Src().Line_num(line);
  (*iter).Src().Col_num(col);
  (*iter).Src().Node_desc(desc);
  return true;
}


bool Manage::update_sink(FILE_ID fid, int line, int col, int desc, GI_VEC::iterator iter)
{
  // validity of source or sink is decided during create_issue_grp (s_s)
  // will need to be set correctly based on that when finally inserted into group rec
  if (Src_sink() == SRC_ONLY) {
    (*iter).Sink().File_id(0);
    (*iter).Sink().Line_num(0);
    (*iter).Sink().Col_num(0);
    (*iter).Sink().Node_desc(0);
    return false;
  }
  (*iter).Sink().File_id(fid);
  (*iter).Sink().Line_num(line);
  (*iter).Sink().Col_num(col);
  (*iter).Sink().Node_desc(desc);
  return true;
}

#if 0
void Manage::update_grp(IKEY_ID idx, int grp_complexity, GI_VEC& issuegrp)
{
  // given an offset to group string, find the corresponding index into the group table
  vector<GRP_INFO>::iterator iter;
  for (iter = issuegrp.begin(); iter < issuegrp.end(); iter++) {
    if ((*iter).Ikey_id() == idx)
      break;
  }

  if (iter == issuegrp.end())
    assert(0);
  int cplx = (*iter).Acc_cplx();
  cplx = cplx + grp_complexity;
  (*iter).Acc_cplx(cplx);
  (*iter).Src(src);
  (*iter).Sink(sink);
  (*iter).Timestamp();

  return;
}
#endif

//
// when the issue from .h file or the same issuekey from different vtxt
// skip it first to speed up the performance.
// TODO: need refact the string compare logic to refine the performance no skip
//
void Manage::skip_issue(FILE *in)
{
   char *ignore;
   // we will need to keep parsing towards the variable part, and also "confidence"
   skip_dlimiter(in, ',');
     
   ignore = get_varlen_str(in, '[', ']', '\0');    
   skip_dlimiter(in, ',');  
   
   // skip next [] field (used to be source <fileid, linenum>)
   ignore = get_varlen_str(in, '[', ']', '\0'); // ignore source pair
   skip_dlimiter(in, ',');
   
   ignore = get_varlen_str(in, '[', ']', '\0');  // get defect category
   skip_dlimiter(in, ',');
     
   ignore = get_varlen_str(in, '[', ']', '\0');  // get confidence
   skip_dlimiter(in, ',');
   
   char *pdftid = get_varlen_str(in, '[', ']', '\0');  // get defect 
   skip_dlimiter(in, ',');
   
   ignore = get_varlen_str(in, '[', ']', '\0'); // ignore flow, context, obj triple
   skip_dlimiter(in, ',');
   
   if (strcmp(pdftid, "RBC") == 0) {
     // for RBC, there are two extra items to identify exactly which defect
     ignore = get_varlen_str(in, '[', ']', '\0'); // ignore first item
     skip_dlimiter(in, ',');

     ignore = get_varlen_str(in, '[', ']', '\0');  // get true defect 
     skip_dlimiter(in, ',');
   }
     
   // variable name
   ignore = get_varlen_str(in, '[', ']', '[');
   skip_dlimiter(in, ',');

   // function name
   if (Ver_cmp(0, 6, 0) >= 0 && Ver_cmp(0, 7, 2) < 0)
     ignore = get_varlen_str(in, '#', '#', '[');
   else
     ignore = get_varlen_str(in, '[', ']', '[');
   
   skip_dlimiter(in, ',');    
   skip_dlimiter(in, '[');
   
   int i;    
   PATH_NODE pn;
   do {
     i = get_1path_node(in, ',', pn, true);
     if (i == 0) {
       skip_dlimiter(in, '\n');
     }
   } while (i != 0); // end of one record
}


// WORKAROUND: use this logic to workaround zentao #3612 that when the different issuekey from different vtxt
// WORKAROUND: when the issue be treated as existing issue, but not found in issuegrp, return -1
int Manage::check_grp(IKEY_ID idx, GI_VEC& issuegrp)
{
  vector<GRP_INFO>::iterator iter;
  for (iter = issuegrp.begin(); iter < issuegrp.end(); iter++) {
    if ((*iter).Ikey_id() == idx)
      break;
  }

  if (iter == issuegrp.end())
    return -1;
  return 0;
}

void Manage::update_grp(IKEY_ID idx, char c,  GI_VEC& issuegrp)
{
  // given an offset to group string, find the corresponding index into the group table
  vector<GRP_INFO>::iterator iter;
  for (iter = issuegrp.begin(); iter < issuegrp.end(); iter++) {
    if ((*iter).Ikey_id() == idx)
      break;
  }

  if (iter == issuegrp.end())
    assert(0);
  if ((*iter).Certainty() != 'A') {
    if (c == 'A')
      (*iter).Certainty(c);
    if (c == 'D')
      (*iter).Certainty(c);
  }
}


void Manage::create_issue_grp(char *unique_id, char *pikey, int ikey, char *filename, char *funcname,
                              char *varname, char *pconfidence, char *flag, char *pdftid,
                              DFT_TYPE* dft_ent, char rs, GRP_INFO *grp_info, GI_VEC& issuegrp)
{
  //GRP_INFO *grp_info = new GRP_INFO;

  // get severity, likelihood, cost, defect name and category from table
  int max_dft_tab  = (int)MAX_STD_SZ;
  int dft_idx;
  pair<int, bool> strtab_res;
  
  grp_info->Unique_id(unique_id);

  // issue key string for this group
  grp_info->Ikey(pikey);
  grp_info->Ikey_id(ikey);
  
  // the rule set for this issue group
  grp_info->Rule_set(rs);

  // file name
  strtab_res  = insert_name_str(Prog_name, filename);  // returns start of filename string in tab
  int j = strtab_res.first;
  if (j == EOF) {
    handle_error(E_CSV_INVALID_OUTPUT_FILE, "Cannot create file name for output");
  }

  grp_info->Acc_cplx(1);
  grp_info->Status('N');   // DSR status (N/F/P ignored etc)

  // certainty of issuegrp.
  if (strcmp(pconfidence, "A") == 0)
    grp_info->Certainty('A');
  if (strcmp(pconfidence, "D") == 0)
    grp_info->Certainty('D');
  if (strcmp(pconfidence, "M") == 0)
    grp_info->Certainty('M');

  // var name
  strtab_res = insert_name_str(Prog_name, varname);  // returns start of var name string in tab
  j = strtab_res.first;
  if (j == EOF) {
    handle_error(E_CSV_INVALID_OUTPUT_FILE, "Cannot create variable name for output");
  }
  grp_info->Var_id(j);

  // func name
  strtab_res = insert_name_str(Prog_name, funcname);  // returns start of var name string in tab
  j = strtab_res.first;
  if (j == EOF) {
    handle_error(E_CSV_INVALID_OUTPUT_FILE, "Cannot create function name for output");
  }
  grp_info->Func_id(j);

  grp_info->Inc_num_dft();

  if (rs == 'M' || rs == 'G' || rs == 'A') {
    grp_info->Cmr_name(pdftid);
  } else {
    grp_info->Dft_ent(dft_ent);
  }
  DBG_PRINTDDD("Create group %d - filename %s (%d)\n", ikey, filename, grp_info->Num_dft());

  issuegrp.push_back(*grp_info);
  return;
}


// fill entry (given issue key string) in issue group
// create one entry if not already there
// returns pair of <index to issues table, confidence (as char)>
pair<int, char> Manage::fill_issue_grp(FILE *in, char *unique_id, char *pikey,
                                       char *flag, GRP_INFO *grp_info, GI_VEC& issuegrp)
{
  char *ignore;
  pair<int, char> strtab_res = insert_name_str(Issue_key, pikey);  // Callee API decides if unique string be used
  int ikey = strtab_res.first;
  if (ikey == EOF) {
    handle_error((long)E_CSV_INVALID_OUTPUT_FILE," : Output file write error\n");
  }

  DBG_PRINT_FS("filling issue group %s\n", pikey);
  
  // we need only insert func name, var name and file name
  // until we know for sure issue key has this property, we will deal with these 3 now
  // but defect category, complexity will not need to be handled again
  bool new_issue = strtab_res.second;

  // WORKAROUND: skip issue when return -1
  if (!new_issue) {
    int i = check_grp(ikey, issuegrp);
    if ( i == -1) {
      skip_issue(in);
      return make_pair(-1, -1);
    }
  }

  // we will need to keep parsing towards the variable part, and also "confidence"
  skip_dlimiter(in, ',');
    
  char *pfile = get_varlen_str(in, '[', ']', '\0');    
  if ((pfile == 0) || (*pfile == '\0'))
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : issue file name error\n");
  
  skip_dlimiter(in, ',');  
  
  // skip next [] field (used to be source <fileid, linenum>)
  ignore = get_varlen_str(in, '[', ']', '\0'); // ignore source pair
  skip_dlimiter(in, ',');
  
  char *pdft = get_varlen_str(in, '[', ']', '\0');  // get defect category
  DFT_CAT defect;
  DFT_MAP_TAB dmt;
  strcpy(defect.name, pdft);
  
  skip_dlimiter(in, ',');
    
  char *pconfidence = get_varlen_str(in, '[', ']', '\0');  // get confidence
  CONF_INFO conf_info;   
  
  if (strlen(pconfidence) != 1) {
    handle_error(E_CSV_INVALID_INPUT_FILE, "Input confidence code error\n");
  }
  
  skip_dlimiter(in, ',');
  
  char *pdftid = get_varlen_str(in, '[', ']', '\0');  // get defect 
  
  skip_dlimiter(in, ',');
  
  ignore = get_varlen_str(in, '[', ']', '\0'); // ignore flow, context, obj triple
  skip_dlimiter(in, ',');
  
  // do not support user defined table yet
  int dft_tab_idx;
  DFT_TYPE *dft_ent = NULL;
  char rule_set = 'X';    // assume Xcalibyte builtin rule set
  if (strcmp(pdftid, "RBC") == 0) {
    rule_set = 'S';
    // for RBC, there are two extra items to identify exactly which defect
    ignore = get_varlen_str(in, '[', ']', '\0'); // ignore first item
    skip_dlimiter(in, ',');

    pdftid = get_varlen_str(in, '[', ']', '\0');  // get true defect 
    skip_dlimiter(in, ',');

    if (strcmp(ignore, "CERT") == 0) {
      dft_tab_idx = get_defect_idx(pdftid, STD_TAB);
      if (dft_tab_idx >= MAX_STD_SZ || dft_tab_idx < 0) {
        handle_error(E_CSV_INVALID_INPUT_FILE, "Unknown defect string");
      }
      dft_ent = &defect_std_vec[dft_tab_idx];  
    } else if (strcmp(ignore, "MSR") == 0) {
      // for MSR, use M as rule set
      // TODO: Need abstract this to support MSR, GJB, P3C or Customize rule
      rule_set = 'M';
      dft_ent = &defect_std_vec[0];
    } else if (strcmp(ignore, "GJB") == 0) {
      // for GJB, use G as rule set
      // TODO: Need abstract this to support MSR, GJB, P3C or Customize rule
      rule_set = 'G';
      dft_ent = &defect_std_vec[0];
    } else if (strcmp(ignore, "ATS") == 0) {
      // for Autosar, use A as rule set
      // TODO: Need abstract this to support MSR, GJB, P3C or Customize rule
      rule_set = 'A';
      dft_ent = &defect_std_vec[0];
    } else if (strcmp(ignore, "CMR") == 0){
      rule_set = 'M';
      dft_ent = &defect_std_vec[0];
    }

  } else {
    // get defect name and other related info
    dft_tab_idx = get_defect_idx(pdftid, BLT_TAB);
    if (dft_tab_idx >= MAX_BLTIN_SZ || dft_tab_idx < 0) {
      //when one builtin issue is not belongs to rule table,  skip it as 'M' first.
      rule_set = 'M';
      dft_ent = &defect_std_vec[0];
      //handle_error(E_CSV_INVALID_INPUT_FILE, "Unknown defect string");
    }
    dft_ent = &defect_blt_vec[dft_tab_idx];    
  }
    
  // variable name
  char *pvar = get_varlen_str(in, '[', ']', '[');
  if (*pvar == '\0') {
    // manufacture a name
    strcpy(pvar, NO_NAME_VAR_STR);
  }
  
  skip_dlimiter(in, ',');

  // function name
  char *pfunc;
  if (Ver_cmp(0, 6, 0) >= 0 && Ver_cmp(0, 7, 2) < 0)
    pfunc = get_varlen_str(in, '#', '#', '[');
  else
    pfunc = get_varlen_str(in, '[', ']', '[');
  
  if (pfunc == (char *)0) 
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input issue function name error");

  // since src_sink is really a global, must be updated for each issue
  const char* src_sink = NULL;
  if (dft_ent != NULL)
    src_sink = dft_ent->Iattr();
  //assert(src_sink != 0);
  // comment assert, when issue is not belongs to rule table, skip it first.
  if (src_sink == NULL)
    Src_sink('K');
  else
    Src_sink(src_sink[0]);
 
  if (new_issue) {
    // accumulate unique issue keys
    create_issue_grp(unique_id, pikey, ikey, pfile, pfunc, pvar, pconfidence,
                     flag, pdftid, dft_ent, rule_set, grp_info, issuegrp);
  }
  else {
    // no need to update if confidence is M since grp is default to M
    if (*pconfidence != 'M') {
      update_grp(ikey, *pconfidence, issuegrp);
    }
  }
  return make_pair(ikey, *pconfidence);
}


void Manage::build_strtab_hdr(FILE *out)
{
  // write out path table and fill tab position in hdr
  put_str_tab(out, Path, Strtab_pos(Path));
  if (Strtab_sz(Prog_name) != 0) {
    put_str_tab(out, Prog_name, Strtab_pos(Prog_name));
    put_str_tab(out, Issue_key, Strtab_pos(Issue_key));
  }
  else {
    // if no prog_name, no defect found, hence, no issue record
    Strtab_pos(Prog_name, 0);
    Strtab_pos(Issue_key, 0);
  }
  mark_hdr(out);
  return;
}


long Manage::put_hdr(FILE *out)
{
  fputs(CSV_MAGIC, out);
  assert(CSV_MAGIC_LEN == strlen(CSV_MAGIC));
  fputs(CSV_VERSION, out);
  assert(CSV_MAGIC_LEN == strlen(CSV_VERSION));

  long ret = ftell(out);    // mark start of offset part in hdr
  fputs("DeADBeeF", out);   // file path filler first, will rewrite later
  fputs("A55a5Aa5", out);   // file name, var, etc
  fputs("BEeFA55A", out);   // issue key
  fputs("CDaDDeaf", out);   // Group hdr Dixed table offset
  fputs("CDaDDean", out);   // Group hdr New table offset
  fputs("CDaDDeap", out);   // Group hdr Partial changed table offset
  fputs("CDaDDeaq", out);   // Group hdr Existing table offset
  fputs("DEaDdeaD", out);   // issues table of N, P
  fputs("DEaDdeaE", out);   // issues table of E
  fputs("DEfD", out);       // number of Fixed issue-groups
  fputs("DEnD", out);       // number of New issue-groups
  fputs("DEaD", out);       // number of Partial changed issue-groups
  fputs("DEcD", out);       // scan-id
  fputs("0000", out);       // CICD mode, include unknow, ci, cd, trial 
  fputs("CDaDDeaf", out);   // offset of Baseline & Current commit ID for DSR
  return ret;
}


inline void fputc_array8(char array[8], FILE *ofile)
{
  fputc(array[0], ofile);
  fputc(array[1], ofile);
  fputc(array[2], ofile);
  fputc(array[3], ofile);
  fputc(array[4], ofile);
  fputc(array[5], ofile);
  fputc(array[6], ofile);
  fputc(array[7], ofile);
}


inline void fputc_array4(char array[4], FILE *ofile)
{
  fputc(array[0], ofile);
  fputc(array[1], ofile);
  fputc(array[2], ofile);
  fputc(array[3], ofile);
}


void Manage::mark_hdr(FILE *out)
{
  fseek(out, CSV_STR_OFS_LEN, SEEK_SET);
  NAME8_IDX idx;
  long l = ftell(out);

  idx.name = Strtab_pos(Path);
  fputc_array8(idx.name_c, out);

  idx.name = Strtab_pos(Prog_name);
  fputc_array8(idx.name_c, out);

  idx.name = Strtab_pos(Issue_key);
  fputc_array8(idx.name_c, out);

  idx.name = Strtab_pos(Grp_hdr_f_rec);
  fputc_array8(idx.name_c, out);

  idx.name = Strtab_pos(Grp_hdr_n_rec);
  fputc_array8(idx.name_c, out);

  idx.name = Strtab_pos(Grp_hdr_p_rec);
  fputc_array8(idx.name_c, out);

  idx.name = Strtab_pos(Grp_hdr_e_rec);
  fputc_array8(idx.name_c, out);

  idx.name = Strtab_pos(Issue_n_p_rec);
  fputc_array8(idx.name_c, out);

  idx.name = Strtab_pos(Issue_e_rec);
  fputc_array8(idx.name_c, out);

  NAME4_IDX id4;
  id4.name = Issuegrp_f_num();
  fputc_array4(id4.name_c, out);

  id4.name = Issuegrp_n_num();
  fputc_array4(id4.name_c, out);

  id4.name = Issuegrp_p_num();
  fputc_array4(id4.name_c, out);

#if 0
  int total_num = Issuegrp_n_num() + Issuegrp_p_num();
  id4.name = 0;
  if (total_num != 0) {
    id4.name = Proj_cplx() / total_num;
    fputc_array4(id4.name_c, out);
  }
#endif

  NAMEC_IDX idc;
  idc.name = Scanid();
  fputc_array4(idc.name, out);

  id4.name = CICDmode();
  fputc_array4(id4.name_c, out);

  idx.name = Strtab_pos(Commit_id);
  fputc_array8(idx.name_c, out);

#if 0
  time_t rawtime;
  time(&rawtime);
  struct tm *ptm;
  ptm = gmtime(&rawtime);

  idx.name = mktime(ptm);
  fputc_array8(idx.name_c, out);
#endif

  return;
}


void Manage::put_str_tab(FILE *out, STR_TAB_T t, long pos)
{
  // put string table
  long cur_pos = ftell(out);           // mark beginning of this string table
  Strtab_pos(t, cur_pos);              // need to back fill file position of this table

  int i;
  for (i = 0; i < Strtab_sz(t); ++i) {
    char c = Strtab(t, i);
    if (c == '\0' && i != 0) { // first entry is always null
      fputc(JAVA_STRING_TERM, out);    // replace C string terminator with Java tailored 
    }
    else
      fputc(c, out);
  }

  //  Strtab_sz(t);  // ??
  //if (Strtab(t) != NULL)
  //  free(Strtab(t));
}

void Manage::dump_f_single_issuekey(FILE *out, GI_VEC::iterator iter, char *flag)
{
  char last_char = '\n';
  fprintf(out, "%s%c", (*iter).Unique_id(), last_char);

  if (strcmp(flag, ATTR_F) == 0)
    Set_pos_f_issuegrp(ftell(out)); // locate the end of F issue grp as the start of p issue grp.
}

void Manage::dump_single_issuekey(FILE *out, GI_VEC::iterator iter, char *flag)
{
  char last_char = '\n';
  //               |     |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
  //             1 1 2 2 3 3 4 4 5 5 6 6 7 7 8 8 9 9 0 0 1 1 2 2 3 3 4 4 5 5 6 6 7 7 8 8 9 9 0 0 1 1 2 2 3 3 4 4
  fprintf(out, "%s%c%d%c%c%c%s%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%s%c%c%c%s%c%d%c",
  (*iter).Unique_id(), CSV_SEPARATOR,        /* 1 */
  (*iter).Ikey_id(), CSV_SEPARATOR,
  (*iter).Rule_set(), CSV_SEPARATOR,         /* 3 */
  ((*iter).Rule_set() == 'M' || (*iter).Rule_set() == 'G' || (*iter).Rule_set() == 'A') ? (*iter).Cmr_name() : (*iter).Rulename(), CSV_SEPARATOR,
  (*iter).Num_path(), CSV_SEPARATOR,
  (*iter).Src().File_id(), CSV_SEPARATOR,
  (*iter).Src().Line_num(), CSV_SEPARATOR,   /* 7 */
  (*iter).Src().Col_num(), CSV_SEPARATOR,
  (*iter).Src().Node_desc(), CSV_SEPARATOR,
  (*iter).Sink().File_id(), CSV_SEPARATOR,
  (*iter).Sink().Line_num(), CSV_SEPARATOR,  /* 11 */
  (*iter).Sink().Col_num(), CSV_SEPARATOR,
  (*iter).Sink().Node_desc(), CSV_SEPARATOR,
  (*iter).Func_id(), CSV_SEPARATOR,
  (*iter).Var_id(), CSV_SEPARATOR,           /* 15 */
  (*iter).Acc_cplx(), CSV_SEPARATOR,
  0, CSV_SEPARATOR,
  ((*iter).Rule_set() == 'M' || (*iter).Rule_set() == 'G' || (*iter).Rule_set() == 'A') ? 9 : (*iter).Sevr(), CSV_SEPARATOR,
  ((*iter).Rule_set() == 'M' || (*iter).Rule_set() == 'G' || (*iter).Rule_set() == 'A') ? 9 : (*iter).Likely(), CSV_SEPARATOR,
  ((*iter).Rule_set() == 'M' || (*iter).Rule_set() == 'G' || (*iter).Rule_set() == 'A') ? 9 : (*iter).Rcost(), CSV_SEPARATOR,
  (*iter).Dft_cat_name(Vul), CSV_SEPARATOR,  /* 21 */
  (*iter).Certainty(), CSV_SEPARATOR,
  flag, CSV_SEPARATOR,
  (*iter).Criticality(), last_char
  );

  if (strcmp(flag, ATTR_N) == 0)
    Set_pos_n_issuegrp(ftell(out)); // locate the end of N issue grp as the start of p issue grp.
  if (strcmp(flag, ATTR_P) == 0)
    Set_pos_p_issuegrp(ftell(out)); // locate the end of P issue grp as the start of p issue grp.
}


void Manage::dump_f_issuekey(FILE *out, char *flag, GI_VEC& issuegrp)
{
  GI_VEC::iterator iter;
  char last_char = '\n';

  for (GI_VEC::iterator iter = issuegrp.begin(); iter < issuegrp.end(); iter++) {
    fprintf(out, "%s%c", (*iter).Unique_id(), last_char);
  }

  if (strcmp(flag, ATTR_F) == 0)
    Set_pos_f_issuegrp(ftell(out)); // locate the end of F issue grp as the start of p issue grp.
}


void Manage::dump_issuekey(FILE *out, char *flag, GI_VEC& issuegrp)
{
  GI_VEC::iterator iter;
  char last_char = '\n';

  for (GI_VEC::iterator iter = issuegrp.begin(); iter < issuegrp.end(); iter++) {
    //               |     |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | |
    //             1 1 2 2 3 3 4 4 5 5 6 6 7 7 8 8 9 9 0 0 1 1 2 2 3 3 4 4 5 5 6 6 7 7 8 8 9 9 0 0 1 1 2 2 3 3 4 4
    fprintf(out, "%s%c%d%c%c%c%s%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%d%c%s%c%c%c%s%c%d%c",
    (*iter).Unique_id(), CSV_SEPARATOR,        /* 1 */
    (*iter).Ikey_id(), CSV_SEPARATOR,
    (*iter).Rule_set(), CSV_SEPARATOR,         /* 3 */
    ((*iter).Rule_set() == 'M' || (*iter).Rule_set() == 'G' || (*iter).Rule_set() == 'A') ? (*iter).Cmr_name() : (*iter).Rulename(), CSV_SEPARATOR,
    (*iter).Num_path(), CSV_SEPARATOR,
    (*iter).Src().File_id(), CSV_SEPARATOR,
    (*iter).Src().Line_num(), CSV_SEPARATOR,   /* 7 */
    (*iter).Src().Col_num(), CSV_SEPARATOR,
    (*iter).Src().Node_desc(), CSV_SEPARATOR,
    (*iter).Sink().File_id(), CSV_SEPARATOR,
    (*iter).Sink().Line_num(), CSV_SEPARATOR,  /* 11 */
    (*iter).Sink().Col_num(), CSV_SEPARATOR,
    (*iter).Sink().Node_desc(), CSV_SEPARATOR,
    (*iter).Func_id(), CSV_SEPARATOR,
    (*iter).Var_id(), CSV_SEPARATOR,           /* 15 */
    (*iter).Acc_cplx(), CSV_SEPARATOR,
    0, CSV_SEPARATOR,
    ((*iter).Rule_set() == 'M' || (*iter).Rule_set() == 'G' || (*iter).Rule_set() == 'A') ? 9 : (*iter).Sevr(), CSV_SEPARATOR,
    ((*iter).Rule_set() == 'M' || (*iter).Rule_set() == 'G' || (*iter).Rule_set() == 'A') ? 9 : (*iter).Likely(), CSV_SEPARATOR,
    ((*iter).Rule_set() == 'M' || (*iter).Rule_set() == 'G' || (*iter).Rule_set() == 'A') ? 9 : (*iter).Rcost(), CSV_SEPARATOR,
    (*iter).Dft_cat_name(Vul), CSV_SEPARATOR,  /* 21 */
    (*iter).Certainty(), CSV_SEPARATOR, 
    flag, CSV_SEPARATOR,
    (*iter).Criticality(), last_char
    );
  }

  if (strcmp(flag, ATTR_N) == 0)
    Set_pos_n_issuegrp(ftell(out)); // locate the end of N issue grp as the start of p issue grp.
  if (strcmp(flag, ATTR_P) == 0)
    Set_pos_p_issuegrp(ftell(out)); // locate the end of P issue grp as the start of E issue grp.
  if (strcmp(flag, ATTR_E) == 0)
    Set_pos_e_issuegrp(ftell(out)); // locate the end of E issue grp as the start of fil path table.
}


void Manage::dump_issuepath(FILE *out, char *flag, GI_VEC& issuegrp, IP_VEC& issue_path,
                            vector< pair<int, int> > str_idx_tab)
{
  // dump out one record
  vector<ISSUE_PATH>::iterator iterIP;

  for (iterIP = issue_path.begin(); iterIP != issue_path.end(); iterIP++) {
    // unique ID for each issue path.
    fprintf(out, "%s%c", (*iterIP).Unique_id(), CSV_SEPARATOR);

    vector<PATH_NODE>::iterator iterPN = (*iterIP).Var_path().begin();
    vector<PATH_NODE>::iterator iterED = (*iterIP).Var_path().end();
    char last_char = CSV_SEPARATOR;
    // WORKAROUND: skip issue when return 0, comment out assert temp
    //assert(grp_instance.second >= 1);   // there should be at least one node in a path
    
    assert((*iterPN).Node_num() >= 0);
    if (iterPN == iterED) {
      // after pulling the source and/or sink, the path may have no entry
      // finish the record with new line
      // fix length portion of issue path record
      fprintf(out, "%d%c%d%c%c", grp_instance.first, CSV_SEPARATOR,
                                 (*iterPN).Node_num(), CSV_SEPARATOR,
                                 grp_instance.second);
      fprintf(out, "%c", '\n');
    } else {
      // fix length portion of issue path record
      fprintf(out, "%d%c%d%c%c%c", grp_instance.first, CSV_SEPARATOR,
                                   (*iterPN).Node_num(), CSV_SEPARATOR,
                                   grp_instance.second, CSV_SEPARATOR);
      for ( ; iterPN != iterED; ++iterPN) {
        // column number is always 0 now
        if (iterPN == (iterED-1))
          last_char = '\n';

        fprintf(out, "%d%c%d%c%d%c%d%c", (*iterPN).File_id(), CSV_SEPARATOR, 
                                         (*iterPN).Line_num(), CSV_SEPARATOR,
                                         0, CSV_SEPARATOR, 
                                         (*iterPN).Node_desc(), last_char);
      }
    }
    // update issue group header length of path, num_nodes is for complexity calc
    // update src and/sink if not already there
    //assert((*iterPN).Node_num() >= 0);
    //update_grp(grp_instance.first, num_nodes, issuegrp);      // no need to increment defect number
  }

  if (strcmp(flag, ATTR_N) == 0)
    Set_pos_n_p_issue_path(ftell(out)); // locate the end of issue path record as the start of e issue path.
  if (strcmp(flag, ATTR_P) == 0)
    Set_pos_n_p_issue_path(ftell(out)); // locate the end of issue path record as the start of e issue path.
  if (strcmp(flag, ATTR_E) == 0)
    Set_pos_e_issue_path(ftell(out));   // locate the end of issue path record as the start of f issue grp.
}

void Manage::Dump_commit_id(FILE *out)
{
  char last_char = '\n';
  fprintf(out, "%s%s%c", Base_commit_id(), Curr_commit_id(), last_char);

  Set_pos_commit_id(ftell(out)); // locate the end of commit ID
}

// Compare issue grp with E. If issuekey in E, it's partial N/F.
// If issuekey not in E, it's N/F.
// For L issues, it's need no diff with E. Because it belongs to E.
void Manage::Compare_dump_issuegrp(FILE *out, char *flag, GI_VEC& iterC, IP_VEC& issue_path,
                                   vector< pair<int, int> > str_idx_tab)
{
  GI_VEC::iterator iterE = Issuegrp_e().begin();
  GI_VEC::iterator iter = iterC.begin();
  char *status = flag;

  for ( ; iter != iterC.end(); iter++ ) {
    for ( ; iterE != Issuegrp_e().end(); iterE++ ) {
      if ((*iter).Ikey_id() == (*iterE).Ikey_id()) {
        status = (char*)ATTR_P;
	if (strcmp(flag, ATTR_F) == 0) {
          dump_f_single_issuekey(out, iter, status); 
          break;
        } else {
          dump_single_issuekey(out, iter, status);
          break;
        }
      } else {
        if (strcmp(flag, ATTR_F) == 0) {
          dump_f_single_issuekey(out, iter, status);
          break;
        } else {
          dump_single_issuekey(out, iter, status);
          break;
	}
      }
    }
  }
}


// The first scan, no DSR, the issue of E, L, F must be empty. N may is empty.
// multi time scan, do DSR, the issue of E, L, F, N maybe all is empty.
// whatever N issue if empty, dump ntxt contents to csf.
void Manage::Dump_csf(FILE *out, long pos)
{
  // dump baseline and current commit ID.
  if (Base_commit_id() != 0 && Curr_commit_id() != 0) {
    Dump_commit_id(out);
  } else {
    Set_pos_n_p_issue_path(ftell(out)); // locate the end of issue path record as the start of e issue path.
  }

  // dump issue path section if N/L/E is not empty, whatever the status of E.
  if (Issuegrp_n().size() != 0) {
    dump_issuepath(out, (char *)ATTR_N, Issuegrp_n(), Issue_path_n(), str_idx_tab_n);
  } else {
    Set_pos_n_p_issue_path(ftell(out)); // locate the end of issue path record as the start of e issue path.
  }
  if (Issuegrp_l().size() != 0) {
    dump_issuepath(out, (char *)ATTR_P, Issuegrp_l(), Issue_path_l(), str_idx_tab_l);
  } else {
    Set_pos_n_p_issue_path(ftell(out)); // locate the end of issue path record as the start of e issue path.
  }
  if (Issuegrp_e().size() != 0) {
    dump_issuepath(out, (char *)ATTR_E, Issuegrp_e(), Issue_path_e(), str_idx_tab_e);
  } else {
    Set_pos_e_issue_path(ftell(out)); // locate the end of issue path record as the start of f issue grp.
  }

  // when E is empty, dump issue grp section directly.
  if (Issuegrp_e().size() == 0) {
    if (Issuegrp_f().size() != 0) {
      dump_f_issuekey(out, (char *)ATTR_F, Issuegrp_f());
    } else {
      Set_pos_f_issuegrp(ftell(out)); // locate the end of F issue grp as the start of n issue grp.
    }
    if (Issuegrp_n().size() != 0) {
      dump_issuekey(out, (char *)ATTR_N, Issuegrp_n());
    } else {
      Set_pos_n_issuegrp(ftell(out)); // locate the end of N issue grp as the start of p issue grp.
    }
    if (Issuegrp_l().size() != 0) {
      dump_issuekey(out, (char *)ATTR_P, Issuegrp_l());
    } else {
      Set_pos_p_issuegrp(ftell(out)); // locate the end of P issue grp as the start of file path table.
    }
  }

  // when E results is not empty, need compare and then dump.
  if (Issuegrp_e().size() != 0) {
    // compare and dump issue grp section.
    if (Issuegrp_f().size() != 0) {
      Compare_dump_issuegrp(out, (char *)ATTR_F, Issuegrp_f(), Issue_path_f(), str_idx_tab_f);
    } else {
      Set_pos_f_issuegrp(ftell(out)); // locate the end of F issue grp as the start of p issue grp.
    }
    if (Issuegrp_n().size() != 0) {
      Compare_dump_issuegrp(out, (char *)ATTR_N, Issuegrp_n(), Issue_path_n(), str_idx_tab_n);
    } else {
      Set_pos_n_issuegrp(ftell(out)); // locate the end of F issue grp as the start of p issue grp.
    }
    // even though L is not empty, it's no need to be compared.
    if (Issuegrp_l().size() != 0) {
      dump_issuekey(out, (char *)ATTR_P, Issuegrp_l());
    } else {
      Set_pos_p_issuegrp(ftell(out)); // locate the end of P issue grp as the start of p issue grp.
    }
    if (Issuegrp_e().size() != 0) {
      dump_issuekey(out, (char *)ATTR_E, Issuegrp_e());
    } else {
      Set_pos_e_issuegrp(ftell(out)); // locate the end of P issue grp as the start of p issue grp.
    }
  }

  // mark the start of f issue group header position.
  Strtab_pos(Grp_hdr_f_rec, Pos_e_issue_path());
  // mark the start of n issue group header position.
  Strtab_pos(Grp_hdr_n_rec, Pos_f_issuegrp());
  // mark the start of p issue group header position.
  Strtab_pos(Grp_hdr_p_rec, Pos_n_issuegrp());
  // mark the start of e issue group header position.
  Strtab_pos(Grp_hdr_e_rec, Pos_p_issuegrp());
  // mark the start of e issue path record position.
  Strtab_pos(Issue_e_rec, Pos_n_p_issue_path());
  // write issue path table, func/var name table, issue key table.
  build_strtab_hdr(out);
}

int Manage::cvt2csv(FILE *in, FILE *out, char *flag, char *hostpath, GRP_INFO *grp_info,
                    GI_VEC& issuegrp, IP_VEC& issue_path, vector< pair<int, int> > str_idx_tab, bool ignore_h)
{
  assert(in != 0);
  assert(out != 0);
#define ATTR_LEN 100
  int  max_fileid = 0;
  char *ignore;
  char *path = (char *)0;
  bool done = false;
  char *fileattr = (char *)0;
  char attr[ATTR_LEN] = {"0"};
  char scanid[ATTR_LEN] = {"0"};
  char version[ATTR_LEN] = {"0"};
  char scanmode[ATTR_LEN] = {"0"};
  int  maj_ver  = 0;
  int  min_ver  = 0;
  int  mmin_ver = 0;

  // skip/validate the attribute and version of input file.
  fileattr = get_varlen_str(in, '{', '}', '\0');
  sscanf(fileattr, "%[^,], %[^,], %[^,],%s", attr, scanid, version, scanmode);
  sscanf(version, "%d.%d.%d", &maj_ver, &min_ver, &mmin_ver);
  Major_ver(maj_ver); Minor_ver(min_ver); MMinor_ver(mmin_ver);
  skip_dlimiter(in, '\n');

  if (strcmp(flag, ATTR_E) == 0) {
    E_scan_id(scanid);
  } else if (strcmp(flag, ATTR_L) == 0) {
    L_scan_id(scanid);
  } else if (strcmp(flag, ATTR_F) == 0) {
    F_scan_id(scanid);
  } else if (strcmp(flag, ATTR_N) == 0) {
    N_scan_id(scanid);
  }
  if(attr[0] == '0') {
    handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file in invalid attribute \n");
  }


  // first prtion is path names, enclosed with '[' and ']'
  // path will be broken up into an array of paths
  path = get_varlen_str(in, '[', ']', '\0');
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
    
    int idx = 0;
    // it is up to insert API to ensure paths are not duplicated
    // This logic is used to truncate file path and just store relative path to csf.
    // Add one logic to solve the path is start with "../" that is define INCLUDE_PATH
    if (strstr(one_path->S(), hostpath) != NULL) {
      string tmp_filepath(one_path->S());
      string filepath = tmp_filepath.replace(tmp_filepath.find(hostpath), strlen(hostpath), "");
      filepath = "$h" + filepath;
      idx = insert_str(Path, filepath.c_str());
    } else if (strncmp(one_path->S(), INCLUDE_PATH, 3) == 0) {
      string filepath(one_path->S());
      filepath = "$h/" + filepath;
      idx = insert_str(Path, filepath.c_str());
    } else {
      idx = insert_str(Path, one_path->S());
    }

    int fid = one_path->Id();
    str_idx_tab.push_back( make_pair(idx, fid) );
    if (one_path->S() != NULL)
      free(one_path->S());
    if (one_path != NULL)
      free(one_path);
    max_fileid++;
    
  } while (!done);

  // consume and put defects
  do {
    char *unique_id = get_varlen_str(in, '[', ']', '\0');  // get unique_id
    skip_dlimiter(in, ',');

    char *pikey = get_varlen_str(in, '[', ']', '[');
    
    if (pikey == (char *)-1) {   // read end of file done converting
      // at this point, variable part (aka issue path record) has been output
      // next, output group head records
      vector<GRP_INFO>::iterator iter;

      char last_char = '\n';
      int num = 0; // count the number of issues in one group
      for (iter = issuegrp.begin(); iter < issuegrp.end(); iter++) {
        // normalize group complexity, taking into account number of issues in a group
        int acc_cplx = (*iter).Acc_cplx();
        int norm_num_dft = (*iter).Num_dft();
        int avg_cplx = acc_cplx / (*iter).Num_dft();
        norm_num_dft = norm_num_dft / MAX_NODES + 1;
        if (norm_num_dft > MAX_NODES)
          norm_num_dft = MAX_NODES;
        
        // Remediation cost high means low desire to fix, hence less critical
        int acc_cplx_aug = (int)DFT_RCOST_HIGH;
        if (norm_num_dft >(int) RCOST_HIGH_LIMIT)
          acc_cplx_aug = (int)DFT_RCOST_MED;
        if (norm_num_dft > (int)RCOST_MEDIUM_LIMIT)
          acc_cplx_aug = (int)DFT_RCOST_LOW;
        
        int acc_cplx_avg_aug = (int)DFT_RCOST_HIGH;
        if (acc_cplx > (int)RCOST_HIGH_LIMIT)
          acc_cplx_avg_aug = (int)DFT_RCOST_MED;
        if (acc_cplx > (int)RCOST_MEDIUM_LIMIT)
          acc_cplx_avg_aug = (int)DFT_RCOST_LOW;
        
        // calculate true complexity
        // factor into complexity of a given issue #defs in group, average nodes in group
        // augment Remediation cost with these two factors
        
        int combined_cplx_aug = (acc_cplx_avg_aug + acc_cplx_aug) / 2;
        
        // for MSR, use M as rule set
        // TODO: Need abstract this to support MSR, GJB, P3C or Customize rule
	// Temporary hardcode the Severity, Likely, Cost as High
        if ((*iter).Rule_set() == 'M' || (*iter).Rule_set() == 'G' || (*iter).Rule_set() == 'A') {
          acc_cplx = 3 *
                     ((3 * 3) * 2) * 3;
        } else {
          acc_cplx = combined_cplx_aug *
                     (((*iter).Sevr() * (*iter).Likely()) * 2) * (*iter).Rcost();
	}
	// scale the value to within 1 - 9
        if (acc_cplx >= 90)
          acc_cplx = 89;
        acc_cplx = (acc_cplx)/10 + 1;
	(*iter).Acc_cplx(combined_cplx_aug); // update issuegrp acc_cplx
	(*iter).Criticality(acc_cplx); // update issuegrp criticality
        int proj_cplx = Proj_cplx() + acc_cplx;
        Proj_cplx(proj_cplx);
        // scale that down to ASCII
        acc_cplx = '0' + acc_cplx;

        num++;
      }

      // count the number of E/L/F/N issues.
      if (strcmp(flag, ATTR_E) == 0) {
        Set_num_e(num);
      } else if (strcmp(flag, ATTR_L) == 0) {
        Set_num_l(num);
      } else if (strcmp(flag, ATTR_F) == 0) {
        Set_num_f(num);
      } else if (strcmp(flag, ATTR_N) == 0) {
        Set_num_n(num);
      }

      DBG_PRINTDD("Issue_group %d has %d nodes\n", num, (*iter).Num_dft());

      return 0;
    }

    if ((pikey == 0) || (*pikey == '\0')) {
      handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input issue key error");
    }

    if (ignore_h && strstr(pikey, ".h") != NULL) {
      // when the issue from .h file, skip it.
      skip_issue(in);
    } else {

      // set the issue trace path limitation
      int num_current_path = 0;
      for (GI_VEC::iterator iter_issuegrp = issuegrp.begin(); iter_issuegrp != issuegrp.end(); iter_issuegrp++) {
        if (strcmp((*iter_issuegrp).Unique_id(), unique_id) == 0) {
          num_current_path = (*iter_issuegrp).Num_path();
          break;
        }
      }

      if (num_current_path >= Dump_path_limit()){
        skip_issue(in);
        continue;
      }

      grp_instance = fill_issue_grp(in, unique_id, pikey, flag, grp_info, issuegrp);
      // when the issue be skiped, skip this one time do-while loop.
      if (grp_instance.first == -1) continue;

      // when partial scan, some issues that from the file not be modified will be pushed to E issue directly, so need unify the unique_id with the same one if the issue key are same.
      for (GI_VEC::iterator iter = issuegrp.begin(); iter < issuegrp.end(); iter++) {
        if ((*iter).Ikey_id() ==  grp_instance.first) {
          unique_id = (*iter).Unique_id();
          break;
        }
      }
      //
      // deal with variable length part
      //
      skip_dlimiter(in, ',');    
      skip_dlimiter(in, '[');
      
      int i;    
      int num_nodes  = 0;  // could total nodes in this path

#if 0
      size_t checksum;
      std::string path_str;
      for ( PN_VEC::iterator iter = Pn_tab_n().begin(); iter != Pn_tab_n().end; iter++ ) {
        path_str = path_str + to_string((*iter).File_id()) + to_string((*iter).Line_num()) + to_string((*iter).Node_desc());
        checksum = hash<string>{}(path_str);
        CHECKSUM cs(checksum);
        Push_back(cs);
      }
#endif

      // this is a two pass algo since we need to count number of nodes in a defect
      // the actual output will be < confidence, num_nodes, (path_node)+ >
      // where path_node is a quadruple: < file_id, line num, col num (now 0), path_msg >

      ISSUE_PATH *ip = new ISSUE_PATH(unique_id);
      PATH_NODE pn;
      do {
        i = get_1path_node(in, ',', pn, false);
        if (i == 0) {
          skip_dlimiter(in, '\n');
        }

        num_nodes++;
        // map file index to strtab offset in appropriate string table
        int index = pn.File_id();

        if (index == -1) {
          // file index -1 (before subtract above) means path has been truncated
          // ignore this path_node
          // change path node to -1,-1,-1,0
          pn.Line_num(-1); pn.Col_num(-1), pn.File_id(-1); pn.Node_desc(0);
        } else if (index == 0) {
          pn.Node_num(num_nodes);
          pn.Line_num(0); pn.Col_num(0), pn.File_id(0); pn.Node_desc(0);
          ip->Push_back(pn);
        } else if (index >= 1) {
          int idx;
          for (idx = 0; idx < max_fileid; ++idx) {
            if (str_idx_tab[idx].second == index)
              break;
          }
          //if (strstr(pikey, "DDC") == NULL) // TODO: del this temporary condition to skip DDC error that "fid&lineno = 0"
          //  assert(idx != max_fileid);
          // second is index, first is offset
          
          // now index is switched to index of str tab, table first entry is null
          // pn.File_id(idx+1);
          pn.File_id(str_idx_tab[idx].first);
          pn.Node_num(num_nodes);
          ip->Push_back(pn);
        } else {
          handle_error(E_CSV_INVALID_OUTPUT_FILE, "File index error, out of bound");
        }
      } while (i != 0); // end of one record

      issue_path.push_back(*ip);

      //
      // update src/sink for each issue path.
      GI_VEC::iterator iter_end;
      for (iter_end = issuegrp.end() - 1; iter_end >= issuegrp.begin(); iter_end--) {
        if (strcmp((*iter_end).Unique_id(), unique_id) == 0) {
          (*iter_end).Inc_num_path();
          break;
        }
      }
      if ((*iter_end).Num_path() == 0) (*iter_end).Inc_num_path();

      IP_VEC::iterator iterS = issue_path.end() - 1;
      PN_VEC::iterator iterB = (*iterS).Var_path().begin();
      int vec_start = 0;
      int vec_end = (*iterS).Var_path().size() - 1;

      if (vec_end >= 0) {
        // first extract the source and/or sink as needed
        if (update_src((*iterS).Var_path()[vec_start].File_id(), (*iterS).Var_path()[vec_start].Line_num(), 0, (*iterS).Var_path()[vec_start].Node_desc(), iter_end)) {
          // this note has been pulled into group record, skip
          num_nodes--;
          (*iterS).Var_path().erase(iterB); // when update src to issuegrp, delete this node from issue path record.
          (*iterS).Var_path()[vec_start].Node_num(num_nodes);
        }

        if (update_sink((*iterS).Var_path()[vec_end].File_id(), (*iterS).Var_path()[vec_end].Line_num(), 0, (*iterS).Var_path()[vec_end].Node_desc(), iter_end) == false) {
          // this node will not be pulled into the group record, reset the iterator. 
          (*iterS).Var_path()[vec_end].Node_num(num_nodes);
        }
      }
    }
  } while (1);

  assert(0); // should never come here
  return 0;
}

void Manage::Dft_num(GI_VEC& issuegrp, vector< pair<char*, int> >& iterv)
{
    int iter2 = 0;
    for (GI_VEC::iterator iter1 = issuegrp.begin(); iter1 != issuegrp.end(); iter1++) {
    if (iterv.size() == 0) {
      iterv.push_back( make_pair((char *)(*iter1).Rulename(), 1) );
    } else {
      for (iter2 = 0; iter2 < iterv.size(); iter2++) {
        if (strcmp((*iter1).Rulename(), iterv[iter2].first) == 0) {
          iterv[iter2].second += 1;
	  break;
        } 
      }

     if (iter2 == iterv.size()) {
       iterv.push_back( make_pair((char *)(*iter1).Rulename(), 1) );
     }
    }
  }
}

void Manage::Dump_log(char *logfile)
{
  LOG logger;
  logger.Debug_log();
  char read_N[50];
  char read_L[50];
  char read_E[50];
  char read_F[50];
  char dump_csf[50];

  sprintf(read_N, "read ntxt time %fs", Read_N_time());
  sprintf(read_L, "read ltxt time %fs", Read_L_time());
  sprintf(read_E, "read etxt time %fs", Read_E_time());
  sprintf(read_F, "read ftxt time %fs", Read_F_time());
  sprintf(dump_csf, "dump csf time %fs", Dump_csf_time());

  if (logfile != NULL) {
    if (Issuegrp_n().size() != 0) {
      Dft_num(Issuegrp_n(), Dft_num_n());
    }
    if (Issuegrp_l().size() != 0) {
      Dft_num(Issuegrp_l(), Dft_num_l());
    }
    if (Issuegrp_e().size() != 0) {
      Dft_num(Issuegrp_e(), Dft_num_e());
    }
    if (Issuegrp_f().size() != 0) {
      Dft_num(Issuegrp_f(), Dft_num_f());
    }

    // write count results to log file.
    logger.Open_log(logfile, (char*)"TLOGgEr");
    string issuegrp_str = string("the number of issue group is: ") + string((char*)to_string(Issuegrp_n().size()).c_str());
    logger.Write_log(_INFO, (char*)read_N);
    logger.Write_log(_INFO, (char*)read_L);
    logger.Write_log(_INFO, (char*)read_E);
    logger.Write_log(_INFO, (char*)read_F);
    logger.Write_log(_INFO, (char*)dump_csf);
    logger.Write_log(_INFO, (char*)issuegrp_str.c_str());
    if (dft_num_n.size() != 0) {
      string issue_str;
      for (vector< pair<char*, int> >::iterator itern = dft_num_n.begin(); 
           itern != dft_num_n.end(); itern++) {
        issue_str = issue_str + string((*itern).first) + string(": ") + string((char*)to_string((*itern).second).c_str()) + string(", ");
      }
      logger.Write_log(_INFO, (char*)issue_str.c_str());
    }
  }
}


#define USAGE "Usage: %s -n ${file}.ntxt -l ${file}.ltxt -f ${file}ftxt -e ${file}.etxt -h host_path_string -T issue_path_limit[ -C [ci|cd|trial] -b ${baseline_commit_id} -c ${current_commit_id} ] [ -p log_file_path -d -i ]\n"

int main(int argc, char **argv)
{
  //GRP_INFO grp_info;
  Manage m; 
  char *outfile = NULL, *prevfile = NULL, *logfile = NULL;
  FILE *inputn = NULL, *inputl = NULL, *inputf = NULL, *inpute = NULL, *output = NULL;
  char *flag_n, *flag_l, *flag_f, *flag_e;
  BOOL dbg_mod = FALSE;
  int fname_index = 0;
  int c = 0;  // count the number of input file is 1 or 4.
  
  if (argc < 2) {
    fprintf(stderr, USAGE, argv[0]);
    exit(0);
  }

  size_t len;
  int prev_txt = 0;
  for (int i = 1; i < argc; i++)  {
    // output file not specified, use input_file name with .csv extension
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
      case 'n':       // scan result input file orignal vtxt or dsr output ntxt
      {
        m.Trace(true);
        if ((i+1) >= argc) {
          fprintf(stderr, USAGE, argv[0]);
          exit(0);
        }
        len = strlen(argv[i+1]);
        inputn = fopen(argv[i+1], "r");
        flag_n = (char *)ATTR_N;  // mark this input is N
        fname_index = i+1;
        i++;
        c++;
        if (!inputn) {
          m.handle_error( E_CSV_INVALID_INPUT_FILE, "Failed to open input ntxt/vtxt file");
        }
        break;
      }

      case 'l':       // scan result input file dsr ltxt
      {
        m.Trace(true);
        if ((i+1) >= argc) {
          fprintf(stderr, USAGE, argv[0]);
          exit(0);
        }
        len = strlen(argv[i+1]);
        inputl = fopen(argv[i+1], "r");
        flag_l = (char *)ATTR_L; // mark this input is L
        fname_index = i+1;
        i++;
        c++;
        if (!inputl) {
          m.handle_error( E_CSV_INVALID_INPUT_FILE, "Failed to open input ltxt file");
        }
        break;
      }

      case 'f':       // scan result input file 
      {
        m.Trace(true);
        if ((i+1) >= argc) {
          fprintf(stderr, USAGE, argv[0]);
          exit(0);
        }
        len = strlen(argv[i+1]);
        inputf = fopen(argv[i+1], "r");
        flag_f = (char *)ATTR_F; // mark this input is F
        fname_index = i+1;
        i++;
        c++;
        if (!inputf) {
          m.handle_error( E_CSV_INVALID_INPUT_FILE, "Failed to open input ftxt file");
        }
        break;
      }

      case 'e':       // scan result input file 
      {
        m.Trace(true);
        if ((i+1) >= argc) {
          fprintf(stderr, USAGE, argv[0]);
          exit(0);
        }
        len = strlen(argv[i+1]);
        inpute = fopen(argv[i+1], "r");
        flag_e = (char *)ATTR_E; // mark this input is E
        fname_index = i+1;
        i++;
        c++;
        if (!inpute) {
          m.handle_error( E_CSV_INVALID_INPUT_FILE, "Failed to open input etxt file");
        }
        break;
      }

      case 't':
        //  fall thru
      case 'h':
      {
        char relpath_char = argv[i][1];
        char *relpath = 0;
        if ((i+1) >= argc) {
          m.handle_error(E_CSV_INVALID_INPUT_FILE, "Missing argument for -h");
          exit(1);
        }
        relpath = (char *)malloc(strlen(argv[i+1])+1);
        if (relpath == 0) {
          m.handle_error(E_CSV_INVALID_INPUT_FILE, "-h argument error, out of memory");
          exit(1);
        }
        strcpy(relpath, argv[i+1]);
        if (relpath_char == 'h')
          m.Hostpath(relpath);
	i++;
#if 0
        else
          m.Targetpath(relpath);
#endif
        break;
      }
      case 'p':
      {
        logfile = &(argv[i+1][0]);
	argc -= 2;
	i += 2;
	break;
      }
      case 'd':
      {
        dbg_mod = TRUE;
	i++;
        break;
      }
      case 'i':
      {
        m.Ignore_h(true);
	i++;
        break;
      }
      case 'C':  // the option of CI/CD Mode
      {
	int ci_cd_mode = 0;
	if (strcmp(argv[i+1], "ci") == 0) {
	  ci_cd_mode = m.CICDmode() + CI_MODE * 1000;
	}
	if (strcmp(argv[i+1], "cd") == 0) {
	  ci_cd_mode = m.CICDmode() + CD_MODE * 1000;
	}
	if (strcmp(argv[i+1], "trial") == 0) {
	  ci_cd_mode = m.CICDmode() + TRIAL * 1000;
	}
        m.CICDmode(ci_cd_mode);
	i++;
        break;
      }
      case 'b':  // the option of Baseline commit ID
      {
        char *commitid = 0;
        if ((i+1) >= argc) {
          m.handle_error(E_CSV_INVALID_INPUT_FILE, "Missing argument for -b");
          exit(1);
        }
        commitid = (char *)malloc(strlen(argv[i+1])+1);
        if (commitid == 0) {
          m.handle_error(E_CSV_INVALID_INPUT_FILE, "-b argument error, out of memory");
          exit(1);
        }
        strcpy(commitid, argv[i+1]);
        m.Base_commit_id(commitid);
	i++;
	break;
      }
      case 'c':  // the option of Currnet commit ID
      {
        char *commitid = 0;
        if ((i+1) >= argc) {
          m.handle_error(E_CSV_INVALID_INPUT_FILE, "Missing argument for -c");
          exit(1);
        }
        commitid = (char *)malloc(strlen(argv[i+1])+1);
        if (commitid == 0) {
          m.handle_error(E_CSV_INVALID_INPUT_FILE, "-c argument error, out of memory");
          exit(1);
        }
        strcpy(commitid, argv[i+1]);
        m.Curr_commit_id(commitid);
	i++;
	break;
      }
      case 'T':  // the option of issue trace path limitation
      {
        if ((i+1) >= argc) {
          m.handle_error("Missing argument for -T");
          exit(1);
        }
        int val = atoi(argv[i+1]);
        if (val > 0 && val < 2000)
          m.Set_path_limit(val);
        else
          m.handle_error("-T argument error, valid number for T should be between 1 and 2000");
        i++;
        break;
      }
      default:
        fprintf(stderr, USAGE, argv[0]);
        exit(0);
      }
    }
  }

  if (c != 1 && c != 4) {
    m.handle_error( E_CSV_INVALID_INPUT_FILE, "Input files error, no vtxt or N/L/F/E txt" );
  }

  if (fname_index == 0) {
    fprintf(stderr, USAGE, argv[0]);
    exit(0);
  }

  outfile = (char *) malloc(len + sizeof(OUTFILE_CSF) + 1);
  if (outfile != NULL) {
    int i;
    int n = len + 1;
    for (i = 0; i < n; i++) {
      //  prepare to replace file suffix
      if (argv[fname_index][i] == '.')
        break;
    }

    memcpy((void *)outfile, argv[fname_index], i);  // copy all but "vtxt"
    outfile = strcat(outfile, OUTFILE_CSF);

    if (prev_txt) {
      prevfile = (char *) malloc(len + sizeof(DSR_EXT) + 1);  // previous DSR old issues file
      memcpy((void *)prevfile, argv[fname_index], i);  // copy all but "vtxt"
      prevfile = strcat(prevfile, DSR_EXT);
      m.Prevfile(prevfile);
    }
    m.Outfile(outfile);
    DBG_PRINTS(outfile);
    // check that scan_id is specified
#if 0
    if ((m.Scan_id() == 0) || ((prev_txt == 1) && (strlen(m.Prev_scan_id()) == 0))) {
      m.handle_error(E_CSV_INVALID_INPUT_FILE, "Scan_id and previous scan_id must be specified");
      exit(1);
    }
#endif
  }

  output = fopen(outfile, "w");
  if (!output) {
    fprintf(stderr, "Failed to open output file %s\n", outfile);
    free(outfile);
    exit(1);
  }

  // init csf file header
  long l = 0;
  if (output != NULL) {
    l = m.put_hdr(output);      // need to come back and fill where strtabs are
    m.Strtab_pos(Path, l);
    m.Strtab_pos(Prog_name,      l + CSV_STR_OFS_LEN);
    m.Strtab_pos(Issue_key,     (l + CSV_STR_OFS_LEN * 2));
    m.Strtab_pos(Grp_hdr_f_rec, (l + CSV_STR_OFS_LEN * 2) + sizeof(INT64));
    m.Strtab_pos(Grp_hdr_n_rec, (l + CSV_STR_OFS_LEN * 2) + 2 * sizeof(INT64));
    m.Strtab_pos(Grp_hdr_p_rec, (l + CSV_STR_OFS_LEN * 2) + 3 * sizeof(INT64));
    m.Strtab_pos(Grp_hdr_e_rec, (l + CSV_STR_OFS_LEN * 2) + 4 * sizeof(INT64));
    m.Strtab_pos(Issue_n_p_rec, (l + CSV_STR_OFS_LEN * 2) + 5 * sizeof(INT64));
    m.Strtab_pos(Issue_e_rec,   (l + CSV_STR_OFS_LEN * 2) + 6 * sizeof(INT64));

    l = ftell(output);           // start of issue path records
    m.Strtab_pos(Issue_n_p_rec, l);  // record it in header
  }

  // Input and read E/L/F/N txt files.
  assert(m.Hostpath() != 0);

  if (inpute != NULL) {
    clock_t read_E_start = clock();
    if (m.cvt2csv(inpute, output, flag_e, m.Hostpath(), m.Grp_info_e(),
                  m.Issuegrp_e(), m.Issue_path_e(), m.str_idx_tab_e, m.Ignore_h()) != 0) {
      fprintf(stderr, "etxt file conversion error\n");
    }
    clock_t read_E_end = clock();
    m.Read_E_time(static_cast<double>(read_E_end - read_E_start)/CLOCKS_PER_SEC);
  }
  if (inputl != NULL) {
    clock_t read_L_start = clock();
    if (m.cvt2csv(inputl, output, flag_l, m.Hostpath(), m.Grp_info_l(),
                  m.Issuegrp_l(), m.Issue_path_l(), m.str_idx_tab_l, m.Ignore_h()) != 0) {
      fprintf(stderr, "ltxt file conversion error\n");
    }
    clock_t read_L_end = clock();
    m.Read_L_time(static_cast<double>(read_L_end - read_L_start)/CLOCKS_PER_SEC);
  }
  if (inputf != NULL) {
    clock_t read_F_start = clock();
    if (m.cvt2csv(inputf, output, flag_f, m.Hostpath(), m.Grp_info_f(),
                  m.Issuegrp_f(), m.Issue_path_f(), m.str_idx_tab_f, m.Ignore_h()) != 0) {
      fprintf(stderr, "ftxt file conversion error\n");
    }
    clock_t read_F_end = clock();
    m.Read_F_time(static_cast<double>(read_F_end - read_F_start)/CLOCKS_PER_SEC);
  }
  if (inputn != NULL) {
    clock_t read_N_start = clock();
    if (m.cvt2csv(inputn, output, flag_n, m.Hostpath(), m.Grp_info_n(),
                  m.Issuegrp_n(), m.Issue_path_n(), m.str_idx_tab_n, m.Ignore_h()) != 0) {
      fprintf(stderr, "ntxt file conversion error\n");
      exit(1);
    }
    clock_t read_N_end = clock();
    m.Read_N_time(static_cast<double>(read_N_end - read_N_start)/CLOCKS_PER_SEC);
  } 

  // re-write csf header
  if (output != NULL) {
    m.Issuegrp_f_num(m.Num_f());
    m.Issuegrp_p_num(m.Num_l());
    m.Issuegrp_n_num(m.Num_n());
    m.Scanid(m.N_scan_id());
    // will build strtab hdr, write issue_path, func/var name, issue_key table in Dump_csf()
  }

  // dump results to csf
  clock_t dump_csf_start = clock();
  m.Dump_csf(output, l);
  clock_t dump_csf_end = clock();
  m.Dump_csf_time(static_cast<double>(dump_csf_end - dump_csf_start)/CLOCKS_PER_SEC);

  // dump log file 
  if (dbg_mod)
    m.Dump_log(logfile);

  if (inpute != NULL)
    fclose(inpute);
  if (inputl != NULL)
    fclose(inputl);
  if (inputf != NULL)
    fclose(inputf);
  if (inputn != NULL) 
    fclose(inputn);
  if (output != NULL)
    fclose(output);
  exit(0);
}

