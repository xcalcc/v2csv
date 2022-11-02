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

#include "vtxt_report.h"


char*
VTXT_REPORT::Skip_dlimiter(char *path, char d1, char d2)
{
  int j;
  char c;

  // we are guaranteed that path will end with ']' per previous call to get_varlen_str
  while (*path != d1 && *path != d2) {
    path++;
  }
  return path;
}


char*
VTXT_REPORT::Skip_dlimiter(char *b, char d)
{
  if (d != *b) {
    Handle_error((long)E_CSV_INVALID_INPUT_STRING," : Input string token error");
  }
  return ++b;
}


void
VTXT_REPORT::Skip_dlimiter(FILE *f, char d)
{
  int j;
  char c;
  j = fscanf(f, "%c", &c);
  if (d != c) {
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file token error");
  }
}


BOOL
VTXT_REPORT::Validate_file_attr(VTXT_KIND kind, char *attr)
{
  char a[10];
  sscanf(attr, "\"%s\"", a);
  switch (kind) {
  case VTXT_NBASE:
    return a[0] == 'N'; break;
  case VTXT_LBASE:
    return a[0] == 'L'; break;
  case VTXT_EBASE:
    return a[0] == 'E'; break;
  case VTXT_FBASE:
    return a[0] == 'F'; break;
  case VTXT_BASELINE:
  case VTXT_CURRENT:
    return a[0] == 'V'; break;
  default:
    return FALSE;
    break;
  }
}


char*
VTXT_REPORT::Get_varlen_str(FILE *in, char dlimiter_beg, char dlimiter_end,
                            char paired_exception)
{
  // for function name, it is possible that the beginning delimiter may appear
  // inside the good string as pairs e.g. "[]". We can assume that when it
  // happens, it will be in consecutive position.  in these case, it is
  // obviously not the end delimiter
  char *pstr = 0;
  size_t sz = STR_MALLOC_SZ;
  int i = 0;

  pstr = (char *)calloc(sz, sizeof(char));
  if (pstr == 0) {
    Handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory");
  }

  int j = fscanf(in, "%c", &pstr[0]);

  if (j == EOF)  // done with conversion in reality
    return  (char *)-1;
  
  if (j != 1) {
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file read error");
  }

  int number_of_square_bracket = 0;
  if (pstr[0] != dlimiter_beg) {
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file token error 2");
  }
  
  if(dlimiter_beg == '[') {
    number_of_square_bracket++;
  }
  
  while (i != sz) {
    if ((fscanf(in, "%c", &pstr[i])) == 1) {
      if ((pstr[i] == dlimiter_beg) && (dlimiter_beg == '[')) {
        number_of_square_bracket++;
      }
      if ((pstr[i] == dlimiter_end) && (dlimiter_end == ']')) {
        number_of_square_bracket--;
      }
      if ((number_of_square_bracket == 0) && (pstr[i] == dlimiter_end)) {
	// check if exception case in case the string may have exception pairs (such as []
	if (!((pstr[i-1] == dlimiter_beg) && (dlimiter_beg == paired_exception))) {
	  pstr[i] = '\0';
	  return pstr;  
	}
      }

      i++;
      if (i == sz) {
	// buffer full, realloc
	char *p = (char *)realloc(pstr, (sz+sz));
	if (p == NULL) {
	  Handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory\n");
	}

	pstr = p;
	sz = sz*2;
      }
    }
    else{
      Handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file format error");
    }
  }
  
  return (char *)0;
}


char*
VTXT_REPORT::Get_varlen_str(FILE *in, char dlimiter_beg, char dlimiter_end)
{
  char *pstr = 0;
  size_t sz = STR_MALLOC_SZ;
  int i = 0;

  pstr = (char *)calloc(sz, sizeof(char));
  if (pstr == 0) {
    Handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory");
  }

  int j = fscanf(in, "%c", &pstr[0]);

  if (j == EOF)  // done with conversion in reality
    return  (char *)-1;

  if (j != 1) {
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file read error");
  }

  while (i != sz) {
    j = fscanf(in, "%c", &pstr[i]);
    if (j == EOF)
      return (char*)-1;
    if (j == 1) {
      if (pstr[i] == dlimiter_end) {
        pstr[i] = '\0';
        DBG_PRINT_FS("var_string_name:%s\n", pstr);
        return pstr;
      }

      i++;
      if (i == sz) {
        // buffer full, realloc
        char *p = (char *)realloc(pstr, (sz+sz));
        if (p == NULL) {
          Handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory\n");
        }

        pstr = p;
        sz = sz*2;
      }
    }
  }

  return (char *)0;
}


char*
VTXT_REPORT::Get_next_token(char**in, char dlimiter)
{
  char *pstr = 0;
  size_t sz = STR_MALLOC_SZ;
  int i = 0;

  pstr = (char *)calloc(sz, sizeof(char));
  if (pstr == 0) {
    Handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory");
  }

  if (**in == '\0') {
    return (char*)-1;
  }
  else {
    pstr[0] = **in;
    i = 1;
  }

  for ((*in)++; i != sz; ++(*in)) {
    if ((pstr[i] = **in) != '\0') {
      if (pstr[i] == dlimiter) {
        pstr[i] = '\0';
        DBG_PRINT_FS("Get_next_token:%s\n", pstr);
        return pstr;
      }

      i++;
      if (i == sz) {
        // buffer full, realloc
        char *p = (char *)realloc(pstr, (sz+sz));
        if (p == NULL) {
          Handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory\n");
        }

        pstr = p;
        sz = sz*2;
      }
    }
    if (pstr[i] == dlimiter)
      return pstr;
  }

  return (char *)0;
}


FILE_PATH*
VTXT_REPORT::Make_fpath(char *s, int strtab_ofs, int id) 
{
  FILE_PATH *fp = (FILE_PATH *)malloc(sizeof(FILE_PATH));
  if (fp == 0) {
    Handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory during file path");
  }
  fp->S(s); fp->Ofs(strtab_ofs); fp->Id(id);
  return fp; 
}


FILE_PATH*
VTXT_REPORT::Get_path_str(char *path, char dlimiter_beg, char dlimiter_end)
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
    FILE_PATH *filepath = Make_fpath(0, 0, 0);
    return filepath;  // caller must free this filepath
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
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file token error");
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
    Handle_error((long)E_CSV_OUT_OF_MEMORY, " : Out of memory");
  }
  strncpy(s, path, len);

  FILE_PATH *filepath = Make_fpath(s, path-start_path+len, true_fid);
  return filepath;  // caller must free this filepath
}


INT
VTXT_REPORT::Import_filepath(FILE *in, GLB_FP *glb_fp)
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

  fileattr = Get_varlen_str(in, '{', '}');
  Skip_dlimiter(in, '\n');
  if (fileattr == (char *)-1) // missing file attribute N, L, E, V, F
    return 0;
  Filekind(fileattr);
  if (glb_fp != NULL) {
    glb_fp->Fileattr(fileattr);
  }
  // first prtion is path names, enclosed with '[' and ']'
  // path will be broken up into an array of paths
  path = Get_varlen_str(in, '[', ']', '\0');
  if (path == (char *)-1) // missing path table
    return 0;

  do {
    // path delimiters are "{}" pair
    FILE_PATH *one_path = Get_path_str(path, '{', '}');
    if (one_path->S() == (char *)-1)   // read end of file, error
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input file - read path error\n");
    if (one_path->S() == (char *)NULL) { // empty path section
      free(one_path);
      break;
    }
    path = path + one_path->Ofs();
    path = Skip_dlimiter(path, ',', '\0');

    if (*path != ',') {
      if (*path == '\0') {  // end of path was ']' has been replaced with '\0'
        // end of paths portion
        Skip_dlimiter(in, '\n');
        done = TRUE;
      }
    }

    char *var_path = one_path->S();
    int   fid = one_path->Id();

    // make a copy here.  Push_back does not know what to clone
    char *path = Clone_string(var_path);
    FID_PATH fp(fid, path);
    File_paths().push_back(fp);

    if (glb_fp != NULL) {
      glb_fp->Enter_glb_fp(glb_fp->Last_lnkid(), fid, path);
    }
    free(one_path->S());
    free(one_path);

    max_fileid++;
  } while (!done);

  start_ln = 4 * max_fileid + 3;
  // printf("\nstart ln : %d\n", start_ln);

  if (start_ln > 0) {
    return start_ln;
  }
  return -1;
}

FILE*
VTXT_REPORT::Read_filehdr(INT &end, GLB_FP *glb_fp)
{
  FILE   *input;

  if (Infile() == NULL) return NULL;
  if (glb_fp != NULL)
    glb_fp->New_lnkid();

  input = fopen(Infile(), "r");
  if (input == NULL) {
    fprintf(stderr, "%s does not exist\n", Infile());
    exit(1);
  }
  end = Import_filepath(input, glb_fp);
  if (end <= 0) {
    fprintf(stderr, "file import error\n");
    exit(1);
  }
  fclose(input);
  Hdr_end(end);
  return NULL;
  // return input;
}


char *
VTXT_REPORT::Get_prefix(char *filepath, char**end)
{
  char *ofilepath = (char*)malloc(strlen(filepath)+12);
  *end = NULL;
  if (ofilepath == NULL)
    return NULL;
  strcpy(ofilepath, filepath);
  char *cur;
  for (cur = ofilepath+strlen(ofilepath); cur != ofilepath; --cur) {
    if (*cur == '.') {
      *cur = '\0';
      break;
    }
  }
  *end = cur;
  return ofilepath;
} 


void
VTXT_REPORT::Open_ofile(void)
{
  if ( Infile() == NULL)
    return;
  char *ofile;
  if ( Outfile() == NULL) {
    ofile = (char *)malloc(strlen(Infile())+5);
    strcpy(ofile, Infile());

    char *cur;
    ofile = Get_prefix(ofile, &cur);

    if (ofile == NULL || cur == ofile) {
      if (ofile) free(ofile);
      return;
    }

    sprintf(cur, "%s", ".otxt");
    Set_outfile(ofile);
  }
  else
    ofile = Outfile();
  FILE *retv = (FILE *)fopen(ofile, "w");
  if (retv == NULL) {
    INT errorNum = errno;
    const char *errStr = strerror(errorNum);
    char *errMsg = (char*)malloc(1024 + strlen(errStr));
    strcpy(errMsg, "");
    sprintf(errMsg, "Failure while opening vtxt file: %s : %s", ofile, errStr);
    Handle_error(E_CSV_INVALID_OUTPUT_FILE, errMsg);
  }
  Set_out(retv);
}


void
VTXT_REPORT::Verify(void)
{
  assert(Infile() != NULL);
  assert(File_paths().size()!=0);
}


void
VTXT_REPORT::Filekind(char *k)
{
  char *orig = Filekind();
  if (orig) free(orig);
  _filekind = Clone_string(k);

  //sscanf(k, "\"%s\", %s, %f",&attr, &magic, &version);
  k = Skip_till(k, ',');
  k = Skip_dlimiter(k, ',');
  k = Skip_till(k, ',');
  k = Skip_dlimiter(k, ',');
  float version = atof(k); // atof will ignore mminor_version
  _version = version;
  // scan major, minor, mminor version numbers
  char buffer[60];
  int  maj_ver;
  sscanf(k, "%d.%s", &maj_ver, buffer);
  char buffer1[60];
  int  min_ver = 0;
  int  mmin_ver = 0;
  if (Findchar(buffer, '.')) {
    sscanf(buffer, "%d.%s", &min_ver, buffer1);
    char buffer2[60];
    buffer2[0] = '\0';
    if (Findchar(buffer1, ',')) {
      sscanf(buffer1, "%d,%s", &mmin_ver, buffer2);
    }
    if (buffer2[0] != '\0') {
      VTXT_HDR *hdr = new VTXT_HDR(0,0,0,0);
      hdr->Read_filehdr(buffer2);
      Hdr(hdr);
    }
  }
  else {
    sscanf(buffer, "%d", &min_ver);
  }
  Major_ver(maj_ver); Minor_ver(min_ver); MMinor_ver(mmin_ver);
}


void
VTXT_REPORT::Print_filepath(FILE *fp)
{
  FP_VEC::iterator iter;
  //fprintf(stdout, "%sScan Fid Path\n%s", SEPARATOR_s, SEPARATOR_s);
  if (File_paths().size() != 0)  {
    fprintf(fp, "[");
    BOOL first_ent = TRUE;
    for ( iter = File_paths().begin(); iter != File_paths().end(); ++iter ) {
      if (!first_ent) {
        fprintf(fp, ",\n");
      }
      else {
        fprintf(fp, "\n");
        first_ent = FALSE;
      }
      iter->Print(fp);
    }
    fprintf(fp, "\n]\n");
  }
}


void
VTXT_REPORT::Print(FILE *fp)
{
  fprintf(fp, "{%s}\n", Filekind());
  Print_filepath(fp);
  Print_curissue(fp);
}


void
MERGEF::Print(FILE *fp)
{
  fprintf(fp, "Fname:%s, Lnkid:%d, Lastln:%d\n", Fname(), Lnkid(), Lastln());
}

//
//  Update_uid_ikey: when parse one issue, if issuekey already exist, this issue
//                   should use the same unique_id + seq#.
//
char *
VTXT_REPORT::Update_uid_ikey(char *unique_id, char *pikey, UK_VEC& uid_key)
{
  UK_VEC::iterator iter = uid_key.begin();
  int vec_size = uid_key.size();
  int seq = 0;
  int i = 0;

  if (vec_size == 0) {
    seq = 1;
    sprintf(unique_id, "%.5s%.5d", unique_id, seq);
    UID_KEY *uk = new UID_KEY(seq, pikey);
    uid_key.push_back(*uk);
    delete uk;
    return unique_id;
  } else {
    for (; i < vec_size; i++) {
      if (strcmp(uid_key[i].Issuekey(), pikey) == 0) {
	seq = uid_key[i].Seqnum();
	sprintf(unique_id, "%.5s%.5d", unique_id, seq);
        return unique_id;
      }
    }
  }

  if (i == vec_size) {
    seq = uid_key[i-1].Seqnum() + 1;
    sprintf(unique_id, "%.5s%.5d", unique_id, seq);
    UID_KEY *uk = new UID_KEY(seq, pikey);
    uid_key.push_back(*uk);
    delete uk;
    return unique_id;
  }

  return 0;
}


INT
VTXT_REPORT::Parse_issue_hdr(FILE *in, VTXT_ISSUE& cur_issue, UK_VEC& uid_key, bool IF_SEQ)
{
  char *unique_id = Get_varlen_str(in, '[', ']');  // get unique_id
  if (unique_id == (char *)-1) // missing path table
    return 0;
  Skip_dlimiter(in, ',');

  char *pikey = Get_varlen_str(in, '[', ']');   // get issue_key
  if (pikey == (char *)-1)
    return 0;
  if ((pikey == 0) || (*pikey == '\0')) {
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input issue key error");
  }
  cur_issue.Issue_key(pikey);
  Skip_dlimiter(in, ',');

  if (IF_SEQ == true) {
    unique_id = Update_uid_ikey(unique_id, pikey, uid_key);
    if (unique_id != 0) {
      cur_issue.Unique_id(unique_id);
    } else {
      return 0;
    }
  } else {
    cur_issue.Unique_id(unique_id);
  }

  return 1;
}


void
VTXT_REPORT::Parse_fix_portion(FILE *in, VTXT_ISSUE& cur_issue, GLB_FP& glb_fp, INT lnkid, bool IF_MERGE)
{
  char *pfile = Get_varlen_str(in, '[', ']', '\0');    
  if ((pfile == 0) || (*pfile == '\0')) {
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : issue file name error\n");
  }  
  cur_issue.Fname(pfile); Skip_dlimiter(in, ',');  

  // (source <fileid, linenum>)
  char *fileid_lineno = Get_varlen_str(in, '[', ']', '\0');
  INT   fileid, linenum;
  sscanf(fileid_lineno, "%d:%d", &fileid, &linenum);
  // replace fid with new fid after merge
  if (IF_MERGE && fileid != -1)
    fileid = Replace_fid(glb_fp, lnkid, fileid);
  cur_issue.Filenum(fileid); cur_issue.Linenum(linenum); Skip_dlimiter(in, ',');
  
  char *pdft = Get_varlen_str(in, '[', ']', '\0');  // get defect category
  cur_issue.Dft_cat_name(pdft); Skip_dlimiter(in, ',');
    
  char *pconfidence = Get_varlen_str(in, '[', ']', '\0');  // get confidence
  if (strlen(pconfidence) != 1) {
    Handle_error(E_CSV_INVALID_INPUT_FILE, "Input confidence code error\n");
  }
  cur_issue.Conf_info_sym(pconfidence); Skip_dlimiter(in, ',');
  
  char *pdftid = Get_varlen_str(in, '[', ']', '\0');  // get defect 
  cur_issue.Rule_code(pdftid); Skip_dlimiter(in, ',');

  char *ignore = Get_varlen_str(in, '[', ']', '\0'); // copy flow, context, obj triple
  cur_issue.Fco_sens(ignore); Skip_dlimiter(in, ',');

  char  rule_set = 'X';
  // when the issue is RBC / MSR / GJB / ATS, record the issue category and error code.
  if (strcmp(pdftid, "RBC") == 0) {
    rule_set = 'S';
    // for RBC / MSR / GJB / ATS, there are two extra items to identify rule code
    pdftid = Get_varlen_str(in, '[', ']', '\0'); // first item is "CERT", "MSR", "GJB" or "ATS"
    cur_issue.Rule_type(pdftid); Skip_dlimiter(in, ',');    
    pdftid = Get_varlen_str(in, '[', ']', '\0');  // get true defect 
    cur_issue.Error_code(pdftid); Skip_dlimiter(in, ',');
  }
  cur_issue.Rule_set(rule_set);

  // variable name
  char *pvar = Get_varlen_str(in, '[', ']', '[');
  cur_issue.Vname(pvar); Skip_dlimiter(in, ',');

  // function name
  char *pfunc;
  if (Ver_cmp(0, 6, 0) >= 0 && Ver_cmp(0, 7, 2) < 0)
    pfunc = Get_varlen_str(in, '#', '#', '[');
  else
    pfunc = Get_varlen_str(in, '[', ']', '[');
  if (pfunc == (char *)0) 
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : Input issue function name error");
  cur_issue.Pname(pfunc); Skip_dlimiter(in, ',');
}

//
//  Replace_fid: When merger multi vtxt files, need map and replace fid from [fid:lineno] and var issue path.
//
INT
VTXT_REPORT::Replace_fid(GLB_FP& glb_fp, INT lnkid, int fid)
{
    int gid;
    LNK_VEC::iterator iter;
    for ( iter = glb_fp.Lnk_vec().begin(); iter != glb_fp.Lnk_vec().end(); iter++ ) {
      if (iter->Id() == lnkid) {
        gid = iter->Find_gid(fid);
        if (gid != 0) break;
      }
    }
    if (gid == 0)
      gid = fid;
    return gid;
}


INT
VTXT_REPORT::Get_1path_node(FILE *f, const char dlimiter, _PATH_NODE &pn, GLB_FP& glb_fp, INT lnkid, bool IF_MERGE)
{
  // a path from core consist of a triple separated by PN_SEPERATOR
  int fid, line, col, pinfoid;
  int i = fscanf(f, "%d", &fid);
  if (i == EOF) {
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : File ID error\n");
  }
  Skip_dlimiter(f, PN_SEPARATOR);

  i = fscanf(f, "%d", &line);
  if (i == EOF) {
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : line number error\n");
  }
  Skip_dlimiter(f, PN_SEPARATOR);

  i = fscanf(f, "%d", &col);
  if (i == EOF) {
    Handle_error((long)E_CSV_INVALID_INPUT_FILE," : line number error\n");
  }
  Skip_dlimiter(f, PN_SEPARATOR);

  i = fscanf(f, "%d", &pinfoid);
  if (i == EOF) {
        Handle_error((long)E_CSV_INVALID_INPUT_FILE," : path_info error\n");
  }
  //printf("fid:line:col:pinfoid - %d:%d:%d:%d\n", fid, line, col, pinfoid);

  // when run the merge function, map and replace fid from var issue path to fid_path
  if (IF_MERGE && fid != -1) {
    assert(lnkid != 0);
    fid = Replace_fid(glb_fp, lnkid, fid);
  }

  pn.File_id(fid);
  pn.Line_num(line);
  pn.Col_num(col);
  pn.Node_desc(pinfoid);

  char c;   // either ",", "." or "]" expected
  i = fscanf(f, "%c", &c);

  if (c == PN_SEPARATOR || c == PN_TRUNC_SEPARATOR)
    return 1;

  if (c == ']')
    return 0;

  return i;
}


void
VTXT_REPORT::Parse_variable_portion(FILE *in, VTXT_ISSUE& cur_issue, GLB_FP& glb_fp, INT lnkid, bool IF_MERGE)
{
  //
  // deal with variable length part
  //
  Skip_dlimiter(in, '[');

  int i;
  int num_nodes  = 0;
  _PATH_NODE pn;
  do {
    i = Get_1path_node(in, ',', pn, glb_fp, lnkid, IF_MERGE);
    if (i == 0) {
      Skip_dlimiter(in, '\n');
    }

    num_nodes++;

    // map file index to strtab offset in appropriate string table
    int index = pn.File_id();

    if (index == 65535) {
      pn.Line_num(-1); pn.Col_num(-1); pn.File_id(-1); pn.Node_desc(-1);
      pn.Node_num(num_nodes);
      cur_issue.Push_back(pn);
    } else if (index >= 0) {
      pn.Node_num(num_nodes);
      cur_issue.Push_back(pn);
    } else {
      Handle_error(E_CSV_INVALID_OUTPUT_FILE, "File index error, out of bound");
    }
  } while (i != 0); // end of one record
}


void
VTXT_REPORT::Apply_stl_filter(VTXT_ISSUE& cur_issue)
{
  char *pname = cur_issue.Pname();
  for( const std::pair<std::string, int>& n : Stlfilt() ) {
    if (strstr(pname, n.first.c_str()) != NULL) {  // two string content overlapped
      cur_issue.Action(ACTION_FOUT_STL);
      break;
    }
  }
}

void
VTXT_REPORT::Apply_maybe_filter(VTXT_ISSUE& cur_issue)
{
  if (! Filt_maybe()) return;
  char *conf_info = cur_issue.Conf_info_sym();
  if (strcmp(conf_info, "M") == 0)
    cur_issue.Action(ACTION_FOUT_MAYBE);
}

IDTYPE
VTXT_REPORT::Put_stlfilter(char *filt, IDTYPE id)
{
  IDTYPE rid = _stlfilt[filt];
  if (rid == 0) {
    _stlfilt[filt] = id;
  }
  else if (rid != id) {
    char *errMsg = (char*)malloc(1024);
    sprintf(errMsg, "Filter pattern conflict, pattern:%s, id: %d, prior id: %d", filt, id, rid);
    Handle_error(E_CSV_CONFLICT_STLFILTER, errMsg);
    free(errMsg);
  }
  return id;
}

void
VTXT_REPORT::Build_stl_filter(char* filterspec)
{
  // read filter specification line by line and store in the _stlfilt
  if (filterspec == NULL) return;

  FILE   *input;
  input = fopen(filterspec, "r");
  if (input == NULL) {
    fprintf(stderr, "%s does not exist\n", filterspec);
    exit(1);
  }
  char *line= NULL;
  size_t line_len = 0;
  ssize_t ret;
  while ((ret = getline(&line, &line_len, input)) > 0) {
    if (line[ret-1] == '\n') {
      line[ret-1] = '\0';
      --ret;
    }
    char *str = line;
    while (*str == ' ') {
      ++str;
    }
    if (*str == '\0')
      continue;
    char *token = Get_next_token(&line, ',');
    line = Skip_dlimiter(line, ',');
    char *idstr = Get_next_token(&line, '\0');
    IDTYPE id = atoi(idstr);
    Put_stlfilter(token, id);
    //printf("VTXT_REPORT::Build_stl_filter {%s : %d}\n", token, id);
    free(idstr);
  }
}

INT
VTXT_REPORT::Reopen_input(FILE **in)
{
  if (*in == NULL) {
    *in = fopen(Infile(), "r");
    if (*in == NULL) {
      fprintf(stderr, "%s does not exist\n", Infile());
      exit(1);
    }
    // skip the first number of lines specified in Hdr_end()
    for (INT line_no = 0; line_no < Hdr_end(); ++line_no) {
      char* fpath = NULL;
      size_t len = 0;
      ssize_t nread;
      nread = getline(&fpath, &len, *in); // skip fid_path section
    }
    return 0;
  }
  return 1;
}

INT
VTXT_REPORT::Read_issues(FILE *in, GLB_FP& glb_fp, INT lnkid, UK_VEC& uid_key)
{
  // need to open file if in is NULL
  BOOL need_close = FALSE;
  if (in == NULL) {
    if (Reopen_input(&in) == 0)
      need_close = TRUE;
  }

  do {
    VTXT_ISSUE cur_issue;
    INT status;
    status = Parse_issue_hdr(in, cur_issue, uid_key, IF_SEQ_F);
    if (status == 0)
      return status;
    Parse_fix_portion(in, cur_issue, glb_fp, lnkid, IF_MERGE_F);
    Parse_variable_portion(in, cur_issue, glb_fp, lnkid, IF_MERGE_F);
    Apply_stl_filter(cur_issue);
    Apply_maybe_filter(cur_issue);
    cur_issue.Print(Out(), (Ver_cmp(0, 6, 0) >= 0 && Ver_cmp(0, 7, 2) < 0));
  } while (1);
  if (need_close) fclose(in);
}


void
DRIVER::Read_vtxt_file(void)
{
  if (_test_file == NULL)
    return;

  VTXT_REPORT vtxt_rpt(_test_file, _outfile, (char*)"V", _stlfiltfile, _action);
  INT   end;
  FILE *input;

  input = vtxt_rpt.Read_filehdr(end, NULL);
  if (input == NULL) {
    return;
  }
  else {
    vtxt_rpt.Print();
    // test one record
    vtxt_rpt.Read_issues(input, Glb_fp(), 0, Uid_key());
  }
}


// =============================================================================
//
// Read_write_issues, stream in issue, replace fid, stream out
//
// =============================================================================
void
MERGEF::Read_write_issues(FILE *fp, GLB_FP& glb_fp, UK_VEC& uid_key)
{
  VTXT_REPORT *vtxt_rpt = Rpt();
  vtxt_rpt->Out(fp);
  FILE *in = Fp();
  if (in == NULL)
    vtxt_rpt->Reopen_input(&in);

  do {
    VTXT_ISSUE  cur_issue;
    if (vtxt_rpt->Parse_issue_hdr(in, cur_issue, uid_key, IF_SEQ_T) == 0) {
      if (Fp() == NULL)
        fclose(in);
      return;
    }
    vtxt_rpt->Parse_fix_portion(in, cur_issue, glb_fp, Lnkid(), IF_MERGE_T);
    vtxt_rpt->Parse_variable_portion(in, cur_issue, glb_fp, Lnkid(), IF_MERGE_T);
    //fm->Replace_fid(cur_issue, Lnkid());
    cur_issue.Print(fp, (vtxt_rpt->Ver_cmp(0, 6, 0) >= 0 && vtxt_rpt->Ver_cmp(0, 7, 2) < 0));
  } while (1);
}

INT
DRIVER::Collect_files_4_merge(char *filelist)
{
  INT i = 0;

  // read filelist line by line and create VTXT_REPORT for them
  if (filelist == NULL) return i;

  FILE   *input;
  input = fopen(filelist, "r");
  if (input == NULL) {
    fprintf(stderr, "%s does not exist\n", filelist);
    exit(1);
  }
  char *line= NULL;
  size_t line_len = 0;
  ssize_t ret;
  while ((ret = getline(&line, &line_len, input)) > 0) {
    if (line[ret-1] == '\n') {
      line[ret-1] = '\0';
      --ret;
    }
    // skip leading space
    char *str = line;
    while (*str == ' ') {
      ++str;
    }
    if (*str == '\0') // empty line
      continue;

    VTXT_REPORT *rpt = new VTXT_REPORT(str, NULL, NULL, NULL, ACTION_NONE, FALSE);
    Mergee().push_back(MERGEF(rpt));
    ++i;
  }

  return i;
}


void
DRIVER::Read_write_issues(FILE *fp, GLB_FP& glb_fp)
{
  if (Mergee().size() == 0)
    return;

  MF_VEC::iterator iter;
  for ( iter = Mergee().begin(); iter != Mergee().end(); ++iter ) {
    iter->Read_write_issues(fp, glb_fp, Uid_key());
  }

}


void
DRIVER::Print(FILE *fp)
{
  MF_VEC::iterator iter3;
  fprintf(fp, "%sList of files to be merged\n%s", SEPARATOR_s, SEPARATOR_s);
  if (Mergee().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for ( iter3 = Mergee().begin(); iter3 != Mergee().end(); ++iter3 ) {
      iter3->Print(fp);
    }
  }
}


// =============================================================================
//
// FIND_MATCH::Merge_files, reads contents of all Mergee file list and merge
//                          into M_TXT file
//
// =============================================================================
void
DRIVER::Merge_files(void)
{
  // open and read all input files' file_path section
  MF_VEC::iterator iter;
  if (Mergee().size() == 0)
    return;
  else {
    //printf("Merge files into %s\n", M_TXT);
    for ( iter = Mergee().begin(); iter != Mergee().end(); ++iter ) {
      //printf("Read file %s header\n", iter->Fname());
      INT   last_ln;
      FILE *fp = iter->Rpt()->Read_filehdr(last_ln, Glb_fp_ref());
      iter->Lastln(last_ln);
      iter->Lnkid(Glb_fp().Last_lnkid());
      iter->Fp(fp);
    }
  }
  Print(stdout);

  //assert(Glb_fp().All_unique());
  
  FILE *output_file = fopen(M_TXT, "w");
  Glb_fp().Print_json(output_file);

  Read_write_issues(output_file, Glb_fp());

  fclose(output_file);
  exit(0);
}


#ifdef VTXTREADER
INT main(int argc, char **argv) {
  DRIVER driver;
  if (driver.Process_option(argc, argv) != 0)
    return 1;

  driver.Read_vtxt_file();
  
  return 0;
}
#endif
