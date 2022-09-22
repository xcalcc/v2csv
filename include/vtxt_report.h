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
// Module: vtxt_report.h
//
// Description:
//
// =============================================================================
// =============================================================================
//

#ifndef VTXT_REPORT_H
#define VTXT_REPORT_H

#include <vector>
using namespace std;

#include "commondefs.h"
#include "filepath.h"
#include "srcpos.h"
#include "vtxt_hdr.h"       // vtxt file hdr definition
#include "vtxt_issue.h"

#ifndef CSVERRCODE_H
#define CSVERRCODE_H

#define  E_CSV_INVALID_INPUT_FILE   0
#define  E_CSV_OUT_OF_MEMORY        1
#define  E_CSV_INVALID_OUTPUT_FILE  2
#define  E_CSV_SIZE                 3
#define  E_CSV_INVALID_INPUT_STRING 4
#define  E_CSV_CONFLICT_STLFILTER   5

#endif
extern INT32 Csv_errcode(INT c);

// =============================================================================
//
// 
//
// =============================================================================
//

#define IF_MERGE_T true
#define IF_MERGE_F false
#define IF_SEQ_T   true
#define IF_SEQ_F   false

class UID_KEY {
private:
  int            _seq_num;
  char          *_issuekey;

public:
  UID_KEY(int n, char *k): _seq_num(n), _issuekey(k) {}

  void           Set_seq_num(int n)     { _seq_num = n; }
  void           Set_issuekey(char *k)  { _issuekey = k; }
  int            Seqnum(void)           { return _seq_num; }
  char          *Issuekey(void)         { return _issuekey; }
};

typedef vector<UID_KEY> UK_VEC;

class VTXT_REPORT {
private:
  char          *_infile;     // input file, prefix.vtxt will be created
  char          *_outfile;    // output file
  char          *_errmsg;
  FILE          *_out;        // output file
  char          *_filekind;   // {"V", magic, version} for xvsa
  int            _hdr_end;
  float          _version;
  int            _major_ver;  // three level versioning
  int            _minor_ver;  // three level versioning
  int            _mminor_ver; // three level versioning
  FP_VEC         _file_paths; // file path
  ACTION         _action;     // a mask for all actions defined in vtxt_issue.h
  STR_MAP        _stlfilt;
  IDTYPE         _stlfiltid;

  VTXT_HDR      *_vtxt_hdr;   // the header info of _infile
  VTXT_ISSUE    *_cur_issue;  // cache the pointer for cur_issue, not in use
  struct timeval _scan_start; // time when scan starts
  struct timeval _scan_end;   // time when scan ends

  VTXT_REPORT(const VTXT_REPORT&);            // no copy constructor
  VTXT_REPORT& operator=(const VTXT_REPORT&); // no assign operator

  // helper functions
  char       *Outfile(void)         { return _outfile; }
  char       *Filekind(void)        { return _filekind; }
  void        Filekind(char *);
  FILE       *Out(void)             { return _out; }
  void        Set_out(FILE *o)      { _out = o; }
  void        Set_outfile(char *f)  { _outfile = f; }
  void        Open_ofile(void);
  void        Flush(void)           { if (_out != NULL) fflush(_out); }
  void        Errmsg(char *msg)     { _errmsg = Clone_string(msg); }

  INT         Import_filepath(FILE *f, GLB_FP *glb_fp);
  FILE_PATH  *Make_fpath(char *s, int strtab_ofs, int id);
  INT32       Code(int c)           { return Csv_errcode(c); }
  FILE_PATH  *Get_path_str(char *path, char dlimiter_beg, char dlimiter_end);

  INT         Findchar(char *b, char c) { for (; *b != '\0'; ++b) {if (*b == c) return 1;} return 0; }
  char       *Skip_dlimiter(char *, char d);
  char       *Skip_dlimiter(char *path, char d1, char d2);
  void        Skip_dlimiter(FILE *f, char d);
  char       *Skip_till(char *k, char dlimiter) {  for (++k; *k != dlimiter && *k != '\0'; ++k) ; return k; }
  BOOL        Validate_file_attr(VTXT_KIND kind, char *attr);
  char       *Get_next_token(char **in, char dlimiter);
  char       *Get_varlen_str(FILE *in, char dlimiter_beg, char dlimiter_end);
  char       *Get_varlen_str(FILE *in, char dlimiter_beg, char dlimiter_end, char pe);
  INT         Remove_outfile()      { return remove(_outfile); }
  void        Handle_error(const int err, const char *msg2)
                                    { fprintf(stderr, "%8x, %s\n", Code(err), msg2),
                                      (void)Remove_outfile(), exit(EXIT_FAILURE); }
  void        Handle_error(const char *msg) { fprintf(stderr, "%s\n", msg),
                                        (void)Remove_outfile(), exit(EXIT_FAILURE); }

  char       *Get_prefix(char *f,char **end);// Create the prefix from a filepath
  char*       Clone_string(char *s) { return Clone_data(s); }

  BOOL        Filt_stl(void) const  { return (_action & ACTION_FOUT_STL) != 0; }
  BOOL        Filt_maybe(void) const{ return (_action & ACTION_FOUT_MAYBE) != 0; }

  STR_MAP&    Stlfilt(void)         { return _stlfilt;  }
  STR_MAP    *Stlfiltref(void)      { return &_stlfilt; }
  IDTYPE      Stlfilterid(void)     { return ++_stlfiltid; }
  IDTYPE      Put_stlfilter(char *filt, IDTYPE id);
  void        Build_stl_filter(char* filterspec);
  void        Apply_stl_filter(VTXT_ISSUE& cur_issue);
  void        Apply_maybe_filter(VTXT_ISSUE& cur_issue);

public:
  VTXT_REPORT(char* i, char *o, char* k, char *s, ACTION a, BOOL needofile = TRUE):
    _action(a), _stlfiltid(0), _version(0), _major_ver(0), _minor_ver(0), _mminor_ver(0),
    _vtxt_hdr(NULL), _cur_issue(NULL), _errmsg(NULL), _filekind(NULL), _hdr_end(0),
    _out(NULL) {
    if (i) _infile = Clone_string(i);
    if (o) _outfile = Clone_string(o);
    if (k) _filekind = Clone_string(k);
    if (s) Build_stl_filter(s);
    if (needofile) Open_ofile();
  }
  VTXT_REPORT(FILE *op):_action(ACTION_NONE),
                        _infile(NULL),
                        _outfile(NULL),
                        _errmsg(NULL),
                        _filekind(NULL),
                        _version(0),
                        _hdr_end(0),
                        _major_ver(0),
                        _minor_ver(0),
                        _mminor_ver(0),
                        _vtxt_hdr(NULL),
                        _cur_issue(NULL),
                        _out(op) { }
  ~VTXT_REPORT(void) {
    Flush();
    if (_infile != NULL) free(_infile);
    if (_outfile != NULL) free(_outfile);
    if (_errmsg != NULL) free(_errmsg);
    if (_filekind != NULL) free(_filekind);
    if (_vtxt_hdr != NULL) free(_vtxt_hdr);
  }

  char       *Infile(void)          { return _infile; }
  INT         Reopen_input(FILE **);
  void        Out(FILE *fp)         { _out = fp; }
  float       Version(void)         { return _version; }
  INT         Ver_cmp(mINT32 maj, mINT32 min, mINT32 mmin) {
    if (maj > _major_ver) return -1;
    if (maj < _major_ver) return 1;
    if (min > _minor_ver) return -1;
    if (min < _minor_ver) return 1;
    return (_mminor_ver - mmin);
  }
  int         Hdr_end(void)         { return _hdr_end;   }
  void        Hdr_end(int he)       { _hdr_end = he;     }
  int         Major_ver(void)       { return _major_ver; }
  void        Major_ver(int v)      { _major_ver = v;    }
  int         Minor_ver(void)       { return _minor_ver; }
  void        Minor_ver(int v)      { _minor_ver = v;    }
  int         MMinor_ver(void)      { return _mminor_ver; }
  void        MMinor_ver(int v)     { _mminor_ver = v;    }
  FP_VEC&     File_paths(void)      { return _file_paths; }
  FILE       *Read_filehdr(INT &end, GLB_FP *glb_fp);
  INT         Replace_fid(GLB_FP&,INT, int);
  INT         Get_1path_node(FILE *, const char, _PATH_NODE &, GLB_FP&, INT, bool); 
  void        Parse_variable_portion(FILE *in, VTXT_ISSUE& cur_issue, GLB_FP&, INT, bool);
  void        Parse_fix_portion(FILE *in, VTXT_ISSUE& cur_issue, GLB_FP&, INT, bool);
  INT         Parse_issue_hdr(FILE *in, VTXT_ISSUE& cur_issue, UK_VEC&, bool);
  char       *Update_uid_ikey(char *, char *, UK_VEC&);
  INT         Read_issues(FILE *in, GLB_FP&, INT, UK_VEC&);
  VTXT_HDR   *Hdr(void)             { return _vtxt_hdr;  }
  void        Hdr(VTXT_HDR *hdr)    { _vtxt_hdr = hdr;   }
  VTXT_ISSUE *Cur_issue(void)       { return _cur_issue; }

  void        Verify(void);

  void        Print_curissue(FILE *p)  { if (_cur_issue) _cur_issue->Print(p, (Ver_cmp(0, 6, 0) >= 0 && Ver_cmp(0, 7, 2) < 0)); }
  void        Print_filepath(FILE *p);
  void        Print(FILE *fp);

  // for debugger
  void        Print_curissue(void)     { if (_out) Print_curissue(_out); Flush(); }
  void        Print_filepath(void)     { if (_out) Print_filepath(_out); Flush(); }
  void        Print(void)              { if (_out) Print(_out); Flush(); }
};


// =============================================================================
//
// MERGEF is the basis of the adminstration class for vtxt file merge.
// The actual management is done through the MF_VEC reside in the program driver
//
// =============================================================================
class MERGEF {
private:

  FILE        *_infp;           // file pointer
  VTXT_REPORT *_inhandle;
  INT          _lnkid;          // the index into the local-global map
  INT          _lastln;         // last line for fid_path, issue start
  FP_VEC       _fp_vec;         // Fid_path for this file

public:
  MERGEF(VTXT_REPORT *rpt): _infp(NULL),
                            _inhandle(rpt) {}
  ~MERGEF(void) { if (_infp != NULL) fclose(_infp); }

  char        *Fname(void)      { return _inhandle->Infile(); }
  FILE        *Fp(void)         { return _infp; }
  void         Fp(FILE *fp)     { _infp = fp; }
  VTXT_REPORT *Rpt(void)        { return _inhandle; }
  INT          Lnkid(void)      { return _lnkid; }
  INT          Lnkid(INT l)     { return (_lnkid = l); }
  INT          Lastln(void)     { return _lastln; }
  INT          Lastln(INT l)    { return (_lastln = l); }
  FP_VEC&      Fp_vec(void)     { return _fp_vec; }
  void         Print(FILE *fp);
  void         Read_write_issues(FILE *fp, GLB_FP&, UK_VEC&);
};

typedef vector <MERGEF> MF_VEC;

#define M_TXT "xvsa-xfa-dummy.mtxt" // Merged output file from multiple vtxt files

class DRIVER {
private:
  char    *_test_file;
  char    *_outfile;
  MF_VEC   _mergee;          // the list of files to be merged
  char    *_stlfiltfile;
  ACTION   _action;          // what action against the issue
  GLB_FP   _glb_fp;          // Global Fid_Path 
  UK_VEC   _uid_key;

  DRIVER(const DRIVER&);              // REQUIRED UNDEFINED UNWANTED methods
  DRIVER& operator = (const DRIVER&); // REQUIRED UNDEFINED UNWANTED methods

  MF_VEC&  Mergee(void)           { return _mergee; }
  void     Action(ACTION a)       { _action = (ACTION) ((INT)_action|(INT)a); }
  ACTION   Action(void) const     { return _action; }

  void     Output_fname_only(void){ _action != ACTION_OFNAM; }

  void     Print(FILE *fp);
  void     Print_option_guide(char *arg) {
    printf("Unrecognized Option: \"%s\"\n", arg);
    printf("Usage: ./vtxtreader -i input.vtxt -o output.vtxt -filts stlfilter.inc -merge *.vtxt -fmerge vtxt_filelist.txt \n");
  }

  GLB_FP&  Glb_fp(void)          { return _glb_fp; }
  GLB_FP  *Glb_fp_ref(void)      { return &_glb_fp; }
  UK_VEC&  Uid_key(void)         { return _uid_key; }
  void     Push_back(FID_PATH fp);

  FILE    *Read_vtxt_filehdr(char *vtxt_file, INT& istart_line, VTXT_KIND k, FP_VEC& mf);
  void     Read_write_issues(FILE *fp, GLB_FP&);
  INT      Collect_files_4_merge(char *vtxt_filelist);

  INT      Collect_files_2b_merged(int argc, char **argv) {
    INT i;
    for (i = 1; i < argc; i++) {
      if (argv[i][0] == '-')
        return i;
      VTXT_REPORT *rpt = new VTXT_REPORT(argv[i], NULL, NULL, NULL, ACTION_NONE, FALSE);
      Mergee().push_back(MERGEF(rpt));
    }
    return i;
  }


public:
  DRIVER(void): _test_file(NULL),
                _outfile(NULL),
                _stlfiltfile(NULL),
                _action(ACTION_NONE) { }
  ~DRIVER(void) { }

  void     Merge_files(void);
  void     Read_vtxt_file(void);

  INT      Process_option(INT argc, char **argv) {
    for (INT i = 1; i < argc; i++) {

      if (argv[i][0] == '-') {
        switch (argv[i][1]) {
        case 'i':
          _test_file = argv[i+1];
          ++i;
          break;
        case 'o':
          _outfile = argv[i+1];
          ++i;
          break;
        case 'f':
          // -filt option
          if (argv[i][2] == 'i' && argv[i][3] == 'l' && argv[i][4] == 't') {
            switch (argv[i][5]) {
            case 's': // stl filter
              _stlfiltfile = argv[i+1];
              Action(ACTION_FOUT_STL);
              ++i;
              break;
            case 'f': // print out only function name
              Output_fname_only();
              break;
            default:
              Print_option_guide(argv[i]);
              return 2;
            }
          }
          else if (argv[i][2] == 'm' && argv[i][3] == 'e' && argv[i][4] == 'r' && argv[i][5] == 'g' && argv[i][6] == 'e') {
            Collect_files_4_merge(argv[i+1]);
            ++i;
          }
          else {
            Print_option_guide(argv[i]);
            return 2;
          }
          break;
        case 'm':
          if (argv[i][2] == 'a' && argv[i][3] == 'y' && argv[i][4] == 'b' && argv[i][5] == 'e') {
            Action(ACTION_FOUT_MAYBE);
          }
          else if (argv[i][2] == 'e' && argv[i][3] == 'r' && argv[i][4] == 'g' && argv[i][5] == 'e') {
            i += Collect_files_2b_merged(argc - i, &argv[i]);
          }
          else {
            Print_option_guide(argv[i]);
            return 2;
          }
          break;
        default:
          Print_option_guide(argv[i]);
          return 2;
        }
      } else {
        Print_option_guide(argv[i]);
        return 2;
      } // process one option
    } // loop through argument list
    return 0;
  }


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
#endif // DEBUG_ON

#endif // VTXT_REPORT_H
