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
// Module: cvsreader.h
//
// Description:
//
// This header file efines abstractions for capturing CSV which is either input
// from a file with ".csv" suffix or a string.
//
// Besides the CSV / CSVROW, this file also defines the managing class to parse
// to parse the input and produce one row at a time.
//
// =============================================================================
// =============================================================================
//

#ifndef CSVREADER_H
#define CSVREADER_H

#include "commondefs.h"

typedef enum {
  INIT_ROW_WIDTH = 8,
  INIT_FIELD_LEN = 64
} CONFIGS;

typedef enum {
  NO_UTF8   = 0x0,
  UTF8      = 0x1,
  NOGENENUM = 0x2,
  GENENUM   = 0x4,
  GENPMJSON = 0x8,
  GENRULEMAP= 0x10,
  GENVERSION= 0x20,
  GENOWASP  = 0x40,
  GENCWE    = 0x80,
  GENP3C    = 0x100,
  GENCSV    = 0x200,
  GENPMJSON1= 0x400,
} _FLAGS;

typedef enum {
  FILT_CWE,
  FILT_OWASP
} _FILTER;

// =============================================================================
//
// CSVROW - the content of a CSV row
//
// =============================================================================
template <class T>
class SIMPARR {
private:
  T   *_assign;      // number of entries in the row
  T   *_begin;       // entry content, variable length array
  T   *_end;
  BOOL _nested_free;

  SIMPARR(void);                        // REQUIRED UNDEFINED UNWANTED methods
  SIMPARR(const SIMPARR&);              // REQUIRED UNDEFINED UNWANTED methods
  SIMPARR& operator = (const SIMPARR&); // REQUIRED UNDEFINED UNWANTED methods

public:
  SIMPARR(INT init_size, BOOL nested_free = TRUE): _nested_free(nested_free),
	_assign(NULL), _begin(NULL), _end(NULL) {
    _begin = (T*) malloc(sizeof(T) * init_size);
    if (_begin != NULL) {
      _assign = _begin;
      _end = _begin + init_size;
    }
  }

  ~SIMPARR(void) {
    if (_begin == NULL) return;
    if (_nested_free) {
      // a typical iterator
      for (T *iter = Begin(); iter != Last(); ++iter) {
        free((void *)*iter);
      }
    }
    free(_begin);
  }
  INT  Elem_cnt(void)               { return _assign - _begin; }
  T*   Begin(void)                  { return _begin; };
  T*   End(void)                    { return _end; };
  T*   Last(void)                   { return _assign; };
  BOOL Is_empty(void)               { return _begin == _assign; }
  void Back(void)                   { --_assign; }
  T*   Assign_into(T value) {
    // Check if we need to realloc and double the size of the row.
    if (_assign >= _end) {
      INT cur_size = _end-_begin;
      INT new_size = cur_size*2;
      T *newrow = (T*) realloc(_begin, sizeof(T) * new_size);
      if (newrow != NULL) {
        // successful realloc
        _begin = newrow;
        _assign = _begin+cur_size;
        _end = _begin+new_size;
      }
      else {
        return NULL;
      }
    }
    *_assign = value;
    T *retv = _assign;
    ++_assign;
    return(retv);
  }

};

typedef SIMPARR<char*> CSVROW;     // need nested free in dtor
typedef SIMPARR<char> CHARBUF;     // no need for nested free in dtor
typedef SIMPARR<CSVROW*> CSVTAB;

// =============================================================================
//
// CSVREADER - Parses the .csv file or an equivalent string, and return CSVROW
//             one by one to the caller.
//
// =============================================================================
class CSVREADER {
  friend class CSVWORKER;
  BOOL     _fromstring;      // the source is a string, instead of a file
  char    *_filepath;        // the .csv file contains source
  FILE    *_filep;           // FILE pointer for the .csv file
  char    *_csvstring;       // the string for the whole csv table
  INT      _csvstringcursor; // track the cursor location

  char     _delimiter;       // the character separate fields
  INT      _headerln;        // the CSV has header row
  INT      _rownum;          // Row number in the CSV file
  CSVROW  *_header;          // points to the header row
  char    *_errmsg;          // error message when abort
  BOOL     _has_utf8;        // input file contains UTF8 char
  
  BOOL     Fromstring(void)      { return _fromstring; }
  FILE    *Filep(void)           { return _filep; }
  char    *Csvstring(void)       { return _csvstring; }
  INT      Csvstringcursor(void) { return _csvstringcursor; }
  void     Inc_csvstringcursor(void) { ++_csvstringcursor; }

  BOOL     Is_delimit(char c)    { return c == _delimiter; }
  char     Delimiter(void)       { return _delimiter; }
  CSVROW  *Header(void)          { return _header; }
  CSVROW  *Set_header(CSVROW *h) { return(_header = h); }
  BOOL     Has_utf8(void)        { return _has_utf8; }

  BOOL     Verify(void);     // return FALSE if failure

  CSVREADER(void);                           // REQUIRED UNDEFINED UNWANTED methods
  CSVREADER(const CSVREADER&);               // REQUIRED UNDEFINED UNWANTED methods
  CSVREADER& operator = (const CSVREADER&);  // REQUIRED UNDEFINED UNWANTED methods

  void     Set_filep(FILE* p){ _filep = p; }

  void     Set_errmsg(char *errmsg) {
    if (_errmsg != NULL) free(_errmsg);   // keeps only one errmsg
    _errmsg = Clone_string(errmsg);
  }

  BOOL     Legal_delimiter(const char *delimit) {
    switch (*delimit) {
    case '\n':
    case '\r':
    case '\0':
    case '\"':
      return FALSE;
    default:
      return TRUE;
    }
  }

  CSVROW * Get_row(void);
  void     Set_rownum(void)      { _rownum++;        }

  void     Remove_trail_space(char *buf) {
    if (strlen(buf) == 0)
      return;
    char *end = buf+strlen(buf);
    for (--end; end != buf; --end) {
      if (*end == ' ') {
        *end = '\0';
      }
      else {
        break;
      }
    }
    if (*end == ' ') *end = '\0'; // do not let the single space go
  }

  char*    Clone_string(char *orig) {
    if (orig != NULL) {
      Remove_trail_space(orig);
      char *retv = (char*)malloc(strlen(orig)+1);
      if (retv == NULL) {
        Set_errmsg((char *)"Fail to allocate memory during Clong_string");
        return NULL;
      }
      strcpy(retv, orig);
      return retv;
    }
    return orig;
  }

public:
  CSVREADER(const char *filepath, const char *delimit, BOOL header_lines, BOOL utf8):
    _fromstring(FALSE), _filep(NULL), _headerln(header_lines), _rownum(1), _header(NULL),
  _errmsg(NULL), _has_utf8(utf8), _csvstring(NULL), _csvstringcursor(0) {
    _filepath = Clone_string((char *)filepath);
    if (delimit == NULL) {
      _delimiter = ',';
    }
    else if (!Legal_delimiter(delimit)) {
      _delimiter = '\0';
    }
    else {
      _delimiter = *delimit;
    }
  }

  CSVREADER(BOOL fromstring, char *csvstring, char* delimit, BOOL header_lines, BOOL utf8):
    _fromstring(fromstring), _filepath(NULL), _filep(NULL), 
    _headerln(header_lines), _rownum(1), _header(NULL), _errmsg(NULL), _has_utf8(utf8),
    _csvstringcursor(0) {
    _csvstring = Clone_string(csvstring);
    if (delimit == NULL) {
      _delimiter = ',';
    }
    else if (!Legal_delimiter(delimit)) {
      _delimiter = '\0';
    }
  }

  ~CSVREADER(void) {
    if (_filepath != NULL)   free(_filepath); 
    if (_filep != NULL)      fclose(_filep);
    if (_errmsg != NULL)     free(_errmsg);
    if (_header != NULL)     { free(_header); _header = NULL; }
    if (_csvstring != NULL)  free(_csvstring);
  }

  char    *Filepath(void)    { return _filepath; }
  INT      Hasheader(void)   { return _headerln; }
  char    *Errmsg(void)      { return _errmsg;   }
  INT      Get_rownum(void)  { return _rownum;   }
  CSVROW  *Read_header(void);
  CSVROW  *Read_row(void);

};

class CSVWORKER {
private:
  CSVROW    *_row;
  INT        _begincol;           // the starting column for printing guide
  INT        _endcol;             // to print the number of column
  CSVREADER *_csvreader;
  FILE      *_ofile;              // to store struct init or JSON in EN
  FILE      *_ofile_cn;           // to store enum typedef or JSON in CN
  FILE      *_efile;              // to store enum typedef or JSON in CN
  INT        _litno;              // enum literal numbering
  INT        _rsvdlitno;          // reserved enum numbering
  char      *_prefix;             // for enumlit gen, free by dtor
  CSVTAB    *_csvtab;             // build the whole table
  _FLAGS     _ofiletype;          // the type of output file

  CSVROW    *Row(void)            { return _row; }
  CSVROW    *Set_row(CSVROW *r)   { return (_row = r); }
  INT        Printcol(void)       { return _endcol - _begincol; }
  INT        Begincol(void)       { return _begincol; }
  INT        Endcol(void)         { return _endcol; }
  CSVREADER *Csvreader(void)      { return _csvreader; }
  FILE      *Ofile(void)          { return _ofile; }
  void       Set_ofile_cn(FILE *p){ _ofile_cn = p; }
  FILE      *Ofile_cn(void)       { return _ofile_cn; }
  void       Set_efile(FILE *p)   { _efile = p; }
  FILE      *Efile(void)          { return _efile; }
  INT        Assign_lit(void)     { return _litno++; }
  INT        Assign_rsvdlit(void) { return _rsvdlitno++; }

  void       Open_ofile(char *f, _FLAGS genenum);
  char      *Get_prefix(char *f,char **end);// Create the prefix from a filepath
  void       Set_prefix(char *p)  { _prefix = p; }
  char      *Prefix(void)         { return _prefix; } // return saved prefix
  _FLAGS     Ofiletype(void)      { return _ofiletype; }

  CSVTAB    *Set_tab(CSVTAB *t)   { return (_csvtab = t); }
  CSVTAB    *Csvtab(void)         { return _csvtab; }

  BOOL       To_print_row(void);
  BOOL       Format_json(void)    { return (Ofiletype() == GENPMJSON ||
                                            Ofiletype() == GENPMJSON1 ||
                                            Ofiletype() == GENRULEMAP ||
                                            Ofiletype() == GENVERSION ||
                                            Ofiletype() == GENOWASP ||
                                            Ofiletype() == GENCWE ||
                                            Ofiletype() == GENP3C); }
  char      *Get_varlen_str(char *buf, char dlimiter);
  char      *Get_last_token(char *buf);
  char      *Toupper(char *buf);
  void       Print_enumlit(char *lit, const char *fmt);
  void       Print_nested_object(const char **fmt, const BOOL *en_ctrl, const BOOL *cn_ctrl, INT ctrl);
  void       Print_header(const BOOL *filter_ctrl, INT ctrl);
  void       Filter_rows(const BOOL *filter_ctrl, INT ctrl);
  void       Print_rows(const char **fmt, const BOOL *en_ctrl, const BOOL *cn_ctrl, INT ctrl);

  CSVWORKER(void);                          // REQUIRED UNDEFINED UNWANTED methods
  CSVWORKER(const CSVWORKER&);              // REQUIRED UNDEFINED UNWANTED methods
  CSVWORKER& operator = (const CSVWORKER&); // REQUIRED UNDEFINED UNWANTED methods
public:
  CSVWORKER(char *filepath, char *delimit, BOOL wheader, INT scol, INT pcol, _FLAGS utf8, _FLAGS genenum, BOOL rdonly, INT ln=0):
    _row(NULL), _begincol(scol), _ofile(NULL), _ofile_cn(NULL), _efile(NULL),
    _litno(ln), _rsvdlitno(0), _prefix(0), _ofiletype(genenum) {
    _csvreader = new CSVREADER(filepath, delimit, wheader, utf8);
    _endcol = _begincol + pcol;    // set the _endcol 
    if (! rdonly)
      Open_ofile(filepath, genenum);
  }
  ~CSVWORKER(void) {
    delete _csvreader;
    if (_ofile != NULL) {
      fclose(_ofile);
      _ofile = NULL;
    }
    if (_ofile_cn != NULL) {
      fclose(_ofile_cn);
      _ofile = NULL;
    }
    if (_efile != NULL) {
      fclose(_efile);
      _efile = NULL;
    }
    if (_prefix != NULL) { free(_prefix); _prefix = NULL; }
  }

  FILE      *Open_file_w(char *f);
  void       Set_ofile(FILE *p)   { _ofile = p; }
  INT        Hasheader(void)    { return _csvreader->Hasheader(); }
  CSVTAB    *Read_master_file(void);       // return the table
  void       Filter_rule_file(_FILTER);    // create rule_code map
  void       Print_json_pathmsg(void);
  void       Print_owasp_json(void);
  void       Print_cwe_json(void);
  void       Print_p3c_json(void);
  void       Print_rule_json(BOOL printalias = FALSE);
  void       Print_struct_init(void);
  void       Print_enum_struct_init(void);
};

class DRIVER {
private:
  char      *_delimiter;
  char      *_bltrulefile;  // the normalized builtin rule file to be processed
  char      *_certrulefile ;// the normalized cert rule file to be processed
  char      *_filtcwefile;  // the ruleid to cwe mapping 
  char      *_filtowaspfile;// the ruleid to cwe mapping 
  char      *_filtCWEfile;  // the ruleid to cwe mapping 
  char      *_filtOWASPfile;// the ruleid to cwe mapping 
  char      *_gjbrulefile ; // the normalized GJB rule file to be processed
  char      *_masterfile;   // master rule file
  char      *_certinfofile; // the normalized cert info file to be processed
  char      *_owasprulefile;// the normalized owasp rule file to be processed
  char      *_cwerulefile;  // the normalized cwe rule file to be processed
  char      *_p3crulefile;  // the normalized p3c rule file to be processed
  char      *_pathmsgfile;  // the path message file to be processed
  char      *_stlfilterfile;// the file specifies what to filter from vtxt file
  CSVTAB    *_mastab;       // Hold the master table
  INT        _headerln;     // # of header lines
  INT        _gjblitno;     // the enum literal startning number
  BOOL       _json_only;    // generate json files only


  void       Print_option_guide(char *arg) {
    printf("Unrecognized Option: \"%s\"\n", arg);
    printf("Usage: ./csvreader -b blt.csv -c cert.csv -d \"delimiter\" -h # -p pathmsg.csv -m master.csv -o owasp.csv -w cwe.csv -e p3c.csv -g GJB5369.csv 500\n");
  }

  DRIVER(const DRIVER&);              // REQUIRED UNDEFINED UNWANTED methods
  DRIVER& operator = (const DRIVER&); // REQUIRED UNDEFINED UNWANTED methods

public:
  DRIVER(void): _delimiter((char*)","), _bltrulefile(NULL), _certrulefile(NULL),
                _filtcwefile(NULL), _filtowaspfile(NULL),
                _filtCWEfile(NULL), _filtOWASPfile(NULL),
                _gjbrulefile(NULL),
                _masterfile(NULL), _certinfofile(NULL),
                _owasprulefile(NULL), _cwerulefile(NULL), _p3crulefile(NULL),
                _pathmsgfile(NULL), 
                _mastab(NULL), _headerln(0), _gjblitno(0), _json_only(0)  { }
  ~DRIVER(void) { if (_mastab != NULL) delete _mastab; }

  INT        Process_option(INT argc, char **argv) {
    for (INT i = 1; i < argc; i++) {

      if (argv[i][0] == '-') {
        switch (argv[i][1]) {
        case 'b':
          _bltrulefile = argv[i+1];
          ++i;
          break;
        case 'c':
          _certrulefile = argv[i+1];
          ++i;
          break;
        case 'C':
          _certinfofile = argv[i+1];
          ++i;
          break;
        case 'd':
          _delimiter = argv[i+1];
          ++i;
          break;
        case 'e':
          _p3crulefile = argv[i+1];
          ++i;
          break;  
        case 'f':
          // -filt option
          if (argv[i][2] == 'i' && argv[i][3] == 'l' && argv[i][4] == 't') {
            switch (argv[i][5]) {
            case 'c':
              _filtcwefile = argv[i+1];  // the output file name
              break;
            case 'o':
              _filtowaspfile = argv[i+1];
              break;
            case 'C':
              _filtCWEfile = argv[i+1];  // the output file name
              break;
            case 'O':
              _filtOWASPfile = argv[i+1];
              break;
            case 's':
              _stlfilterfile = argv[i+1];
              break;
            }
          }
          ++i;
          break;  
        case 'g':
          _gjbrulefile = argv[i+1];
          ++i;
          _gjblitno = atoi(argv[i+1]);
          ++i;
          break;
        case 'h':
          _headerln = atoi(argv[i+1]);
          ++i;
          break;
        case 'j':
          _json_only = TRUE;
          break;
        case 'm':
          _masterfile = argv[i+1];
          ++i;
          break;
        case 'o':
          _owasprulefile = argv[i+1];
          ++i;
          break;
        case 'p':
          _pathmsgfile = argv[i+1];
          ++i;
          break;
        case 'w':
          _cwerulefile = argv[i+1];
          ++i;
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

  void Process_norm_builtin_rule_file(void) {
    if (_bltrulefile == NULL)
      return;
    if (! _json_only) {
      CSVWORKER worker(_bltrulefile, _delimiter, _headerln, 0, 8, NO_UTF8, GENENUM, FALSE, 0);
      worker.Print_enum_struct_init();
    }
    {
      CSVWORKER worker1(_bltrulefile, _delimiter, _headerln, 0, 15, NO_UTF8, GENRULEMAP, FALSE, 0);
      worker1.Print_rule_json(TRUE);
    }
    if (_filtcwefile != NULL) {
      // create filterd csv file for rule_code / cwe filter
      CSVWORKER worker2(_bltrulefile, _delimiter, _headerln, 0, 22, UTF8, GENPMJSON, TRUE, 0);
      worker2.Set_ofile(worker2.Open_file_w(_filtcwefile));
      worker2.Filter_rule_file(FILT_CWE);
    }
    if (_filtowaspfile != NULL) {
      // create filterd csv file for rule_code / owasp filter
      CSVWORKER worker3(_bltrulefile, _delimiter, _headerln, 0, 22, UTF8, GENPMJSON, TRUE, 0);
      worker3.Set_ofile(worker3.Open_file_w(_filtowaspfile));
      worker3.Filter_rule_file(FILT_OWASP);
    }
  }

  void Process_norm_cert_rule_file(void) {
    if (_certrulefile == NULL)
      return;
    if (! _json_only) {
      CSVWORKER worker(_certrulefile, _delimiter, _headerln, 0, 8, NO_UTF8, GENENUM, FALSE, 0);
      worker.Print_enum_struct_init();
    }
    {
      CSVWORKER worker1(_certrulefile, _delimiter, _headerln, 0, 15, NO_UTF8, GENRULEMAP, FALSE, 0);
      worker1.Print_rule_json();
    } 
    if (_filtCWEfile != NULL) {
      // create filterd csv file for rule_code / cwe filter
      CSVWORKER worker2(_certrulefile, _delimiter, _headerln, 0, 22, UTF8, GENPMJSON1, TRUE, 0);
      worker2.Set_ofile(worker2.Open_file_w(_filtCWEfile));
      worker2.Filter_rule_file(FILT_CWE);
    }
    if (_filtOWASPfile != NULL) {
      // create filterd csv file for rule_code / owasp filter
      CSVWORKER worker3(_certrulefile, _delimiter, _headerln, 0, 22, UTF8, GENPMJSON1, TRUE, 0);
      worker3.Set_ofile(worker3.Open_file_w(_filtOWASPfile));
      worker3.Filter_rule_file(FILT_OWASP);
    }
 }
 
  void Process_norm_gjb_rule_file(void) {
    if (_gjbrulefile == NULL)
      return;
    if (! _json_only) {  
      CSVWORKER worker(_gjbrulefile, _delimiter, _headerln, 0, 8, NO_UTF8, GENENUM, FALSE, _gjblitno);
      worker.Print_enum_struct_init();
    }
    {
      CSVWORKER worker1(_gjbrulefile, _delimiter, _headerln, 0, 15, NO_UTF8, GENRULEMAP, FALSE, _gjblitno);
      worker1.Print_rule_json();
    }
  }

  void Process_cert_info_file(void) {
    if (_certinfofile == NULL)
      return;
    {
      CSVWORKER worker(_certinfofile, _delimiter, _headerln, 0, 3, UTF8, GENOWASP, FALSE, 0);
      worker.Print_owasp_json();
    }
  }

  void Process_owasp_rule_file(void) {
    if (_owasprulefile == NULL)
      return;
    {
      CSVWORKER worker(_owasprulefile, _delimiter, _headerln, 0, 3, UTF8, GENOWASP, FALSE, 0);
      worker.Print_owasp_json();
    }
  }

  void Process_cwe_rule_file(void) {
    if (_cwerulefile == NULL)
      return;
    {
      CSVWORKER worker(_cwerulefile, _delimiter, _headerln, 0, 3, UTF8, GENCWE, FALSE, 0);
      worker.Print_owasp_json();
    }
  }

  void Process_p3c_rule_file(void) {
    if (_p3crulefile == NULL)
      return;
    {
      CSVWORKER worker(_p3crulefile, _delimiter, _headerln, 0, 3, UTF8, GENP3C, FALSE, 0);
      worker.Print_owasp_json();
    }
  }

  void Process_path_message_file(void) {
    if (_pathmsgfile == NULL)
      return;
    if (! _json_only) {
      // This pass will filter out UTF8 characters
      CSVWORKER worker(_pathmsgfile, _delimiter, _headerln, 0, 2, NO_UTF8, NOGENENUM, FALSE, 0);
      worker.Print_struct_init();
    }
    {
      CSVWORKER worker1(_pathmsgfile, _delimiter, _headerln, 1, 3, UTF8, GENPMJSON, FALSE, 0);
      worker1.Print_json_pathmsg();
    }
 }

  void Read_master_file(void) {
    if (_masterfile == NULL)
      return;
    // the following line can create in memory 2-D table for the .csv file
    // CSVWORKER worker(_masterfile, _delimiter, _headerln, 0, 22, UTF8, NOGENENUM, TRUE);
    {
      CSVWORKER worker(_masterfile, _delimiter, _headerln, 0, 22, UTF8, GENPMJSON, FALSE, 0);
      _mastab = worker.Read_master_file();
    }
    {
      CSVWORKER worker1(_masterfile, _delimiter, _headerln, 0, 0, NO_UTF8, GENVERSION, FALSE, 0);
      _mastab = worker1.Read_master_file();
    }
  }
};
#endif // CSVREADER
