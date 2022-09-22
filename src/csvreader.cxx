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

#include <ctype.h>
#include <vector>
#include "csvreader.h"
#include <assert.h>

using namespace std;

// =============================================================================
//
// CSVREADER::Read_row/Read_header - Two not very useful interface at this point
//
// =============================================================================
CSVROW *
CSVREADER::Read_row(void) {
  if (Hasheader() && Header() == NULL) {
    Set_header(Get_row());
  }
  return Get_row();
}

CSVROW *
CSVREADER::Read_header(void) {
  if (Hasheader() && Header() != NULL) {
    Set_errmsg((char *) "Cannot process header twice");
    return NULL;
  }

  if (Header() == NULL) {
    Set_header(Get_row());
  }
  return Header();
}

// =============================================================================
//
// Verify - To check some basic precondition for this module to operate normally
//
// =============================================================================
BOOL
CSVREADER::Verify(void) {
  if (Filepath() == NULL && (! Fromstring())) {
    Set_errmsg((char *)"Please supply CSV file path");
    return FALSE;
  }
  if (Csvstring() && Fromstring()) {
    Set_errmsg((char *)"Please supply CSV string");
    return FALSE;
  }
  if (Delimiter() == '\0') {
    Set_errmsg((char *)"Please supply supported separator");
    return FALSE;
  }
  if (! Fromstring()) {
    if (Filep() == NULL) {
      Set_filep(fopen(Filepath(), "r"));
      if (Filep() == NULL) {
        INT errorNum = errno;
        const char *errStr = strerror(errorNum);
        char *errMsg = (char*)malloc(1024 + strlen(errStr));
        strcpy(errMsg, "");
        sprintf(errMsg, "Failure while opening CSV file: %s : %s", Filepath(), errStr);
        Set_errmsg((char *)errMsg);
        free(errMsg);
        return FALSE;
      }
    }
  }
  return TRUE;
}

// =============================================================================
//
// Get_row - returns the pointer list to the row
//           returns NULL when error occurs
//
// =============================================================================
CSVROW *
CSVREADER::Get_row(void) {
  if (! Verify()) {
    printf("%s\n", Errmsg());
    return NULL;
  }

  CSVROW  *csvrow = new CSVROW(INIT_ROW_WIDTH, TRUE);  // buffer 4 a row
  CHARBUF *curfld = new CHARBUF(INIT_FIELD_LEN, FALSE);// buffer 4 string from csv

  INT  inside_complex_field = 0;
  INT  seriesOfQuotesLength = 0;
  BOOL lastchar_quote = 0;
  BOOL is_eof = FALSE;

  // Tokenize a line, copy char into curfld buffer
  while (1) {
    char cur_ch;
    if (Fromstring()) {
      cur_ch = Csvstring()[Csvstringcursor()];
      Inc_csvstringcursor();
    } else {
      cur_ch = fgetc(Filep());
    }
    BOOL eof_indicator = Fromstring()? (cur_ch == '\0') : feof(Filep());
    if (eof_indicator) {
      if (curfld->Is_empty() && csvrow->Is_empty()) {
        Set_errmsg((char *)"EOF reached");
        delete curfld;
        delete csvrow;
        return NULL;
      }
      cur_ch = '\n';
      is_eof = TRUE;
    }
    if (! isascii(cur_ch) && ! Has_utf8()) continue;
    if (cur_ch == '\r')    continue;
    if (curfld->Is_empty() && ! lastchar_quote) {
      if (cur_ch == '\"') {
        inside_complex_field = 1;
        lastchar_quote = 1;
        continue;
      }
    } else if (cur_ch == '\"') {
      seriesOfQuotesLength++;
      inside_complex_field = (seriesOfQuotesLength % 2 == 0);
      if (inside_complex_field) {
        curfld->Back();
      }
    } else {
      seriesOfQuotesLength = 0;
    }

    if (is_eof || ((Is_delimit(cur_ch) || cur_ch == '\n') && ! inside_complex_field) ){
      if (lastchar_quote) curfld->Back();
      curfld->Assign_into('\0');
      char *content = Clone_string(curfld->Begin());
      if (content != curfld->Begin())
        csvrow->Assign_into(content);

      delete(curfld);
      if (cur_ch == '\n') {   // reach EOL, send the row back
        Set_rownum();
        return csvrow;
      }
      curfld = new CHARBUF(INIT_FIELD_LEN, FALSE);
      inside_complex_field = 0;
    } else {
      curfld->Assign_into(cur_ch);
    }
    lastchar_quote = (cur_ch == '\"') ? TRUE : FALSE;
  } // end of the tokenizer
}

// =============================================================================
//
// CSVWORKER::Get_prefix Returns the prefix of a filepath and the pointer to
//                       its end.
//                       The caller is responsible for free the pointer returned
//
// =============================================================================
char *
CSVWORKER::Get_prefix(char *filepath, char**end)
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

// =============================================================================
//
// CSVWORKER::Get_last_token
//            Search backward till the first ' ' and return ptr to next char.
//
// =============================================================================
char *
CSVWORKER::Get_last_token(char *buf)
{
  char *end;
  for (end = buf + strlen(buf); end != buf; --end) {
    if (*end == ' ') {
      *end = '\0';
      return end+1;
    }
  }
  return buf;
}
#if 0
char *
CSVWORKER::Get_real_end(char *buf)
{
  char *end;
  for (end = buf + strlen(buf); end != buf; --end) {
    if (*end == ' ') {
      *end = '\0';
    }
  }
  return end+1;
}
#endif
// =============================================================================
//
// CSVWORKER::Open_ofile Open the file for writing, using the filepath from the
//                       input with '.inc' suffix.
//
// =============================================================================

FILE *
CSVWORKER::Open_file_w(char *fname)
{
  FILE *retv = (FILE *)fopen(fname, "w");
  if (retv == NULL) {
    INT errorNum = errno;
    const char *errStr = strerror(errorNum);
    char *errMsg = (char*)malloc(1024 + strlen(errStr));
    strcpy(errMsg, "");
    sprintf(errMsg, "Failure while opening INC file: %s : %s", fname, errStr);
    free(errMsg);
  }
  return retv;
}

void
CSVWORKER::Open_ofile(char *filepath, _FLAGS ofiletype)
{
  if (filepath == NULL)
    return;
  char *cur;
  char *ofilepath = Get_prefix(filepath, &cur);
  if (ofilepath == NULL || cur == ofilepath) {
    if (ofilepath) free(ofilepath);
    return;
  }

  if (ofiletype == GENVERSION) {
    sprintf(cur, "%s", "ver");
    cur = cur+3;
  }
  // open Ofile() for struct init or JSON in EN
  if (Format_json()) {
    sprintf(cur, "%s", ".json"); // replace original suffix with new suffix
  }
  else {
    sprintf(cur, "%s", ".inc"); // replace original suffix with new suffix
  }
  Set_ofile(Open_file_w(ofilepath));

  if (ofiletype == GENENUM) {
    // open Efile() for enum
    sprintf(cur, "%s", "_enum.inc"); // replace original suffix with new suffix
    Set_efile(Open_file_w(ofilepath));
  } else if (ofiletype == GENPMJSON ||
             ofiletype == GENOWASP ||
             ofiletype == GENCWE ||
             ofiletype == GENP3C) {
    // open Ofile_cn() for JSON in CN
    sprintf(cur, "%s", "_cn.json"); // replace original suffix with new suffix
    Set_ofile_cn(Open_file_w(ofilepath));
  }
  if (ofiletype != GENENUM) {
    free(ofilepath);
    return;
  }
  else {
    // preserve the prefix in CSVWORKER for prefix in enum values
    *cur = '\0';
    Toupper(ofilepath);
    Set_prefix(ofilepath);
  }
}

const char* master_fmt[] = {"\"master_id\":%s", "\"category\":\"%s\"", "\"language\":\"%s\"", "", "", "\"code\":\"%s\"", "\"name\":\"%s\"", "\"name\":\"%s\"", "\"desc\":\"%s\"", "\"desc\":\"%s\"", "\"detail\":\"%s\"", "\"detail\":\"%s\"", "\"msg_templ\":\"%s\"", "\"msg_templ\":\"%s\"","\"severity\":\"%s\"", "\"likelihood\":\"%s\"", "\"cost\":\"%s\"", "", "", "  \"owasp\":\"%s\"", "  \"cwe\":\"%s\"", "  \"p3c-sec\":\"%s\"", ""};
//                           A B C D E F G H I J K L M N O P Q R S T U V W
//const BOOL  master_en_p[] = {1,1,1,0,0,1,1,0,1,0,0,0,1,0,1,1,1,0,0,4,1,5,0};
//const BOOL  master_cn_p[] = {1,1,1,0,0,1,0,1,0,1,0,0,0,1,1,1,1,0,0,4,1,5,0};
const BOOL  master_en_p[] = {1,1,1,0,0,1,1,0,1,0,0,0,1,0,1,1,1,0,0,0,0,0,0};
const BOOL  master_cn_p[] = {1,1,1,0,0,1,0,1,0,1,0,0,0,1,1,1,1,0,0,0,0,0,0};
const char* owaspjson_fmt[] = {"\"%s\" : {", "\"name\":\"%s\"", "\"name\":\"%s\"", "\"url\":\"%s\""};
const char* cwejson_fmt[] = {"\"cwe_id\" : \"%s\"", "\"name\":\"%s\"", "\"name\":\"%s\"", "\"url\":\"%s\""};
const char* p3cjson_fmt[] = {"\"p3c_id\" : \"%s\"", "\"name\":\"%s\"", "\"name\":\"%s\"", "\"url\":\"%s\""};
//                              A B C D E F G H I J K L M N O P Q R S T U V W
const BOOL  owaspjson_en_p[] = {2,3,0,1};
const BOOL  owaspjson_cn_p[] = {2,0,3,1};
//                            A B C D E F G H I J K L M N O P Q R S T U V W
const BOOL  cwejson_en_p[] = {1,1,0,1};
const BOOL  cwejson_cn_p[] = {1,0,1,1};
const char* pathmsg_fmt[] = {"\"%s\"", "%s", "\"EN\": \"%s\"", "\"CN\": \"%s\"" };
const char* pathmsgj_fmt[] = {"\"%s\"", "\"id\":%s", "\"msg\": \"%s\"", "\"msg\": \"%s\"" };
const BOOL  pathmsgj_en_p[] = {0, 1, 1, 0 };
const BOOL  pathmsgj_cn_p[] = {0, 1, 0, 1 };
const char* rule_fmt[] = { "%s", "\"%s\"", "\"%s\"", "S%s", "L%s", "C%s", "", "\"%s\"" };
//                      A B C D E F G H I J K L M N O P Q R S T U V W
const BOOL  rule_p[] = {1,1,1,1,1,1,0,1};
const char* rulejson_fmt[] = {"", "\"core_string\":\"%s\"", "\"csv_string\":\"%s\"", "\"severity\":\"%s\"", "\"likelihood\":\"%s\"", "\"cost\":\"%s\"", "", "", "", "\"alias\" : {\n    \"cert\" : \"%s\"\n}","  \"owasp\":\"%s\"", "  \"cwe\":\"%s\"", "  \"p3c-sec\":\"%s\"", "\"master_id\":%s","\"nyi\":\"%s\"", "\"id\":%s"};
//                          A B C D E F G H I J K L M N O P Q R S T U V W
const BOOL  rulejson_p[] = {0,1,1,1,1,1,0,0,0,0,4,1,5,1,1,1};
      //                          A B C D E F G H I J K L M N O P Q R S T U V W
const BOOL  rulewaliasjson_p[] = {0,1,1,1,1,1,0,0,0,1,4,1,5,1,0,1};
//                            A B C D E F G H I J K L M N O P Q R S T U V W
const BOOL  filter_cwe_p[] = {0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0};
//                              A B C D E F G H I J K L M N O P Q R S T U V W
const BOOL  filter_owasp_p[] = {0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0};

// =============================================================================
//
// Print_row_filter returns TRUE if we want to print this line, otherwise FALSE
//
// =============================================================================
BOOL
CSVWORKER::To_print_row(void)
{
  if (! Format_json())
    return TRUE;
  // Ruleinfo service wants to skip reserved rule entries hence this filter
  char **iter = Row()->Begin();
  char  *critical_field = NULL;
  char  *sanity_check = NULL;
  switch (Ofiletype()) {
  case GENPMJSON:
    critical_field = iter[2];
    break;
  case GENPMJSON1:
  {
    critical_field = iter[2];
    if (critical_field != NULL && strlen(critical_field) != 0) {
      critical_field = iter['O'-'A']; // additional filter Not Yet Implemented
      return ((critical_field)? (strlen(critical_field) == 0) || (critical_field[0] != 'N') : TRUE);
    }
  }
  break;
  case GENRULEMAP:
  {
    critical_field = iter['N'-'A']; // column 13
    if (critical_field != NULL && strlen(critical_field) == 0) {
      // Column N is master_id. If it does not exist, neither should column D
      sanity_check = iter['D'-'A'];
      if (sanity_check != NULL && strlen(sanity_check) != 0) {
        printf("Normalized Rule Table Consistency Violation: Row-%d Col-N is not set while Col-D is set\n", Csvreader()->Get_rownum());
      }
    }
  }
  break;
  case GENOWASP:
  case GENCWE:
  case GENP3C:
    critical_field = iter[1];
    break;
  } // end of switch
  return ((critical_field)? (strlen(critical_field) != 0) : TRUE);
}

// =============================================================================
//
// Toupper: inplace convert the whole string into upper case.
//
// =============================================================================
char*
CSVWORKER::Toupper(char *buf) {
  char *iter = buf;
  if (! isascii(*buf) ) return buf; // only convert when it's ansi ascii
  for (char *end = buf+strlen(buf); iter != end; ++iter) {
    *iter = toupper(*iter);
  }
  return buf;
}

void
CSVWORKER::Print_enumlit(char *lit, const char *fmt)
{
  if (lit == NULL) {
    // error, to print
    return;
  }
  INT litno = Assign_lit();
  if (strcmp(lit, "reserved") == 0) {
    INT rsvdlitno = Assign_rsvdlit();
    if (Efile()) fprintf(Efile(), "%s_RSVD%d = %d,\n", Prefix(), rsvdlitno, litno); 
    fprintf(Ofile(), "%s_RSVD%d", Prefix(), rsvdlitno); 
  }
  else {
    if (Efile()) fprintf(Efile(), "%s = %d,\n", lit, litno); 
    fprintf(Ofile(), fmt, lit);
  }
}

// =============================================================================
//
// CSVWORKER::Print_owasp Generate owasp table object 
//
// =============================================================================
void
CSVWORKER::Print_nested_object(const char **fmt, const BOOL *en_ctrl, const BOOL *cn_ctrl, INT ctrl)
{
  // Stream through CSV file row by row and print
  // fprintf(Ofile(), "{ \n");
  char **iter;
  INT    printcnt;
  BOOL   first_en_row = TRUE;
  BOOL   first_cn_row = TRUE;

  // print the surrounding {} for the object
  if (! Format_json())
    return;
  fprintf(Ofile(), "{\n");
  if (Ofile_cn()) fprintf(Ofile_cn(), "{\n");

  while (Set_row(Csvreader()->Read_row())) {
    if (!To_print_row())
      continue;

    printcnt = 0;
    iter = Row()->Begin();
    BOOL first_en_entry = TRUE;
    BOOL first_cn_entry = TRUE;

    for (;printcnt < ctrl && iter != Row()->Last(); ++printcnt, ++iter) {
      if (*iter) {
        INT pr_en = en_ctrl[printcnt];
        INT pr_cn = cn_ctrl[printcnt];
        if (pr_en != 0) {
          if (! first_en_entry) {
            if (pr_en == 3)
              fprintf(Ofile(), "\n ");
            else
              fprintf(Ofile(), ",\n ");
            fprintf(Ofile(), fmt[printcnt], (strlen(*iter) != 0)? *iter : " ");
          }
          else {
            if (pr_en == 2) { // make it the key
              if (! first_en_row) {
                fprintf(Ofile(), ",\n");
              }
              fprintf(Ofile(), fmt[printcnt], (strlen(*iter) != 0)? *iter : " ");
            }
            else {
              fprintf(Ofile(), fmt[printcnt], (strlen(*iter) != 0)? *iter : " ");
              first_en_entry=FALSE;
              first_en_row = FALSE;
            }
          }
        } // pr_en
        if (pr_cn!=0 && Ofile_cn()) { // May not need to print CN version
          if (! first_cn_entry) {
            if (pr_cn == 3)
              fprintf(Ofile_cn(), "\n ");
            else
              fprintf(Ofile_cn(), ",\n ");
            fprintf(Ofile_cn(), fmt[printcnt], (strlen(*iter) != 0)? *iter : " ");
          }
          else {
            if (pr_cn == 2) { // make it the key
              if (! first_cn_row) {
                fprintf(Ofile_cn(), ",\n");
              }
              fprintf(Ofile_cn(), fmt[printcnt], (strlen(*iter) != 0)? *iter : " ");
            }
            else {
              fprintf(Ofile_cn(), fmt[printcnt], (strlen(*iter) != 0)? *iter : " ");
              first_cn_entry=FALSE;
              first_cn_row = FALSE;
            }
          }
        } // if need to print cn
      } // if there is content in the column
    } // for each column
    if (! first_en_entry) {
      fprintf(Ofile(), "}"); if (Ofile_cn())  fprintf(Ofile_cn(), "}");
    }
    delete(Row());
  }
  if (Format_json()) {
    fprintf(Ofile(), "\n}\n");
    if (Ofile_cn()) fprintf(Ofile_cn(), "\n}\n");
  }
}


// =============================================================================
//
// CSVWORKER::Print_rows Generate init statment and enum according to arg list.
//
// =============================================================================
void
CSVWORKER::Print_rows(const char **fmt, const BOOL *en_ctrl, const BOOL *cn_ctrl, INT ctrl)
{
  // Stream through CSV file row by row and print
  // fprintf(Ofile(), "{ \n");
  char **iter;
  INT    printcnt;
  BOOL   first_row = TRUE;
  BOOL   first_en_row = TRUE;
  BOOL   first_cn_row = TRUE;

  // print the surrounding [] if for JSON
  if (Format_json()) {
    fprintf(Ofile(), "[\n");
    if (Ofile_cn()) fprintf(Ofile_cn(), "[\n");
  }
  while (Set_row(Csvreader()->Read_row())) {
    if (!To_print_row())
      continue;
    BOOL first_entry = TRUE;
    if (en_ctrl == NULL || cn_ctrl == NULL) {
      // Print the head of the struct init statement
      fprintf(Ofile(), "  { ");
 
      // Loop to print column by column in the row
      printcnt = 0;
      iter = Row()->Begin();
      if (printcnt >= Begincol() && printcnt < Endcol()) {
        Print_enumlit(*iter, fmt[printcnt]); // hard code enum print, only 1st col
        ++printcnt; ++iter;
        first_entry = FALSE;
      }
      while (printcnt < Endcol()) {
        if (printcnt >= Begincol()) {
          if (en_ctrl == NULL || en_ctrl[printcnt]) {
            if (! first_entry) fprintf(Ofile(), ", ");
            first_entry = FALSE;
            if (*iter) {
              if (strlen(*iter) != 0 || printcnt < 3 || printcnt > 5)
                fprintf(Ofile(), fmt[printcnt], *iter);
              else if (strlen(*iter) == 0 && printcnt < 6)
                fprintf(Ofile(), fmt[printcnt], "N");
            }
            else
              fprintf(Ofile(), "\"\"");
          } // need to print this column
        }
        ++printcnt; ++iter;
      }
      fprintf(Ofile(), "}, \n");
    }
    else {
      // print JSON file
      // Print the head of the struct init statement

      printcnt = 0;
      iter = Row()->Begin();
      BOOL first_en_entry = TRUE;
      BOOL first_cn_entry = TRUE;
      INT  en_nest_level = 0;
      INT  cn_nest_level = 0;

      for (;printcnt < ctrl && iter != Row()->Last(); ++printcnt, ++iter) {
        if (*iter) {
          INT pr_en = en_ctrl[printcnt];
          INT pr_cn = cn_ctrl[printcnt];
          if ((pr_en!=0) || (pr_cn!=0)) {
            if (pr_en!=0) {
              if (! first_en_entry) { fprintf(Ofile(), ",\n "); }
              else {
                if (first_en_row)
                  fprintf(Ofile(), "{ "); 
                else
                  fprintf(Ofile(), ",\n{ "); 
                first_en_row = FALSE;
              }
              first_en_entry=FALSE;
              if (pr_en == 4) { fprintf(Ofile(), "\"standards\": {\n "); ++en_nest_level; }
              fprintf(Ofile(), fmt[printcnt], (strlen(*iter) != 0)? *iter : "");
              if (pr_en == 5) { fprintf(Ofile(), "\n }\n"); --en_nest_level; }
            }
            if (pr_cn!=0 && Ofile_cn()) { // May not need to print CN version
              if (! first_cn_entry) { fprintf(Ofile_cn(), ",\n "); }
              else {
                if (first_cn_row)
                  fprintf(Ofile_cn(), "{ ");
                else
                  fprintf(Ofile_cn(), ",\n{ "); 
                first_cn_row = FALSE;
              }
              first_cn_entry=FALSE;
              if (pr_cn == 4) { fprintf(Ofile_cn(), "\"standards\": {\n "); ++cn_nest_level; }
              fprintf(Ofile_cn(), fmt[printcnt], (strlen(*iter) != 0)? *iter : "");
              if (pr_cn == 5) { fprintf(Ofile_cn(), "\n }\n"); --cn_nest_level; }
            }
          } // if need to print
        } // if this column contains data
      } // for each column
      while (en_nest_level > 0) { fprintf(Ofile(), "\n }\n"); --en_nest_level; }
      while (cn_nest_level > 0) { fprintf(Ofile_cn(), "\n }\n"); --cn_nest_level; }
      if (! first_en_entry) {
        fprintf(Ofile(), "}"); if (Ofile_cn())  fprintf(Ofile_cn(), "}");
      }
    }
    delete(Row());
  }
  if (Format_json()) {
    fprintf(Ofile(), "\n]");
    if (Ofile_cn()) fprintf(Ofile_cn(), "\n]");
  }
  fprintf(Ofile(), "\n"); if (Ofile_cn())  fprintf(Ofile_cn(), "\n");
  if (Efile() && Prefix()) fprintf(Efile(), "MAX_%s_ENUM = %d,\n", Prefix(), Assign_lit()); 
  // Print the tail of the struct init statement
  // fprintf(Ofile(), "};\n");
}

// =============================================================================
//
// CSVWORKER::Filter_rows collect related field into a vector of pairs
//
// =============================================================================
char*
CSVWORKER::Get_varlen_str(char *buf, char dlimiter)
{
  char *next = buf;
  while (*next != dlimiter && *next != ' ' && *next !='\0')
    ++next;

  if (*next == '\0')
    return next;

  *next = '\0';
  for (++next; *next == ' '&&*next != dlimiter; ++next) ;
  return next;
}

void
CSVWORKER::Print_header(const BOOL *filter_ctrl, INT ctrl)
{
  char **iter;
  INT    cnt = 0;
  iter = Csvreader()->Header()->Begin();
  BOOL  col_once = FALSE;
  char *val1 = NULL;
  char *val2 = NULL;
  for (;cnt < ctrl && iter != Csvreader()->Header()->Last(); ++cnt, ++iter) {
    INT collect = filter_ctrl[cnt];
    if (collect != 0) {
      if (col_once == FALSE) { val1 = (*iter); col_once = TRUE; }
      else { val2 = (*iter); }
    } // if this is selected column
  } // for each column
  fprintf(Ofile(), "%s,%s\n", val2, val1);
}


typedef pair <char*, char*> STR_PAIR;
typedef vector<STR_PAIR> SP_VEC;
void
CSVWORKER::Filter_rows(const BOOL *filter_ctrl, INT ctrl)
{
  char **iter;
  INT    cnt;
  INT    idx = 0;
  SP_VEC pair_tab;

  while (Set_row(Csvreader()->Read_row())) {
    if (!To_print_row())
      continue;
    cnt = 0;
    iter = Row()->Begin();
    BOOL  col_once = FALSE;
    char *val1 = NULL;
    char *val2 = NULL;
    for (;cnt < ctrl && iter != Row()->Last(); ++cnt, ++iter) {
      INT collect = filter_ctrl[cnt];
      if (collect != 0) {
        if (col_once == FALSE) { val1 = (*iter); col_once = TRUE; }
        else { val2 = (*iter); }
      } // if this is selected column
    } // for each column

    if (strlen(val2) != 0) {
      char *cur = val2;
      char *next = val2;
      do {
        next = Get_varlen_str(next, ',');
        // printf("Filter_rows @line %d:rule_code:%s:cwe:%s\n", idx, val1, cur);
        pair_tab.push_back(make_pair(Clone_data(cur), Clone_data(val1)));
        cur = next;
      } while (*next != '\0');
    }
    delete(Row());
    ++idx;
  }
  // sort(pair_tab);
  SP_VEC::iterator iter1;
  for (idx = 0, iter1 = pair_tab.begin(); iter1 != pair_tab.end(); ++iter1, ++idx) {
    fprintf(Ofile(), "%s,%s\n", iter1->first, iter1->second);
    // printf("idx%d : cwe:%s : rule_code:%s\n", idx, iter1->first, iter1->second);
    free(iter1->first); free(iter1->second);
  }
}


// =============================================================================
//
// CSVWORKER::Filter_rule_file
//           It reads .csv file line by line and collect selected column
//
// =============================================================================
void
CSVWORKER::Filter_rule_file(_FILTER filt)
{
  if (Hasheader()) { // skip the header line for now
    CSVROW *header = Csvreader()->Read_header();
    if (header == NULL)
      return;
  }
  switch (filt) {
  case FILT_CWE:
    Print_header(filter_cwe_p, sizeof(filter_cwe_p)/sizeof(INT));
    Filter_rows(filter_cwe_p, sizeof(filter_cwe_p)/sizeof(INT));
    break;
  case FILT_OWASP:
    Print_header(filter_owasp_p, sizeof(filter_owasp_p)/sizeof(INT));
    Filter_rows(filter_owasp_p, sizeof(filter_owasp_p)/sizeof(INT));
  }
}




// =============================================================================
//
// CSVWORKER::Read_master_file
//           It reads .csv file line by line and print out the pathmsg text
//
// =============================================================================
CSVTAB*
CSVWORKER::Read_master_file(void)
{
#if 0
  CSVTAB *csvtab = new CSVTAB(INIT_ROW_WIDTH, TRUE);  // buffer 4 a row
  CSVROW *currow;

  if (csvtab == NULL)
    return csvtab;

  Set_tab(csvtab);
  int lineno = 0;
  while (currow = Csvreader()->Get_row()) {
    // printf("read line #%d\n", ++lineno);
    csvtab->Assign_into(currow);
  }
  return csvtab;
#endif
  if (Hasheader()) {
    CSVROW *header = Csvreader()->Read_header();
    if (header == NULL)
      return NULL;
    if (Ofiletype() == GENVERSION) {
      // generate the version info file
      fprintf(Ofile(), "{ \"xcalscan_rule_version\": \"%s\",\n\"copyright\": \"(C) 2021 Xcalibyte Inc.\" }\n", *(header->Begin()));
      return NULL;
    }
  }
  Print_rows(master_fmt, master_en_p, master_cn_p, sizeof(master_en_p)/sizeof(INT));
  return NULL;
}

// =============================================================================
//
// CSVWORKER::Print_owasp_json
//           It reads .csv file line by line and print out the owasp rule info
//
// =============================================================================
void
CSVWORKER::Print_owasp_json(void)
{
  if (Hasheader()) {
    CSVROW *header = Csvreader()->Read_header();
    if (header == NULL)
      return;
  }
  Print_nested_object(owaspjson_fmt, owaspjson_en_p, owaspjson_cn_p, sizeof(owaspjson_en_p)/sizeof(INT));
}


// =============================================================================
//
// CSVWORKER::Print_cwe_json
//           It reads .csv file line by line and print out the owasp rule info
//
// =============================================================================
void
CSVWORKER::Print_cwe_json(void)
{
  if (Hasheader()) {
    CSVROW *header = Csvreader()->Read_header();
    if (header == NULL)
      return;
  }
  Print_rows(cwejson_fmt, cwejson_en_p, cwejson_cn_p, sizeof(cwejson_en_p)/sizeof(INT));
}


// =============================================================================
//
// CSVWORKER::Print_p3c_json
//           It reads .csv file line by line and print out the owasp rule info
//
// =============================================================================
void
CSVWORKER::Print_p3c_json(void)
{
  if (Hasheader()) {
    CSVROW *header = Csvreader()->Read_header();
    if (header == NULL)
      return;
  }
  Print_rows(p3cjson_fmt, cwejson_en_p, cwejson_cn_p, sizeof(cwejson_en_p)/sizeof(INT));
}


// =============================================================================
//
// CSVWORKER::Print_rule_json
//           It reads .csv file line by line and print out the rulemap
//
// =============================================================================
void
CSVWORKER::Print_rule_json(BOOL printalias)
{
  if (Hasheader()) {
    CSVROW *header = Csvreader()->Read_header();
    if (header == NULL)
      return;
  }
  if (printalias)
    Print_rows(rulejson_fmt, rulewaliasjson_p, rulewaliasjson_p, sizeof(rulewaliasjson_p)/sizeof(INT));
  else
    Print_rows(rulejson_fmt, rulejson_p, rulejson_p, sizeof(rulejson_p)/sizeof(INT));
}

// =============================================================================
//
// CSVWORKER::Print_json_pathmsg
//           It reads .csv file line by line and print out the pathmsg text
//
// =============================================================================
void
CSVWORKER::Print_json_pathmsg(void)
{
  if (Hasheader()) {
    CSVROW *header = Csvreader()->Read_header();
    if (header == NULL)
      return;
  }
  Print_rows(pathmsgj_fmt, pathmsgj_en_p, pathmsgj_cn_p, sizeof(pathmsgj_en_p)/sizeof(INT));
}

// =============================================================================
//
// CSVWORKER::Print_struct_init
//           It reads .csv file line by line and print out the service function
//           for RBC_BASE::Generate_fsm_msg_id
//
//           for more info, search for #include "pathmsg.inc in opt_vsa_rbc.cxx
//
// =============================================================================
void
CSVWORKER::Print_struct_init(void)
{
  char **iter;
  int    printcnt; 
  char  *prefix = NULL;
  char  *has_prefix = NULL;
  char  *key = NULL;
  char  *key_ = NULL;
  char  *value = NULL;
  char  *value_ = NULL;

  // print the header section of the struct init statement
  if (Hasheader()) {
    CSVROW *header = Csvreader()->Read_header();

    if (header == NULL) {
      printf("%s\n", Csvreader()->Errmsg());
      return;
    }
    fprintf(Ofile(), "typedef struct {\n");
    printcnt = 0;
    for (iter = header->Begin(); iter != header->Last(); iter++) {
      if (printcnt < Printcol()) {
        fprintf(Ofile(), "  %s;\n", *iter);
        if (printcnt == 0) {
          key = Csvreader()->Clone_string(*iter);
          key_ = Get_last_token(key);
        } else if (printcnt == 1) {
          value = Csvreader()->Clone_string(*iter);
          value_ = Get_last_token(value);
        }
      }
      ++printcnt;
    }
    char *end;
    prefix = Get_prefix(Csvreader()->Filepath(), &end);
    prefix = (has_prefix = prefix)? prefix : (char *)"aaa";
    fprintf(Ofile(), "} __%s_entry;\n__%s_entry __%s[] = {\n", prefix, prefix, prefix);
  }

  Print_rows(pathmsg_fmt, NULL, NULL, 0);

  if (Hasheader()) {
    // Print the tail of the struct init statement
    fprintf(Ofile(), "};\n");

    // Generate code to count the size of the variable length array
    fprintf(Ofile(),
            "int __%s_size = sizeof(__%s) / sizeof(__%s_entry);\n",
            prefix, prefix, prefix);
    // Followed by two functions to convert from key to value or value to key
    fprintf(Ofile(),
            "%s __%s_k2v(%s key) {\n  for (int i=0; i < __%s_size; ++i)\n    if (strcmp(__%s[i].%s, key) == 0)\n      return __%s[i].%s;\n  return 0;\n}\n",
            value, prefix, key, prefix, prefix, key_, prefix, value_);

    fprintf(Ofile(),
            "%s __%s_v2k(%s value) {\n  for (int i=0; i < __%s_size; ++i)\n    if (__%s[i].%s == value)\n      return __%s[i].%s;\n  return 0;\n}\n",
            key, prefix, value, prefix, prefix, value_, prefix, key_);

    if (has_prefix) free(has_prefix);
    if (key) free(key);
    if (value) free(value);
  }
}

// =============================================================================
//
// CSVWORKER::Print_enum_struct_init - generate the body of the enum type and
//            the body of the table defined in v2csv/include/rule_desc_*.h
//
// =============================================================================
void
CSVWORKER::Print_enum_struct_init(void)
{
  if (Hasheader()) {
    CSVROW *header = Csvreader()->Read_header();

    if (header == NULL) {
      return;
    }
    // skip the header now
  }
  Print_rows(rule_fmt, rule_p, NULL, 0);
}


INT main(int argc, char **argv) {
  DRIVER driver;
  if (driver.Process_option(argc, argv) != 0)
    return 1;

  driver.Read_master_file();
  driver.Process_norm_builtin_rule_file();
  driver.Process_norm_cert_rule_file();
  driver.Process_norm_gjb_rule_file();
  driver.Process_cert_info_file();
  driver.Process_owasp_rule_file();
  driver.Process_cwe_rule_file();
  driver.Process_p3c_rule_file();
  driver.Process_path_message_file();
  return 0;
}
