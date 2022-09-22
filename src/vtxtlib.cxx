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
// Module: vtxtlib.cxx
//
// Library functions that are shared aross v2csf and vtxt_diff
//
// =============================================================================


#include <assert.h>
#include "commondefs.h"
#include "vtxtlib.h"


// =============================================================================
// Read ONE path node, defined in vtxtlib.h/class PATH_NODE 
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
  
  char c;   // either ",", "." or "]" expected
  i = fscanf(f, "%c", &c);

  if (c == PN_SEPARATOR) 
    return 1;


  if (c == ']')
    return 0;

  return i;
  
}
