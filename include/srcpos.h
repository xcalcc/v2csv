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
// Module: srcpos.h
//
// Description:
//        SRCPOS is defined as a 64bit unsigned integer. This is the declaration 
//        visible to most files. 
//
// =============================================================================
// =============================================================================
//

#ifndef SRCPOS_H
#define SRCPOS_H

#include <vector>
#include "commondefs.h"

using namespace std;

typedef mUINT64 SRCPOS;

struct SRCPOS_STRUCT {
  mUINT16 _filenum;          // file_id defined in filepath.h
  mUINT16 _column : 12;      // Max 4096 characters per line
  mUINT16 _stmt_begin : 1;
  mUINT16 _bb_begin : 1;
  mUINT16 _unused : 2;
  mINT32  _linenum;
};
#define SRC_POS_SIZE  2      // 2 * sizeof(mINT32)

typedef union source_position {
  SRCPOS _srcpos;
  struct SRCPOS_STRUCT _t;
  mINT32 _fillers[SRC_POS_SIZE];
} USRCPOS;

#define CHECK_SIZE_CONSISTENCY(s) check_assertion(sizeof(s) == (SRC_POS_SIZE*sizeof(INT32)))
#define USRCPOS_clear(s)     ((s)._fillers[0] = 0,(s)._fillers[1] = 0)

#define SRCPOS_clear(s)	     ((s) = 0)
#define SRCPOS_filenum(s)    (((USRCPOS *)&(s))->_t._filenum)
#define SRCPOS_column(s)     (((USRCPOS *)&(s))->_t._column)
#define SRCPOS_stmt_begin(s) (((USRCPOS *)&(s))->_t._stmt_begin)
#define SRCPOS_bb_begin(s)   (((USRCPOS *)&(s))->_t._bb_begin)
#define SRCPOS_linenum(s)    (((USRCPOS *)&(s))->_t._linenum)

typedef vector<SRCPOS> SRCPOS_VEC;

#endif // SRCPOS_H
