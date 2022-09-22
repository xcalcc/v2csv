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
// Module: rule_desc_blt.h
//
// ====================================================================
//


#ifndef RULE_DESC_BLT_H
#define RULE_DESC_BLT_H

#include "commondefs.h"

typedef enum {
  SH = 3,    // high
  SM = 2,    // medium
  SL = 1,    // low
  SN = 0,    // none
} CPLX_SEVERITY;

typedef enum {
  LL = 3,    // likely
  LP = 2,    // probable
  LU = 1,    // unlikely
  LN = 0,
} CPLX_LIKELY;

typedef enum {
  CH = 1,    // high
  CM = 2,    // medium  
  CL = 3,    // low
  CN = 0,
} CPLX_COST;

typedef enum {
  IP = 4,    // performance
  IV = 3,    // vulnerable
  IC = 2,    // correctness
  IB = 1,    // bad practice
  IN = 0,
} ISSUE_CAT;

typedef enum {
  BLT_TAB = 0,
  STD_TAB = 1,
  USD_TAB = 2,
  MAX_MAP_TAB = 3,
} DFT_MAP_TAB;


typedef enum {
  SINK_ONLY = 'K',
  SRC_ONLY  = 'S',
  SRC_SINK  = 'B',
} SRC_SINK_TAG;


typedef enum RCOST_AUGMENT_LIMIT {
  RCOST_LOW_LIMIT    = 1,
  RCOST_MEDIUM_LIMIT = 2,
  RCOST_HIGH_LIMIT   = 3,
} RCOST_LIMIT;


typedef enum RCOST_AUGMENT_DEFECT {
  DFT_RCOST_LOW   = 1,
  DFT_RCOST_MED   = 2,
  DFT_RCOST_HIGH  = 3,
} RCOST_DFT;


typedef const char *CONST_STR;
typedef const char *I_ATTR;

typedef struct _dft_type {
  int           id;          // unique ID for ALL rules
  CONST_STR     dstr_c;      // string output from core
  CONST_STR     dstr_db;     // string output to DB also for equiv search
  CPLX_SEVERITY sevr;
  CPLX_LIKELY   like;
  CPLX_COST     cost;
  I_ATTR        src_sink;    // source, sink or both
  //  ISSUE_CAT     issu_c;
 public:
  CPLX_SEVERITY Sevr(const int index,  DFT_MAP_TAB dm_tab);
  CPLX_LIKELY   Like(const int index,  DFT_MAP_TAB dm_tab);
  CPLX_COST     Cost(const int index,  DFT_MAP_TAB dm_tab);
  I_ATTR        S_i_attr(const I_ATTR s, DFT_MAP_TAB dm_tab);
  int get_defect_idx(char *, DFT_MAP_TAB);

  int       Sevr(void)            { return (int)sevr; }
  void      Sevr(int s)           { sevr = (CPLX_SEVERITY)s; }
  int       Like(void)            { return (int)like; }
  void      Like(int l)           { like = (CPLX_LIKELY)l; }
  int       Cost(void)            { return (int)cost; }
  void      Cost(int c)           { cost = (CPLX_COST)c; }
  void      Iattr(I_ATTR a)       { src_sink = a; }
  I_ATTR    Iattr(void)           { return src_sink; }
  CONST_STR Str_db(void)          { return dstr_db; }
  void      Str_db(const char *s) { dstr_db = s; }

} DFT_TYPE;

typedef enum {
  // new entries must be added at end
  // and also match the struct below
#include "blt_enum.inc"
  MAX_BLTIN_SZ = MAX_BLT_ENUM,
} DFT_BLTIN_ID;  // unique id for rule

extern DFT_TYPE defect_blt_vec[];

#include "rule_desc_std.h"   // external rule standards
#include "rule_desc_gjb.h"   // GJB5369 standard

CONST_STR Rule_id2corecode(DFT_TYPE *rule_vec, int idx, int max);

#endif // RULE_DESC_BLT_H
