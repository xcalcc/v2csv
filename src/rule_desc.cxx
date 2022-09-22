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
// Module: rule_desc.cxx
//
// ====================================================================
//

#include "rule_desc_blt.h"
#include "vtxt_report.h"

DFT_TYPE defect_blt_vec[MAX_BLTIN_SZ] = {
  // new entries must be added at end, and match the enum above in order

#include "blt.inc"

};

DFT_TYPE defect_std_vec[MAX_STD_SZ] = {
  // new entries must be added at end, and match the enum above in order
#if 1
#include "cert.inc"
#else
  { rSV00,   "",         "",         SN, LN, CN      },
  { rSV01,   "",         "",         SN, LN, CN      },
  { rSV02,   "",         "",         SN, LN, CN      },
  { rSV03,   "",         "",         SN, LN, CN      },
  { S02C1,   "STR02-C",  "S02C1",    SH, LL, CM      },
  { S02C0,   "STR02-C",  "S02C0",    SH, LL, CM      },
  { rSV04,   "",         "",         SN, LN, CN      },
  { A38C0,   "ARR38-C",  "A38C0",    SH, LL, CM      },  
  { rSV05,   "",         "",         SN, LN, CN      },
  { M37C0,   "MSC37-C",  "M37C0",    SM, LU, CL      },
  { rSV06,   "",         "",         SN, LN, CN      },
  { S50P0, "STR50-CPP",  "S50P0",    SH, LL, CM      },
  { rSV07,   "",         "",         SN, LN, CN      },
  { M54P0, "MSC54-CPP",  "M54P0",    SH, LP, CH      },
  { rSV08,   "",         "",         SN, LN, CN      },
  { M51P0, "MSC51-CPP",  "M51P0",    SM, LL, CL      },
  { rSV09,   "",         "",         SN, LN, CN      },
  { O13J0,   "OBJ13-J",  "O13J0",    SM, LL, CL      },
  { rSV10,   "",         "",         SN, LN, CN      },
  { N32C0,   "ENV32-C",  "N32C0",    SM, LL, CM      },
  { rSV11,   "",         "",         SN, LN, CN      },
  { E33C0,   "ERR33-C",  "E33C0",    SH, LL, CM      },
  { rSV12,   "",         "",         SN, LN, CN      },
  { M30C0,   "MSC30-C",  "M30C0",    SM, LU, CL      },  // M for MSC
  { rSV13,   "",         "",         SN, LN, CN      },
  { rSV14,   "",         "",         SN, LN, CN      },
  { M32C1,   "MSC32-C",  "M32C1",    SM, LL, CL      },
  { M32C0,   "MSC32-C",  "M32C0",    SM, LL, CL      },
  { rSV15,   "",         "",         SN, LN, CN      },
  { P54C0,   "POS54-C",  "P54C0",    SH, LL, CL      },
  { rSV16,   "",         "",         SN, LN, CN      },
  { m35C0,   "MEM35-C",  "m35C0",    SH, LP, CH      },  // m for MEM
  { rSV17,   "",         "",         SN, LN, CN      },
  { rSV18,   "",         "",         SN, LN, CN      },
  { N33C1,   "ENV33-C",  "N33C1",    SH, LP, CM      },
  { M33C0,   "ENV33-C",  "M33C0",    SH, LP, CM      },
  { rSV19,   "",         "",         SN, LN, CN      },
  { P30C0,   "POS30-C",  "P30C0",    SH, LP, CM      },
  { rSV20,   "",         "",         SN, LN, CN      },
  { M33C0,   "MSC33-C",  "M33C0",    SH, LL, CL      },
  { rSV21,   "",         "",         SN, LN, CN      },
  { P34C0,   "POS34-C",  "P34C0",    SH, LU, CM      },
  { rSV22,   "",         "",         SN, LN, CN      },
  { G30C0,   "SIG30-C",  "G30C0",    SH, LL, CM      },  // G for SIG
  { rSV23,   "",         "",         SN, LN, CN      },
  { G31C0,   "SIG31-C",  "G31C0",    SH, LL, CH      },
  { rSV24,   "",         "",         SN, LN, CN      },
  { S31C0,   "STR31-C",  "S31C0",    SH, LL, CM      },
  { rSV25,   "",         "",         SN, LN, CN      },
  { S32C0,   "STR32-C",  "S32C0",    SH, LP, CM      },
  { rSV26,   "",         "",         SN, LN, CN      },
  { M41C0,   "MSC41-C",  "M41C0",    SH, LP, CM      },
  { rSV27,   "",         "",         SN, LN, CN      },
  { S38C0,   "STR38-C",  "S38C0",    SH, LL, CL      },
  { rSV28,   "",         "",         SN, LN, CN      },
  { F34C0,   "FIO34-C",  "F34C0",    SH, LP, CM      },
  { rSV29,   "",         "",         SN, LN, CN      },
  { F37C0,   "FIO37-C",  "F37C0",    SH, LP, CM      },
  { rSV30,   "",         "",         SN, LN, CN      },
  { F30C0,   "FIO30-C",  "F30C0",    SH, LL, CM      },
  { rSV31,   "",         "",         SN, LN, CN      },
  { P37C0,   "POS37-C",  "P37C0",    SH, LP, CL      },
  { rSV32,   "",         "",         SN, LN, CN      },
  { F42C0,   "FIO42-C",  "F42C0",    SH, LP, CH      },
  { rSV33,   "",         "",         SN, LN, CN      },
  { P35C0,   "POS35-C",  "P35C0",    SH, LL, CM      },
  { rSV34,   "",         "",         SN, LN, CN      },
  { F45C0,   "FIO45-C",  "F45C0",    SH, LP, CH      },
  { rSV35,   "",         "",         SN, LN, CN      },
  { M51P0,   "MSC51-CPP","M51P0",    SM, LL, CL      },
  { rSV36,   "",         "",         SN, LN, CN      },
  { M54P0,   "MSC54-C",  "M54P0",    SH, LP, CH      },
  { rSV37,   "",         "",         SN, LN, CN      },
  { m55P0, "MEM55-CPP",  "m55P0",    SH, LL, CM      },
  { rSV38,   "",         "",         SN, LN, CN      },
  { X13J0,   "EXP13-J",  "X13J0",    , ,       },
  { rSV39,   "",         "",         SN, LN, CN      },
  { I04J0,   "IDS04-J",  "I04J0",    , ,       },
  { rSV40,   "",         "",         SN, LN, CN      },
  { F16J0,   "FIO16-J",  "F16J0",    SM, LU, CM      },
  { rSV41,   "",         "",         SN, LN, CN      },
  { C02J0,   "SEC02-J",  "C02J0",    SH, LP, CM      },  // C for SEC
  { rSV42,   "",         "",         SN, LN, CN      },
  { C03J0,   "SEC03-J",  "C03J0",    SH, LP, CM      },
  { rSV43,   "",         "",         SN, LN, CN      },
  { F02J0,   "FIO02-J",  "F02J0",    SM, LP, CM      },
  { rSV44,   "",         "",         SN, LN, CN      },
  { M03J0,   "MSC03-J",  "M03J0",    SH, LP, CM      },
  { rSV45,   "",         "",         SN, LN, CN      },
  { rSV46,   "",         "",         SN, LN, CN      },
  { I00J2,   "IDS00-J",  "I00J2",    SH, LP, CH      },
  { I00J1,   "IDS00-J",  "I00J1",    SH, LP, CH      },
  { I00J0,   "IDS00-J",  "I00J0",    SH, LP, CH      },
  { rSV47,   "",         "",         SN, LN, CN      },
  { rSV48,   "",         "",         SN, LN, CN      },
  { rSV49,   "",         "",         SN, LN, CN      },
  { I07J1,   "IDS07-J",  "I07J1",    SH, LP, CM      },
  { I07J0,   "IDS07-J",  "I07J0",    SH, LP, CM      },
  { rSV50,   "",         "",         SN, LN, CN      },
  { F05J0,   "FIO05-J",  "F05J0",    SM, LL, CL      },
  { rSV51,   "",         "",         SN, LN, CN      },
  { F08J0,   "FIO08-J",  "F08J0",    SH, LP, CM      },
  { rSV52,   "",         "",         SN, LN, CN      },
  { F14J0,   "FIO14-J",  "F14J0",    SM, LL, CM      },
  { rSV53,   "",         "",         SN, LN, CN      },
  { rSV54,   "",         "",         SN, LN, CN      },
  { I17J1,   "IDS17-J",  "I17J1",    SM, LP, CM      },
  { I17J0,   "IDS17-J",  "I17J0",    SM, LP, CM      },
  { rSV55,   "",         "",         SN, LN, CN      },
  { I16J0,   "IDS16-J",  "I16J0",    , ,       },
  { rSV56,   "",         "",         SN, LN, CN      },
  { rSV57,   "",         "",         SN, LN, CN      },
  { I01J1,   "IDS01-J",  "I01J1",    SH, LP, CM      },
  { I01J0,   "IDS01-J",  "I01J0",    SH, LP, CM      },
  { rSV58,   "",         "",         SN, LN, CN      },
  { I11J0,   "IDS11-J",  "I11J0",    SH, LP, CM      },
  { rSV59,   "",         "",         SN, LN, CN      },
  { C07J0,   "SEC07-J",  "C07J0",    SH, LP, CL      },
  { rSV60,   "",         "",         SN, LN, CN      },
  { N01J0,   "ENV01-J",  "N01J0",    SH, LP, CM      },
  { rSV61,   "",         "",         SN, LN, CN      },
  { rSV62,   "",         "",         SN, LN, CN      },
  { N03J1,   "ENV03-J",  "N03J1",    SH, LL, CL      },
  { N03J0,   "ENV03-J",  "N03J0",    SH, LL, CL      },
  { rSV64,   "",         "",         SN, LN, CN      },
  { C01J0,   "SEC01-J",  "C01J0",    SH, LL, CL      },
  { rSV63,   "",         "",         SN, LN, CN      },
  { C04J0,   "SEC04-J",  "C04J0",    SH, LP, CM      },
  { rSV65,   "",         "",         SN, LN, CN      },
  { rSV66,   "",         "",         SN, LN, CN      },
  { C06J1,   "SEC06-J",  "C06J1",    SH, LP, CM      },
  { C06J0,   "SEC06-J",  "C06J0",    SH, LP, CM      },
  { rSV67,   "",         "",         SN, LN, CN      },
  { M02J0,   "MSC02-J",  "M02J0",    SH, LP, CM      },
  { rSV68,   "",         "",         SN, LN, CN      },
  { M61J0,   "MSC61-J",  "M61J0",    SM, LP, CH      },
  { rSV69,   "",         "",         SN, LN, CN      },
  { rSV70,   "",         "",         SN, LN, CN      },
  { F52J1,   "FIO52-J",  "F52J1",    SM, LL, CM      },
  { F52J0,   "FIO52-J",  "F52J0",    SM, LL, CM      },
  { rSV71,   "",         "",         SN, LN, CN      },
  { I51J0,   "IDS51-J",  "I51J0",    , ,       },
  { rSV72,   "",         "",         SN, LN, CN      },
  { O09J0,   "OBJ09-J",  "O09J0",    SH, LU, CL      },
  { rSV73,   "",         "",         SN, LN, CN      },
  { N06J0,   "ENV06-J",  "N06J0",    SH, LP, CL      },
  { rSV74,   "",         "",         SN, LN, CN      },
  { E00J0,   "ERR00-J",  "E00J0",    SL, LP, CM      },
  { rSV75,   "",         "",         SN, LN, CN      },
  { O11J0,   "OBJ11-J",  "O11J0",    SH, LP, CM      },
  { rSV76,   "",         "",         SN, LN, CN      },
  { O01J0,   "OBJ01-J",  "O01J0",    SM, LL, CM      },
  { rSV77,   "",         "",         SN, LN, CN      },
  { T06J0,   "MET06-J",  "T06J0",    SH, LP, CL      },
  { rSV78,   "",         "",         SN, LN, CN      },
  { C05J0,   "SEC05-J",  "C05J0",    SH, LP, CM      },
  { rSV79,   "",         "",         SN, LN, CN      },
  { rSV80,   "",         "",         SN, LN, CN      },
  { I15J1,   "IDS15-J",  "I15J1",    SM, LL, CM      },
  { I15J0,   "IDS15-J",  "I15J0",    SM, LL, CM      },
  { rSV81,   "",         "",         SN, LN, CN      },
  { E08J0,   "ERR08-J",  "E08J0",    SM, LL, CM      },
  { rSV82,   "",         "",         SN, LN, CN      },
  { I06J,0   "IDS06-J",  "I06J0",    , ,       },
  { rSV83,   "",         "",         SN, LN, CN      },
  { rSV84,   "",         "",         SN, LN, CN      },
  { I53J1,   "IDS53-J",  "I53J1",    , ,       },
  { I53J0,   "IDS53-J",  "I53J0",    , ,       },
  { rSV84,   "",         "",         SN, LN, CN      },
  { rSV86,   "",         "",         SN, LN, CN      },
  { M62J1,   "MSC62-J",  "M62J1",    , ,       },
  { M62J0,   "MSC62-J2", "M62J0",    , ,       },    // variation of M62J
  { rSV87,   "",         "",         SN, LN, CN      },
  { O07J0,   "OBJ07-J",  "O07J0",    SM, LP, CM      },
  { rSV88,   "",         "",         SN, LN, CN      },
  { D00J0,   "DCL00-J",  "D00J0",    SL, LU, CM      },
  { rSV89,   "",         "",         SN, LN, CN      },
  { rSV90,   "",         "",         SN, LN, CN      },
  { I54J1,   "IDS54-J",  "I54J1",    , ,       },
  { I54J0,   "IDS54-J",  "I54J0",    , ,       },
  { rSV91,   "",         "",         SN, LN, CN      },
  { R01J0,   "SER01-J",  "R01J0",    SH, LL, CL      },    // R for SER
  { rSV92,   "",         "",         SN, LN, CN      },
  { R05J0,   "SER05-J",  "R05J0",    SM, LL, CM      },
  { rSV93,   "",         "",         SN, LN, CN      },
  { J01J0,   "JNI01-J",  "J01J0",    SH, LL, CL      },
  { rSV94,   "",         "",         SN, LN, CN      },
  { X02J0,   "EXP02-J",  "X02J0",    SL, LL, CL      },
#endif
};

DFT_TYPE defect_gjb_vec[MAX_GJB5369_ENUM] = {

#if 1
#include "GJB5369.inc"
#else
  { GJB5369,"GJB5369","GJB5369",SN,LN,CN,""},
  { 4-1-1-1,"4-1-1-1","4-1-1-1",SL,LL,CL,"S"},
  { 4-1-1-2,"4-1-1-2","4-1-1-2",SL,LL,CL,"S"},
  { 4-1-1-3,"4-1-1-3","4-1-1-3",SL,LL,CL,"S"},
  { 4-1-1-4,"4-1-1-4","4-1-1-4",SL,LL,CL,"S"},
  { 4-1-1-5,"4-1-1-5","4-1-1-5",SL,LL,CL,"S"},
  { 4-1-1-6,"4-1-1-6","4-1-1-6",SL,LL,CL,"S"},
  { 4-1-1-7,"4-1-1-7","4-1-1-7",SL,LL,CL,"S"},
  { 4-1-1-8,"4-1-1-8","4-1-1-8",SL,LL,CL,"S"},
  { 4-1-1-9,"4-1-1-9","4-1-1-9",SL,LL,CL,"S"},
  { 4-1-1-10,"4-1-1-10","4-1-1-10",SL,LL,CL,"S"},
  { 4-1-1-11,"4-1-1-11","4-1-1-11",SL,LL,CL,"S"},
  { 4-1-1-12,"4-1-1-12","4-1-1-12",SL,LL,CL,"S"},
  { 4-1-1-13,"4-1-1-13","4-1-1-13",SL,LL,CL,"S"},
  { 4-1-1-14,"4-1-1-14","4-1-1-14",SL,LL,CL,"S"},
  { 4-1-1-15,"4-1-1-15","4-1-1-15",SL,LL,CL,"S"},
  { 4-1-1-16,"4-1-1-16","4-1-1-16",SL,LL,CL,"S"},
  { 4-1-1-17,"4-1-1-17","4-1-1-17",SL,LL,CL,"S"},
  { 4-1-1-18,"4-1-1-18","4-1-1-18",SL,LL,CL,"S"},
  { 4-1-1-19,"4-1-1-19","4-1-1-19",SL,LL,CL,"S"},
  { 4-1-1-20,"4-1-1-20","4-1-1-20",SL,LL,CL,"S"},
  { 4-1-1-21,"4-1-1-21","4-1-1-21",SL,LL,CL,"S"},
  { 4-1-1-22,"4-1-1-22","4-1-1-22",SL,LL,CL,"S"},
  { 4-1-2-1,"4-1-2-1","4-1-2-1",SL,LL,CL,"S"},
  { 4-1-2-2,"4-1-2-2","4-1-2-2",SL,LL,CL,"S"},
  { 4-1-2-3,"4-1-2-3","4-1-2-3",SL,LL,CL,"S"},
  { 4-1-2-4,"4-1-2-4","4-1-2-4",SL,LL,CL,"S"},
  { 4-1-2-5,"4-1-2-5","4-1-2-5",SL,LL,CL,"S"},
  { 4-1-2-6,"4-1-2-6","4-1-2-6",SL,LL,CL,"S"},
  { 4-1-2-7,"4-1-2-7","4-1-2-7",SL,LL,CL,"S"},
  { 4-1-2-8,"4-1-2-8","4-1-2-8",SL,LL,CL,"S"},
  { 4-1-2-9,"4-1-2-9","4-1-2-9",SL,LL,CL,"S"},
  { 4-2-1-1,"4-2-1-1","4-2-1-1",SL,LL,CL,"S"},
  { 4-2-1-2,"4-2-1-2","4-2-1-2",SL,LL,CL,"S"},
  { 4-2-1-3,"4-2-1-3","4-2-1-3",SL,LL,CL,"S"},
  { 4-2-1-4,"4-2-1-4","4-2-1-4",SL,LL,CL,"S"},
  { 4-2-1-5,"4-2-1-5","4-2-1-5",SL,LL,CL,"S"},
  { 4-2-1-6,"4-2-1-6","4-2-1-6",SL,LL,CL,"S"},
  { 4-2-1-7,"4-2-1-7","4-2-1-7",SL,LL,CL,"S"},
  { 4-2-1-8,"4-2-1-8","4-2-1-8",SL,LL,CL,"S"},
  { 4-2-1-9,"4-2-1-9","4-2-1-9",SL,LL,CL,"S"},
  { 4-2-1-10,"4-2-1-10","4-2-1-10",SL,LL,CL,"S"},
  { 4-2-2-1,"4-2-2-1","4-2-2-1",SL,LL,CL,"S"},
  { 4-2-2-2,"4-2-2-2","4-2-2-2",SL,LL,CL,"S"},
  { 4-3-1-1,"4-3-1-1","4-3-1-1",SL,LL,CL,"S"},
  { 4-3-1-2,"4-3-1-2","4-3-1-2",SL,LL,CL,"S"},
  { 4-3-1-3,"4-3-1-3","4-3-1-3",SL,LL,CL,"S"},
  { 4-3-1-4,"4-3-1-4","4-3-1-4",SL,LL,CL,"S"},
  { 4-3-1-5,"4-3-1-5","4-3-1-5",SL,LL,CL,"S"},
  { 4-3-1-6,"4-3-1-6","4-3-1-6",SL,LL,CL,"S"},
  { 4-3-1-7,"4-3-1-7","4-3-1-7",SL,LL,CL,"S"},
  { 4-3-1-8,"4-3-1-8","4-3-1-8",SL,LL,CL,"S"},
  { 4-4-1-1,"4-4-1-1","4-4-1-1",SL,LL,CL,"S"},
  { 4-4-1-2,"4-4-1-2","4-4-1-2",SL,LL,CL,"S"},
  { 4-4-1-3,"4-4-1-3","4-4-1-3",SL,LL,CL,"S"},
  { 4-4-2-1,"4-4-2-1","4-4-2-1",SL,LL,CL,"S"},
  { 4-4-2-2,"4-4-2-2","4-4-2-2",SL,LL,CL,"S"},
  { 4-5-1-1,"4-5-1-1","4-5-1-1",SL,LL,CL,"S"},
  { 4-5-1-2,"4-5-1-2","4-5-1-2",SL,LL,CL,"S"},
  { 4-5-2-1,"4-5-2-1","4-5-2-1",SL,LL,CL,"S"},
  { 4-6-1-1,"4-6-1-1","4-6-1-1",SL,LL,CL,"S"},
  { 4-6-1-2,"4-6-1-2","4-6-1-2",SL,LL,CL,"S"},
  { 4-6-1-3,"4-6-1-3","4-6-1-3",SL,LL,CL,"S"},
  { 4-6-1-4,"4-6-1-4","4-6-1-4",SL,LL,CL,"S"},
  { 4-6-1-5,"4-6-1-5","4-6-1-5",SL,LL,CL,"S"},
  { 4-6-1-6,"4-6-1-6","4-6-1-6",SL,LL,CL,"S"},
  { 4-6-1-7,"4-6-1-7","4-6-1-7",SL,LL,CL,"S"},
  { 4-6-1-8,"4-6-1-8","4-6-1-8",SL,LL,CL,"S"},
  { 4-6-1-9,"4-6-1-9","4-6-1-9",SL,LL,CL,"S"},
  { 4-6-1-10,"4-6-1-10","4-6-1-10",SL,LL,CL,"S"},
  { 4-6-1-11,"4-6-1-11","4-6-1-11",SL,LL,CL,"S"},
  { 4-6-1-12,"4-6-1-12","4-6-1-12",SL,LL,CL,"S"},
  { 4-6-1-13,"4-6-1-13","4-6-1-13",SL,LL,CL,"S"},
  { 4-6-1-14,"4-6-1-14","4-6-1-14",SL,LL,CL,"S"},
  { 4-6-1-15,"4-6-1-15","4-6-1-15",SL,LL,CL,"S"},
  { 4-6-1-16,"4-6-1-16","4-6-1-16",SL,LL,CL,"S"},
  { 4-6-1-17,"4-6-1-17","4-6-1-17",SL,LL,CL,"S"},
  { 4-6-1-18,"4-6-1-18","4-6-1-18",SL,LL,CL,"S"},
  { 4-6-2-1,"4-6-2-1","4-6-2-1",SL,LL,CL,"S"},
  { 4-6-2-2,"4-6-2-2","4-6-2-2",SL,LL,CL,"S"},
  { 4-6-2-3,"4-6-2-3","4-6-2-3",SL,LL,CL,"S"},
  { 4-6-2-4,"4-6-2-4","4-6-2-4",SL,LL,CL,"S"},
  { 4-7-1-1,"4-7-1-1","4-7-1-1",SL,LL,CL,"S"},
  { 4-7-1-2,"4-7-1-2","4-7-1-2",SL,LL,CL,"S"},
  { 4-7-1-3,"4-7-1-3","4-7-1-3",SL,LL,CL,"S"},
  { 4-7-1-4,"4-7-1-4","4-7-1-4",SL,LL,CL,"S"},
  { 4-7-1-5,"4-7-1-5","4-7-1-5",SL,LL,CL,"S"},
  { 4-7-1-6,"4-7-1-6","4-7-1-6",SL,LL,CL,"S"},
  { 4-7-1-7,"4-7-1-7","4-7-1-7",SL,LL,CL,"S"},
  { 4-7-1-8,"4-7-1-8","4-7-1-8",SL,LL,CL,"S"},
  { 4-7-1-9,"4-7-1-9","4-7-1-9",SL,LL,CL,"S"},
  { 4-7-1-10,"4-7-1-10","4-7-1-10",SL,LL,CL,"S"},
  { 4-7-2-1,"4-7-2-1","4-7-2-1",SL,LL,CL,"S"},
  { 4-7-2-2,"4-7-2-2","4-7-2-2",SL,LL,CL,"S"},
  { 4-7-2-3,"4-7-2-3","4-7-2-3",SL,LL,CL,"S"},
  { 4-8-1-1,"4-8-1-1","4-8-1-1",SL,LL,CL,"S"},
  { 4-8-1-2,"4-8-1-2","4-8-1-2",SL,LL,CL,"S"},
  { 4-8-1-3,"4-8-1-3","4-8-1-3",SL,LL,CL,"S"},
  { 4-8-2-1,"4-8-2-1","4-8-2-1",SL,LL,CL,"S"},
  { 4-8-2-2,"4-8-2-2","4-8-2-2",SL,LL,CL,"S"},
  { 4-8-2-3,"4-8-2-3","4-8-2-3",SL,LL,CL,"S"},
  { 4-8-2-4,"4-8-2-4","4-8-2-4",SL,LL,CL,"S"},
  { 4-8-2-5,"4-8-2-5","4-8-2-5",SL,LL,CL,"S"},
  { 4-8-2-6,"4-8-2-6","4-8-2-6",SL,LL,CL,"S"},
  { 4-8-2-7,"4-8-2-7","4-8-2-7",SL,LL,CL,"S"},
  { 4-8-2-8,"4-8-2-8","4-8-2-8",SL,LL,CL,"S"},
  { 4-9-1-1,"4-9-1-1","4-9-1-1",SL,LL,CL,"S"},
  { 4-9-1-2,"4-9-1-2","4-9-1-2",SL,LL,CL,"S"},
  { 4-9-1-3,"4-9-1-3","4-9-1-3",SL,LL,CL,"S"},
  { 4-9-1-4,"4-9-1-4","4-9-1-4",SL,LL,CL,"S"},
  { 4-9-1-5,"4-9-1-5","4-9-1-5",SL,LL,CL,"S"},
  { 4-10-1-1,"4-10-1-1","4-10-1-1",SL,LL,CL,"S"},
  { 4-10-2-1,"4-10-2-1","4-10-2-1",SL,LL,CL,"S"},
  { 4-10-2-2,"4-10-2-2","4-10-2-2",SL,LL,CL,"S"},
  { 4-11-1-1,"4-11-1-1","4-11-1-1",SL,LL,CL,"S"},
  { 4-11-1-2,"4-11-1-2","4-11-1-2",SL,LL,CL,"S"},
  { 4-11-2-1,"4-11-2-1","4-11-2-1",SL,LL,CL,"S"},
  { 4-11-2-2,"4-11-2-2","4-11-2-2",SL,LL,CL,"S"},
  { 4-11-2-3,"4-11-2-3","4-11-2-3",SL,LL,CL,"S"},
  { 4-12-1-1,"4-12-1-1","4-12-1-1",SL,LL,CL,"S"},
  { 4-12-2-1,"4-12-2-1","4-12-2-1",SL,LL,CL,"S"},
  { 4-12-2-2,"4-12-2-2","4-12-2-2",SL,LL,CL,"S"},
  { 4-12-2-3,"4-12-2-3","4-12-2-3",SL,LL,CL,"S"},
  { 4-13-1-1,"4-13-1-1","4-13-1-1",SL,LL,CL,"S"},
  { 4-13-1-2,"4-13-1-2","4-13-1-2",SL,LL,CL,"S"},
  { 4-13-1-3,"4-13-1-3","4-13-1-3",SL,LL,CL,"S"},
  { 4-13-1-4,"4-13-1-4","4-13-1-4",SL,LL,CL,"S"},
  { 4-14-1-1,"4-14-1-1","4-14-1-1",SL,LL,CL,"S"},
  { 4-14-1-2,"4-14-1-2","4-14-1-2",SL,LL,CL,"S"},
  { 4-14-1-3,"4-14-1-3","4-14-1-3",SL,LL,CL,"S"},
  { 4-14-2-1,"4-14-2-1","4-14-2-1",SL,LL,CL,"S"},
  { 4-14-2-2,"4-14-2-2","4-14-2-2",SL,LL,CL,"S"},
  { 4-15-1-1,"4-15-1-1","4-15-1-1",SL,LL,CL,"S"},
  { 4-15-1-2,"4-15-1-2","4-15-1-2",SL,LL,CL,"S"},
  { 4-15-1-3,"4-15-1-3","4-15-1-3",SL,LL,CL,"S"},
  { 4-15-1-4,"4-15-1-4","4-15-1-4",SL,LL,CL,"S"},
  { 4-15-1-5,"4-15-1-5","4-15-1-5",SL,LL,CL,"S"},
  { 4-15-1-6,"4-15-1-6","4-15-1-6",SL,LL,CL,"S"},
  { 4-15-2-1,"4-15-2-1","4-15-2-1",SL,LL,CL,"S"},
  { 4-15-2-2,"4-15-2-2","4-15-2-2",SL,LL,CL,"S"},
#endif
  

};


#ifndef CSVERRCODE_H
#define CSVERRCODE_H

#define  E_CSV_INVALID_INPUT_FILE   0
#define  E_CSV_OUT_OF_MEMORY        1
#define  E_CSV_INVALID_OUTPUT_FILE  2
#define  E_CSV_SIZE                 3

DFT_CAT dft_type[MAX_DFT] = { {Vul, "Vul"}, {Perf, "Perf"} };

CONF_INFO conf_type[MAX_CONF] = {
  { may_be,   (char*)"M" },
  { definite, (char*)"D" },
  { annotate, (char*)"A" }
};

#endif

ERR_CODE_T CSV_ERRCODE[E_CSV_SIZE] = {
//  who  where which  what  visible
   { 1,    4,    3,    1,    1 },
   { 3,    4,    0,    2,    1 },
   { 1,    4,    3,    3,    1 },
};

INT32 Csv_errcode(INT c)
{
  return CSV_ERRCODE[c].val;
}

CONST_STR
Rule_id2corecode(DFT_TYPE *rule_vec, int idx, int max)
{
  for (int i=0; i != max; ++i)
    if (rule_vec[i].id == idx)
      return rule_vec[i].dstr_c;
  return (CONST_STR)NULL;
}
