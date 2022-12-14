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
// Module: rule_desc.h
//
// ====================================================================
//


#ifndef RULE_DESC_H
#define RULE_DESC_H


typedef enum RULE_ID {
  // new entries must be added at end
  // and also match the struct below
  BAD0  = 0,
  BAD1  = 1,
  AOBB  = 2,
  DBFB  = 3,
  DBZB  = 4,
  DBZC  = 5,
  DBZD  = 6,
  DDVB  = 7,
  FAMB  = 8,
  FAMC  = 9,
  FAMD  = 10,
  FMTB  = 11,
  FMTC  = 12,
  FMTD  = 13,
  MSFB  = 14,
  MSFC  = 15,
  NPDB  = 16,
  RALB  = 17,
  UAFB  = 18,
  UAFC  = 19,
  UAFD  = 20,
  UAFE  = 21,
  UDRB  = 22,
  UDRC  = 23,
  UDRD  = 24,
  UDRE  = 25,
  UDRF  = 26,
  UIVB  = 27,
  CRFB  = 28,
  CSLB  = 29,
  CSSB  = 30,
  ECBB  = 31,
  RCDB  = 32,
  RXSB  = 33, 
  SCBB  = 34,
  SSEB  = 35,
  UICB  = 36,
  WRFB  = 37,
  RBCR  = 38,
  S02C  = 39,
  S02D  = 40,
  A38C  = 41,
  M37C  = 42,
  S50P  = 43,
  M54P  = 44,
  M51P  = 45,
  O13J  = 46,
  N32C  = 47,
  E33C  = 48,
  M30C  = 49,
  M32C  = 50,
  M32D  = 51,
  P54C  = 52,
  m35C  = 53,
  N33C  = 54,
  N33D  = 55,
  P30C  = 56,
  M33C  = 57,
  P34C  = 58,
  G30C  = 59,
  G31C  = 60,
  S31C  = 61,
  S32C  = 62,
  M41C  = 63,
  S38C  = 64,
  F34C  = 65,
  F37C  = 66,
  F30C  = 67,
  P37C  = 68,
  F42C  = 69,
  P35C  = 70,
  F45C  = 71,
  M51C  = 72,
  M54C  = 73,
  m55P  = 74,
  X13J  = 75,
  I04J  = 76,
  F16J  = 77,
  C02J  = 78,
  C03J  = 79,
  F02J  = 80,
  M03J  = 81,
  I00J  = 82,
  I00K  = 83,
  I00L  = 84,
  I07J  = 85,
  I07K  = 86,
  F05J  = 87,
  F08J  = 88,
  F14J  = 89,
  I17J  = 90,
  I17K  = 91,
  I16J  = 92,
  I01J  = 93,
  I01K  = 94,
  I11J  = 95,
  C07J  = 96,
  N01J  = 97,
  N03J  = 98,
  N03K  = 99,
  C01J  = 100,
  C04J  = 101,
  C06J  = 102,
  C06K  = 103,
  M02J  = 104,
  M61J  = 105,
  F52J  = 106,
  F52K  = 107,
  I51J  = 108,
  O09J  = 109,
  N06J  = 110,
  E00J  = 111,
  O11J  = 112,
  O01J  = 113,
  T06J  = 114,
  C05J  = 115,
  I15J  = 116,
  I15K  = 117,
  E08J  = 118,
  I06J  = 119,
  I53J  = 120,
  I53K  = 121,
  M62J  = 122,
  M62K  = 123,
  O07J  = 124,
  D00J  = 125,
  I54J  = 126,
  I54K  = 127,
  R01J  = 128,
  R05J  = 129,
  J01J  = 130,
  X02J  = 131,
  MAX_DFT_SZ = 132
} DFT_ID;  // unique id for rule

//  crf, csl, css, ecb, rcd, rxs, scb, sse, uic, wrf,

typedef struct {
  RULE_ID     id;        // unique ID for ALL rules
  const char *dstr_c;    // string output from core
  const char *dstr_db;   // string output to DB
} DFT_TYPE;

DFT_TYPE defect_vec[MAX_DFT_SZ] = {
  // new entries must be added at end, and match the enum above in order
  { BAD0,       "BAD",  "BAD0"},
  { BAD1,       "BAD",  "BAD1"},
  { AOBB,       "AOB",  "AOBB"},
  { DBFB,       "DBF",  "DBFB"},
  { DBZB,       "DBZ",  "DBZB"},
  { DBZC,       "DBZ",  "DBZC"},
  { DBZD,       "DBZ",  "DBZD"},
  { DDVB,       "DDV",  "DDVB"},
  { FAMB,       "FAM",  "FAMB"},
  { FAMC,       "FAM",  "FAMC"},
  { FAMD,       "FAM",  "FAMD"},
  { FMTB,       "FMT",  "FMTB"},
  { FMTC,       "FMT",  "FMTC"},
  { FMTD,       "FMT",  "FMTD"},
  { MSFB,       "MSF",  "MSFB"},
  { MSFC,       "MSF",  "MSFC"},
  { NPDB,       "NPD",  "NPDB"},
  { RALB,       "RAL",  "RALB"},
  { UAFB,       "UAF",  "UAFB"},
  { UAFC,       "UAF",  "UAFC"},
  { UAFD,       "UAF",  "UAFD"},
  { UAFE,       "UAF",  "UAFE"},
  { UDRB,       "UDR",  "UDRB"},
  { UDRC,       "UDR",  "UDRC"},
  { UDRD,       "UDR",  "UDRD"},
  { UDRE,       "UDR",  "UDRE"},
  { UDRF,       "UDR",  "UDRF"},
  { UIVB,       "UIV",  "UIVB"},
  { CRFB,       "CRF",  "CRFB"},
  { CSLB,       "CRL",  "CRLB"},
  { CSSB,       "CSS",  "CSSB"},
  { ECBB,       "ECB",  "ECBB"},
  { RCDB,       "RCD",  "RCDB"},
  { RXSB,       "RXS",  "RXSB"},
  { SCBB,       "SCB",  "SCBB"},
  { SSEB,       "SSE",  "SSEB"},
  { UICB,       "UIC",  "UICB"},
  { WRFB,       "WRF",  "WRFB"},
  { RBCR,       "RBC",  "RBCR"},
  { S02C,   "STR02-C",  "S02C"},
  { S02D,   "STR02-C",  "S02D"},
  { A38C,   "ARR38-C",  "A38C"},
  { M37C,   "MSC37-C",  "M37C"},
  { S50P, "STR50-CPP",  "S50P"},
  { M54P, "MSC54-CPP",  "M54P"},
  { M51P, "MSC51-CPP",  "M51P"},
  { O13J,   "OBJ13-J",  "O13J"},
  { N32C,   "ENV32-C",  "N32C"},
  { E33C,   "ERR33-C",  "E33C"},
  { M30C,   "MSC30-C",  "M30C"},  // M for MSC
  { M32C,   "MSC32-C",  "M32C"},
  { M32D,   "MSC32-C",  "M32D"},
  { P54C,   "POS54-C",  "P54C"},
  { m35C,   "MEM35-C",  "m35C"},  // m for MEM
  { N33C,   "ENV33-C",  "N33C"},
  { M33C,   "ENV33-C",  "M33C"},
  { P30C,   "POS30-C",  "P30C"},
  { M33C,   "MSC33-C",  "M33C"},
  { P34C,   "POS34-C",  "P34C"},
  { G30C,   "SIG30-C",  "G30C"},  // G for SIG
  { G31C,   "SIG31-C",  "G31C"},
  { S31C,   "STR31-C",  "S31C"},
  { S32C,   "STR32-C",  "S32C"},
  { M41C,   "MSC41-C",  "M41C"},
  { S38C,   "STR38-C",  "S48C"},
  { F34C,   "FIO34-C",  "F34C"},
  { F37C,   "FIO37-C",  "F37C"},
  { F30C,   "FIO30-C",  "F30C"},
  { P37C,   "POS37-C",  "P37C"},
  { F42C,   "FIO42-C",  "F42C"},
  { P35C,   "POS35-C",  "P35C"},
  { F45C,   "FIO45-C",  "F45C"},
  { M51C,   "MSC51-C",  "M51C"},
  { M54C,   "MSC54-C",  "M54C"},
  { m55P, "MEM55-CPP",  "m55P"},
  { X13J,   "EXP13-J",  "X13J"},
  { I04J,   "IDS04-J",  "I04J"},
  { F16J,   "FIO16-J",  "F16J"},
  { C02J,   "SEC02-J",  "C02J"},  // C for SEC
  { C03J,   "SEC03-J",  "C03J"},
  { F02J,   "FIO02-J",  "F02J"},
  { M03J,   "MSC03-J",  "M03J"},
  { I00J,   "IDS00-J",  "I00J"},
  { I00K,   "IDS00-J",  "I00K"},
  { I00L,   "IDS00-J",  "I00L"},
  { I07J,   "IDS07-J",  "I07J"},
  { I07K,   "IDS07-J",  "I07K"},
  { F05J,   "FIO05-J",  "F05J"},
  { F08J,   "FIO08-J",  "F08J"},
  { F14J,   "FIO14-J",  "F14J"},
  { I17J,   "IDS17-J",  "I17J"},
  { I17K,   "IDS17-J",  "I17K"},
  { I16J,   "IDS16-J",  "I16J"},
  { I01J,   "IDS01-J",  "I01J"},
  { I01K,   "IDS01-J",  "I01K"},
  { I11J,   "IDS11-J",  "I11J"},
  { C07J,   "SEC07-J",  "C07J"},
  { N01J,   "ENV01-J",  "N01J"},
  { N03J,   "ENV03-J",  "N03J"},
  { N03K,   "ENV03-J",  "N03K"},
  { C01J,   "SEC01-J",  "C01J"},
  { C04J,   "SEC04-J",  "C04J"},
  { C06J,   "SEC06-J",  "C06J"},
  { C06K,   "SEC06-J",  "C06K"},
  { M02J,   "MSC02-J",  "M02J"},
  { M61J,   "MSC61-J",  "M61J"},
  { F52J,   "FIO52-J",  "F52J"},
  { F52K,   "FIO52-J",  "F52K"},
  { I51J,   "IDS51-J",  "I51J"},
  { O09J,   "OBJ09-J",  "O09J"},
  { N06J,   "ENV06-J",  "N06J"},
  { E00J,   "ERR00-J",  "E00J"},
  { O11J,   "OBJ11-J",  "O11J"},
  { O01J,   "OBJ01-J",  "O01J"},
  { T06J,   "MET06-J",  "T06J"},
  { C05J,   "SEC05-J",  "C05J"},
  { I15J,   "IDS15-J",  "I15J"},
  { I15K,   "IDS15-J",  "I15K"},
  { E08J,   "ERR08-J",  "E08J"},
  { I06J,   "IDS06-J",  "I06J"},
  { I53J,   "IDS53-J",  "I53J"},
  { I53K,   "IDS53-J",  "I53K"},
  { M62J,   "MSC62-J",  "M62J"},
  { M62K,   "MSC62-J2", "M62K"},    // variation of M62J
  { O07J,   "OBJ07-J",  "O07J"},
  { D00J,   "DCL00-J",  "D00J"},
  { I54J,   "IDS54-J",  "I54J"},
  { I54K,   "IDS54-J",  "I54K"},
  { R01J,   "SER01-J",  "R01J"},    // R for SER
  { R05J,   "SER05-J",  "R05J"},
  { J01J,   "JNI01-J",  "J01J"},
  { X02J,   "EXP02-J",  "X02J"},

};

#endif // RULE_DESC_H
