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

#ifndef commondefs_INCLUDED
#define commondefs_INCLUDED
// =============================================================================
// =============================================================================
//
// Module: commondefs.h
//
// Revision history:
//  02-Feb-21 - Original Version
//
// Description:
//
// This header file contains definitions to improve the portability
//
// =============================================================================
// =============================================================================

// Make stdio, and string support generally available:
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <unordered_map>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
//
// Type mapping
//
// The following type names are to be used in general to avoid host
// dependencies.  Each type name specifies a minimum bit length for the object 
// being defined of 8, 16, or 32 bits. 
//
// =============================================================================

typedef signed int         INT;	  // The natural integer on the host 
typedef signed int         INT8;
typedef signed int         INT16;
typedef signed int         INT32;
typedef signed long long   INT64;	
typedef unsigned long      INTPTR;// Integer the same size as pointer
typedef unsigned int	   UINT;
typedef unsigned int       UINT8;
typedef unsigned int       UINT16;// Use the natural integer 
typedef unsigned int	   UINT32;// The natural integer matches 
typedef unsigned long long UINT64;
typedef int	           BOOL;  // Natural size Boolean value 
typedef signed char        mINT8; // Avoid - often very inefficient 
typedef signed short       mINT16;// Use a 16-bit integer 
typedef signed int         mINT32;// The natural integer matches 
typedef signed long long   mINT64;
typedef unsigned char      mUINT8;// Use the natural integer
typedef unsigned short     mUINT16;// Use a 16-bit integer
typedef unsigned int       mUINT32;// The natural integer matches
typedef unsigned long long mUINT64;
typedef unsigned char      mBOOL; // Minimal size Boolean value

typedef UINT32             IDTYPE;
typedef const char *       CONST_STR;

typedef enum {
    FALSE = 0,
    TRUE = 1
} BOOLVAL;

typedef enum {
  VTXT_CURRENT  = 1,
  VTXT_BASELINE = 2,
  VTXT_BORC     = (VTXT_BASELINE | VTXT_CURRENT),
  SIMP_CURRENT  = 4,
  SIMP_BASELINE = 8,
  FILT_CURRENT  = 16,
  FILT_BASELINE = 32,
  VTXT_NBASE    = (64 | VTXT_BASELINE),
  VTXT_LBASE    = (128| VTXT_BASELINE),
  VTXT_EBASE    = (256| VTXT_BASELINE),
  VTXT_FBASE    = 512,
  SRC_FILE_JSON = 1024
} VTXT_KIND;

#define SEPARATOR_s "------------------------------------------------------------\n"
#define SEPARATOR_d "============================================================\n"

#ifdef __cplusplus

}
#endif

typedef std::unordered_map<std::string, INT> STR_MAP;

template <typename T>
T Clone_data(T orig) {
  T retv = (T)malloc(strlen(orig)+1);
  if (retv == NULL) {
    fprintf(stderr,(char *)"Fail to allocate memory during Clong_string");
    return NULL;
  }
  strcpy(retv, orig);
  return retv;
}

#endif // commondefs_INCLUDED
