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
// Module: file_path.h
//
// Description:
//
//
//
// =============================================================================
// =============================================================================
//

#ifndef FILEPATH_H
#define FILEPATH_H

#include <vector>
#include "commondefs.h"

using namespace std;

class FID_PATH {
private:
  INT   _fid;
  char *_path;
public:
  FID_PATH(INT fid, char *path) : _fid(fid), _path(path) {}
  ~FID_PATH(void) {}

  INT   Fid(void)   { return _fid; }
  char *Path(void)  { return _path; }
  void  Print(FILE *fp);
};

typedef vector<FID_PATH> FP_VEC;

// =============================================================================
//
// The Global level File_path, for unifying file_path from multiple .vtxt files
//
// =============================================================================
class GFP {
private:
  FID_PATH _fid_path;
  INT      _defby;    // which LNK unit defines it
  INT      _orig;
public:
  GFP(INT fid, char *path, INT defby, INT orig) : _fid_path(fid, path),
                                                  _defby(defby),
                                                  _orig(orig) {}
  ~GFP(void) {}

  INT   Fid(void)   { return _fid_path.Fid(); }
  char *Path(void)  { return _fid_path.Path(); }
  INT   Defby(void) { return _defby; }
  INT   Orig(void)  { return _orig; }
  void  Print(FILE *fp);
};

typedef vector<GFP> GFP_VEC;


extern char *Find_fpath(FP_VEC& fid_path, int fid);
extern INT   Find_fid(FP_VEC& fid_path, char *fname);
extern INT   Find_fid_exact(GFP_VEC& fid_path, char *fname);

// =============================================================================
//
// The map table from local fid to global fid of a specific .vtxt file
//
// =============================================================================
class LOC2GLB {
private:
  INT  _loc;
  INT  _glb;
public:
  LOC2GLB(INT loc, INT glb) : _loc(loc), _glb(glb) {}
  ~LOC2GLB(void) {}

  INT  Loc(void)  { return _loc; }
  INT  Loc(INT l) { return (_loc = l); }
  INT  Glb(void)  { return _glb; }
  INT  Glb(INT g) { return (_glb = g); }
  void Print(FILE *fp);
};

typedef vector<LOC2GLB> LG_VEC;

// =============================================================================
//
// A wrapper class for LOC2GLB vector, with an identifier that could be managed
// at higher level (where we manage a list of vtxt file)
//
// =============================================================================
class LNK {
private:
  INT     _id;
  LG_VEC  _lg_vec;

public:
  LNK(INT id) : _id(id) {}
  ~LNK(void) {}

  INT     Id(void)       { return _id; }
  LG_VEC& Lg_vec(void)   { return _lg_vec; }
  void    Push_back(LOC2GLB lg) { _lg_vec.push_back(lg); }
  INT     Find_gid(INT lid);
  void    Print(FILE *fp);
};

typedef vector<LNK> LNK_VEC;

typedef enum {
  INVALID_GLBID = 0,
} GLBID_V;

// =============================================================================
//
// The global file_path with linkage interface across multiple vtxt
//
// =============================================================================
class GLB_FP {
private:
  INT      _last_glbid;           // the serial number for global file_path
  INT      _last_lnkid;
  char    *_fileattr;             // the first line contains magic and version
  BOOL     _reuse;
  GFP_VEC  _glb_fp;
  LNK_VEC  _lnk_vec;

  GFP_VEC& Glb_fp(void)           { return _glb_fp; }
  INT      New_gid(void)          { return ++_last_glbid; }
  void     Bump_reuse(void)       { ++_reuse; }
  INT      Find_gid(INT lnkid, INT lid, char *path);
  BOOL     Is_invalid(INT id)     { return id == INVALID_GLBID; }
  BOOL     Lnk_exist(INT lnkid);
  INT      Push_back(char *path, INT lnkid, INT lid);

public:
  GLB_FP(void) : _last_glbid(INVALID_GLBID),
                 _last_lnkid(0),
                 _fileattr(NULL),
                 _reuse(0) { }
  ~GLB_FP(void) {}

  LNK_VEC& Lnk_vec(void)          { return _lnk_vec; }
  INT      New_lnkid(void)        { ++_last_lnkid; return _last_lnkid; }
  INT      Last_lnkid(void)       { return _last_lnkid; }
  INT      Enter_glb_fp(INT lnkid, INT fid, char *path);
  INT      Get_glb_id(INT lnkid, INT fid);
  BOOL     All_defby(INT lnkid);
  BOOL     All_unique(void)       { return _reuse == 0; }
  void     Fileattr(char *f)      { if (_fileattr == NULL) _fileattr = f; }
  char    *Fileattr(void)         { return _fileattr; }
  void     Print(FILE *fp);
  void     Print_json(FILE *fp);
};

#endif // FILEPATH
