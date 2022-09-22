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

#include "filepath.h"

void
FID_PATH::Print(FILE *fp)
{
  fprintf(fp, "  {\n  \"fid\": %d,\n  \"path\": \"%s\"\n  }", Fid(), Path());
}


void
GFP::Print(FILE *fp)
{
  fprintf(fp, "{Fid: %d, Defby: %d, Orig: %d, Path: %s}\n", Fid(), Defby(), Orig(), Path());
}


void
LOC2GLB::Print(FILE *fp)
{
  fprintf(fp, "{Local_fid: %d, Global_fid: %d}\n", Loc(), Glb());
}


void
LNK::Print(FILE *fp)
{
  fprintf(fp, "%sLocal (%d) to Global File_id Map\n%s", SEPARATOR_s, Id(),  SEPARATOR_s);
  LG_VEC::iterator iter;
  for ( iter = Lg_vec().begin(); iter != Lg_vec().end(); ++iter ) {
    iter->Print(fp);
  }
}



void
GLB_FP::Print(FILE *fp)
{
  GFP_VEC::iterator iter;
  fprintf(fp, "%sGlobal File_id Path Map\n%s", SEPARATOR_s, SEPARATOR_s);
  if (Glb_fp().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for ( iter = Glb_fp().begin(); iter != Glb_fp().end(); ++iter ) {
      iter->Print(fp);
    }
  }
  // print the list of local to global lnk table
  LNK_VEC::iterator iter1;
  if (Lnk_vec().size() == 0)
    fprintf(fp, "<EMPTY>\n");
  else {
    for ( iter1 = Lnk_vec().begin(); iter1 != Lnk_vec().end(); ++iter1 ) {
      iter1->Print(fp);
    }
  }
}


void
GLB_FP::Print_json(FILE *fp)
{
  if (Glb_fp().size() == 0)
    return;

  // Write fid_path part to otxt file.
  GFP_VEC::iterator iter;
  //fprintf(fp, "{\"%s\"}\n", "V");
  fprintf(fp, "{%s}\n", Fileattr());
  fprintf(fp, "[\n"); // Write "[" as the start of fid_path.
  INT linecnt = 0;
  for ( iter = Glb_fp().begin(); iter != Glb_fp().end(); ++iter ) {
    if (linecnt++ == 0) {
      fprintf(fp, "  {\n");
    }
    else {
      fprintf(fp, ",\n  {\n");
    }
    fprintf(fp, "  \"fid\": %d,\n", iter->Fid());
    fprintf(fp, "  \"path\": \"%s\"\n", iter->Path());
    fprintf(fp, "  }");
  }

  fprintf(fp, "\n]\n"); // Write "]" as the end of file_path.
}


INT
LNK::Find_gid(INT lid)
{
  INT gid = INVALID_GLBID;
  LG_VEC::iterator iter;
  for ( iter = Lg_vec().begin(); iter != Lg_vec().end(); ++iter ) {
    if (iter->Loc() == lid) {
      gid = iter->Glb();
      break;
    }
  }
  return gid;
}

// =============================================================================
//
// Find_fpath: find the full fpath in fid_path.
//             return NULL if not found
//
// =============================================================================
char *
Find_fpath(FP_VEC& fid_path, int fid)
{
  FP_VEC::iterator iter;
  char *retv = NULL;

  for ( iter = fid_path.begin(); iter != fid_path.end(); ++iter ) {
    if (iter->Fid() == fid) {
      retv = iter->Path();
      break;
    }
  }
  return retv;
}

// =============================================================================
//
// Find_fid: find the fid in fid_path.
//           return 0 if not found
//
// =============================================================================
INT
Find_fid(FP_VEC& fid_path, char *fname)
{
  FP_VEC::iterator iter;
  INT retv = 0;
  if(fname == NULL)
    return retv;
  // Add one logic to change filename to path name. Avoid one filename include another filename
  // TODO: How to support file name from windows path? "\\"
  string slash_name = string(fname);
  if ( strstr(fname, "/") == NULL) {
    slash_name = '/' + slash_name;
  }

  for ( iter = fid_path.begin(); iter != fid_path.end(); ++iter ) {
    if ( strstr(iter->Path(), slash_name.c_str()) != NULL) {
      retv = iter->Fid();
      break;
    }
  }
  return retv;
}

// =============================================================================
//
// Find_fid_exact: find the fid in the fid_path return 0 if not found
//
// =============================================================================

INT
Find_fid_exact(GFP_VEC& fid_path, char *fname)
{
  GFP_VEC::iterator iter;
  INT retv = 0;

  for ( iter = fid_path.begin(); iter != fid_path.end(); ++iter ) {
    if ( strcmp (iter->Path(), fname) == 0) {
      retv = iter->Fid();
      break;
    }
  }
  return retv;
}


// =============================================================================
//
// GLB_FP:: Enter_glb_fp enter the {fid, path} of lnkid in the global fp table
//
// =============================================================================
BOOL
GLB_FP::All_defby(INT lnkid)
{
  GFP_VEC::iterator iter;
  for ( iter = Glb_fp().begin(); iter != Glb_fp().end(); ++iter ) {
    if (iter->Defby() != lnkid)
      return FALSE;
  }
  return TRUE;
}


INT
GLB_FP::Push_back(char *path, INT lnkid, INT lid)
{
  INT gid = New_gid();
  Glb_fp().push_back(GFP(gid, path, lnkid, lid));
  return gid;
}


INT
GLB_FP::Find_gid(INT lnkid, INT lid, char *path)
{
  INT gid = INVALID_GLBID;
  // fetch the gid from lnk table lid->gid map
  LNK_VEC::iterator iter;
  for ( iter = Lnk_vec().begin(); iter != Lnk_vec().end(); ++iter ) {
    if (iter->Id() == lnkid) { // find it in the table w/ same lid
      gid = iter->Find_gid(lid);
      // return it immediately, if gid is found or not-found but query only
      if (gid != INVALID_GLBID || path == NULL)
        return gid;
      // otherwise,look up in the glb table
      gid = Find_fid_exact(Glb_fp(), path);
      // enter_lnk table if found and then return gid
      if (gid == INVALID_GLBID) {
        // the LNK has alerady exist
        // create the gid and enter it here
        gid = Push_back(path, lnkid, lid);
        // printf("create (gid:%d) for (lnkid:%d, lid:%d) with path:%s\n", gid, lnkid, lid, path);
      } else
        Bump_reuse();
      iter->Push_back(LOC2GLB(lid, gid));
      return gid;
    }
  }
  // otherwise, return invalid gid
  return gid;
}


BOOL
GLB_FP::Lnk_exist(INT lnkid)
{
  LNK_VEC::iterator iter;
  for ( iter = Lnk_vec().begin(); iter != Lnk_vec().end(); ++iter ) {
    if (iter->Id() == lnkid) { // find it in the table w/ same lnkid
      return TRUE;
    }
  }
  return FALSE;
}


INT
GLB_FP::Enter_glb_fp(INT lnkid, INT lid, char *path)
{
  if (!Lnk_exist(lnkid))
      Lnk_vec().push_back(LNK(lnkid));

  INT gid = Find_gid(lnkid, lid, path);  // does it exist in the global fp table?

  return gid;
}

// =============================================================================
//
// Get_glb_id for lid defined in the lnkid, READ ONLY
//
// =============================================================================
INT
GLB_FP::Get_glb_id(INT lnkid, INT lid)
{
  if (!Lnk_exist(lnkid))
    return INVALID_GLBID;

  INT gid = Find_gid(lnkid, lid, NULL);  // NULL serves as a flag not to enter

  return gid;
}
