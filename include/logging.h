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
// Module: logging.h
//
// ====================================================================
//


/*  API and calling sequence */
/*                           */
//  1. Declare a "log" object" (say, logger)
//  2. Decide the name of the log file (we assume .log as file extension
//  3. Convention:  always write to the log file
//                  if need to write to stdout also, add -d in option or
//                     set Debug_log()
//                  add "path" with option -p pathname or
//                     default path is "/tmp/"
//                  log file name is "path"+"file_name"
//  4. Set name of your "component" e.g. v2csf
//  5. Calling sequence:
//     logger.Open_log (char *logfile, char *component_name) 
//  6. logger.Write_log(Log_lvl, char *message)
//  7. logger.Close_log(void)
//
//  A runnable example can be found at end of this file
//

#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include "commondefs.h"

#ifndef ASSERT
#define ASSERT assert
#define ERROR  handle_error
void handle_error(char *s)
{
  fprintf(stderr, "Fatal: %s\n", s);
  exit(1);
}
#include <assert.h>
#endif


using namespace std;

#ifndef NULL
#define NULL       '\0'
#endif


//
// individual log related
//


#define   LOG_STR_SZ      (5)   // max 5 chars in log format except msg and fname
#define   MAX_MSG_SZ      (30)  // max 30 chars in the message part of log

class LOG_MSG {
  INT        _lvl;
  char*      _ifname;      // name that identifies the processing/task at hand
                        
  char  _msg[MAX_MSG_SZ];  // use snprintf to fill this instance as last part of log
                           // msg for this log is no more than MAX_MSG_SZ chars 
public:

  void       Msg(char* s)       { ASSERT((s != 0));  memcpy(_msg, s, MAX_MSG_SZ); }
  char*      Msg(void)          { return _msg; }
};


typedef enum Log_lvl {
  _TRACE     = 0,
  _DEBUG     = 1,
  _INFO      = 2,
  _WARNING   = 3,
  _ERROR     = 4,
  _FATAL     = 5,
  _MAX_LVL   = 6,
} LOG_LVL;

typedef struct {
  LOG_LVL     _lvl;
  const char *_lname;
} LVL_ID;


  static char SVCNAME[10]  = "V2CSF"; // 6 chars, need to modify for specific service
  static char FNAME[10]    = "V2CSF.log";
#define LOGNAME_SZ (12)
  static char DEF_PATH[5]  =   "/tmp";


//
// log file set up
// stdout is always log output.
// Must call Open_log(path) to write to a specific path
//     otherwise, always write to /tmp
// Must call Close_log() to guarantee final flushing and log file integrity
//
class LOG {
  BOOL    _log_in_file;   // put log in file
  BOOL    _debug_log;     // also output to stdout when true
  LOG_MSG _logmsg;        // one log message
  char*   _path;          // path to log
  char*   _logname;       // log file name (specific per service)
  char    _svcname[10+1]; // name of this service
  FILE*   _fp;            // file pointer to the log file
  LVL_ID  _lvl_id[_MAX_LVL];

public:
  const char*   Lvlname(Log_lvl lvl){ ASSERT(lvl < (LOG_LVL)_MAX_LVL);
                                return _lvl_id[lvl]._lname; }
  void    Log_in_file(void)   { _log_in_file = false; }  // always turn off log with this
  void    Debug_log(void)     { _debug_log = true; }
  BOOL    Is_debug_log(void)  { return _debug_log; }
  void    Path(char *p)       { ASSERT(p != NULL); _path = p; }
  void    Logfp(FILE *f)      { _fp = f; }
  FILE*   Logfp(void)         { return _fp; }
  FILE*   Open_log(char*, char *);
  void    Close_log(void);
  void    Write_log(Log_lvl, char *);
  LOG() : _fp(0), _debug_log(false) {
    _lvl_id[_TRACE]   = { _TRACE,   "TRACE" };
    _lvl_id[_DEBUG]   = { _DEBUG,   "DEBUG" };
    _lvl_id[_INFO]    = { _INFO,    "INFO"  };
    _lvl_id[_WARNING] = { _WARNING, "WARN"  };
    _lvl_id[_ERROR]   = { _ERROR,   "ERROR" };
    _lvl_id[_FATAL]   = { _FATAL,   "FATAL" };
  }
  ~LOG() { Close_log(); }
};

FILE *LOG::Open_log(char* path, char* sname)
{
  ASSERT(sname != 0);

  int i = strlen(sname);
  if (i == 0) {
    ERROR((char*)"service name empty\n");
    exit(1);
  }

  int j;
  for (j = 0; j < 10; j++) {
    _svcname[j] = sname[j];
  }
  _svcname[j+1] = '\0';
    
  if (path == 0) {
    // use default tmp dir
    path = DEF_PATH;
  }
  _path = path;

  _logname = (char *)malloc(strlen(path)+strlen(FNAME)+1+1);  // "/" for path/name
  if (_logname == NULL) {
    return 0; // fail to open file, caller must handle null return
  }
  _logname =(char *) memcpy(_logname, path, strlen(path)+strlen(FNAME)+1);
  _logname = strcat(_logname, "/");
  _logname = strcat(_logname, FNAME);
  _fp = fopen(_logname, "w");
  if (_fp == 0) {
    ERROR((char*)"file open error\n");
  }
  _log_in_file = true;
  return _fp;  
}


void LOG::Close_log()
{
  ASSERT(Logfp());
  (void)fflush(_fp);
  (void)fclose(_fp);
  Logfp(NULL);
  free(_logname);
}

void LOG::Write_log(Log_lvl l, char *messg)
{
  struct tm* ptm;
  char   timestr[26];
  struct timeval tv;

  gettimeofday(&tv, NULL);
  
  int millisec = lrint(tv.tv_usec/1000.0); // round to millisec
  if (millisec >= 1000) { // allow to round up to nearest sec
    millisec -= 1000;
    tv.tv_sec++;
  }
  ptm = localtime(&tv.tv_sec);  
  strftime(timestr, 26, "%Y-%m-%d %H:%M:%S", ptm);
  
  fprintf(Logfp(), "%s.%03d ", timestr, millisec);
  fprintf(Logfp(), " %5s", _lvl_id[l]._lname);
  fprintf(Logfp(), " %-10s : ", _svcname);
  if (messg) // in case messg is null
    fprintf(Logfp(), "%s\n", messg);
  
 if (Is_debug_log()) {
  fprintf(stdout, "%s.%03d ", timestr, millisec);
  fprintf(stdout, " %5s", _lvl_id[l]._lname);
  fprintf(stdout, " %-10s:", _svcname);
  if (messg)  // in case messg is null
    fprintf(stdout, "%s\n", messg);
  }
}


//
// below is sample use that is runnable
//
#ifdef MAIN
int main(int argc, char **argv)
{
  char *logfile = 0;
  bool use_log_file = true;
  int i = 1;
  LOG  logger;
  if (argc < 2) {
    fprintf(stderr, "log [-p path]|[-d]\n");
    exit(0);
  }
  do {
    if (argv[i][0] == '-') {
      if ((argv[i][1] == 'p')) {
	if (argc < 3) {
	  fprintf(stderr, "missing path\n");
	  exit(1);
	}
	logfile = &(argv[i+1][0]);
	argc -= 2;
	i += 2;
      }
      else if (argv[i][1] == 'd') {
	logger.Debug_log();
	argc--;
	i++;
      }
      
    }
  } while (argc >= 2);

  logger.Open_log(logfile, (char*)"TLOGgEr");
  logger.Write_log(_TRACE, (char*)"Testing1");
  logger.Write_log(_FATAL, (char*)"TESTING fatal");
  logger.Write_log(_INFO, (char*)"Test info -----------end-info");
    
}

#endif

#endif // LOGGING_H
