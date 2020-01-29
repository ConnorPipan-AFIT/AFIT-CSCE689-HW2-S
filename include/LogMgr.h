#pragma once

#include "FileDesc.h"

class LogMgr
{
public:

    LogMgr(const char *log_file);
   ~LogMgr();

   void Log(const std::string message);


private:

    FileFD *LogFD;

};