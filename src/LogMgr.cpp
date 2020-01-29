#include <chrono>
#include <ctime>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <fstream>

#include "LogMgr.h"

LogMgr::LogMgr(const char *log_file)
{
  
    //Open up the log file in our FD

    LogFD = new FileFD(log_file);
    if(!LogFD->openFile(FileFD::appendfd))
    {
        //If we can't open our log file, then we have to create it.
        std::ofstream file;
        file.open(log_file);
        file.close();
        LogFD->openFile(FileFD::appendfd);
    }
    
}
LogMgr::~LogMgr()
{
    LogFD->closeFD();
}

void LogMgr::Log(const std::string message)
{  
    std::stringstream ss;

    //Get system time
    auto current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string time = ctime(&current_time);
    time.pop_back();

    ss << '[' << time << ']' << " - " << message << '\n';

    std::string log_message = ss.str();
    LogFD->writeFD(log_message);
}