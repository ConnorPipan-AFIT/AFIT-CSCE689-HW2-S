#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <sstream>
#include "TCPConn.h"
#include "strfuncts.h"

// The filename/path of the password file
const char pwdfilename[] = "passwd";
const char whitelistfilename[] = "whitelist";

TCPConn::TCPConn(LogMgr *server_log)
{

   ServerLog = server_log;
   PasswordManager = new PasswdMgr(pwdfilename);
   

}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   return _connfd.acceptFD(server);
}

/**********************************************************************************************
 * sendText - simply calls the sendText FileDesc method to send a string to this FD
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

int TCPConn::sendText(const char *msg) {
   return sendText(msg, strlen(msg));
}

int TCPConn::sendText(const char *msg, int size) {
   if (_connfd.writeFD(msg, size) < 0) {
      return -1;  
   }
   return 0;
}

/**********************************************************************************************
 * startAuthentication - Sets the status to request username
 *
 *    Throws: runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::startAuthentication() {

   //Get IP
   std::string UserIP;
   this->getIPAddrStr(UserIP);
   //std::cout << "Incoming connection from " << UserIP << "\n";
   

   //Compare IP to whitelist
   if(checkIPWhitelist(UserIP))
   {
      //Ask for username/password
      ServerLog->Log("Connection from " + UserIP + " accepted (on whitelist)");
      _status = s_username;
      
   }
   else
   {
      //IP not in whitelist, cancel connection.
      //std::cout << "Refusing connection from " << UserIP << "\n";
      ServerLog->Log("Connection from " + UserIP + " refused (not on whitelist)");
      _connfd.writeFD("This connection is not allowed.\n");
      this->disconnect();

   }

   
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   try {
      switch (_status) {
         case s_username:
            getUsername();
            break;

         case s_passwd:
            getPasswd();
            break;
   
         case s_changepwd:
         case s_confirmpwd:
            changePassword();
            break;

         case s_menu:
            getMenuChoice();

            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      //std::cout << "Socket error, disconnecting.";
      ServerLog->Log("Socket error, disconnecting client " + _username);
      disconnect();
      return;
   }

   nanosleep(&sleeptime, NULL);
}

/**********************************************************************************************
 * getUsername - called from handleConnection when status is s_username--if it finds user data,
 *               it expects a username and compares it against the password database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getUsername() {
   // Insert your mind-blowing code here
   _connfd.writeFD("Username: "); 
  getUserInput(_username);

  if(PasswordManager->checkUser(_username.c_str())) //find user = true
  {
     //std::cout << "Found user " << _username << "\n";
     _status = s_passwd;
     //_connfd.writeFD("Welcome, user!");
  }
  else
  {
     //std::cout << "Unknown user\n";
     ServerLog->Log("Username " + _username + " not recognized.");
     _connfd.writeFD("Username not recognized.\n");
     this->disconnect();
  }
  
   
}

/**********************************************************************************************
 * getPasswd - called from handleConnection when status is s_passwd--if it finds user data,
 *             it assumes it's a password and hashes it, comparing to the database hash. Users
 *             get two tries before they are disconnected
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getPasswd() {
   // Insert your astounding code here

   _connfd.writeFD("Password: "); 

   std::string password;
   getUserInput(password);

   //Check password
   bool passwordIsValid = PasswordManager->checkPasswd(_username.c_str(), password.c_str());

   _pwd_attempts = _pwd_attempts + 1;
   if(passwordIsValid)
   {
      _connfd.writeFD("Password verified. Welcome back!\n");
      sendMenu();
      ServerLog->Log("User " + _username + " has successfully logged in.");
      _status = s_menu;
   }
   else
   {
      //std::cout << "User " << _username << " attempted to log in with bad password. Attempt " << _pwd_attempts << "/" << _max_pwd_attempts << "\n";
      if(_pwd_attempts < _max_pwd_attempts)
      {
         _connfd.writeFD("Username/Password combination not recognized. Please try again.\n");
         _status = s_username;
      }
      else
      {
         //std::cout << "User " << _username << " has run out of password attempts.\n";
         std::string UserIP;
         getIPAddrStr(UserIP);
         ServerLog->Log("Failed login - too many password attempts (" + _username + ", " + UserIP + ")");
         _connfd.writeFD("You have run out of password attempts. Goodbye.\n");
         this->disconnect();
      }
      
   }

   


}

/**********************************************************************************************
 * changePassword - called from handleConnection when status is s_changepwd or s_confirmpwd--
 *                  if it finds user data, with status s_changepwd, it saves the user-entered
 *                  password. If s_confirmpwd, it checks to ensure the saved password from
 *                  the s_changepwd phase is equal, then saves the new pwd to the database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::changePassword() {
   // Insert your amazing code here

   //Get new password
   std::string password1;
   getUserInput(password1);

   _connfd.writeFD("\n Enter new password again: ");
   std::string password2;
   getUserInput(password2);

   if(password1.compare(password2) == 0)
   {
      _connfd.writeFD("\nUpdating password....\n");
      PasswordManager->changePasswd(_username.c_str(), password1.c_str());
      _connfd.writeFD("Password updated.\n");
      
   }
   else
   {
      _connfd.writeFD("\nPasswords do not match. Returning to menu.\n");
   }
   _status = s_menu;

   //

}


/**********************************************************************************************
 * getUserInput - Gets user data and includes a buffer to look for a carriage return before it is
 *                considered a complete user input. Performs some post-processing on it, removing
 *                the newlines
 *
 *    Params: cmd - the buffer to store commands - contents left alone if no command found
 *
 *    Returns: true if a carriage return was found and cmd was populated, false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getUserInput(std::string &cmd) {
   std::string readbuf;

   // read the data on the socket
   _connfd.readFD(readbuf);

   // concat the data onto anything we've read before
   _inputbuf += readbuf;

   // If it doesn't have a carriage return, then it's not a command
   int crpos;
   if ((crpos = _inputbuf.find("\n")) == std::string::npos)
      return false;

   cmd = _inputbuf.substr(0, crpos);
   _inputbuf.erase(0, crpos+1);

   // Remove \r if it is there
   clrNewlines(cmd);

   return true;
}

/**********************************************************************************************
 * getMenuChoice - Gets the user's command and interprets it, calling the appropriate function
 *                 if required.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getMenuChoice() {
   if (!_connfd.hasData())
      return;
   std::string cmd;
   if (!getUserInput(cmd))
      return;
   lower(cmd);      

   // Don't be lazy and use my outputs--make your own!
   std::string msg;
   if (cmd.compare("hello") == 0) {
      _connfd.writeFD("Hello back!\n");
   } else if (cmd.compare("menu") == 0) {
      sendMenu();
   } else if (cmd.compare("exit") == 0) {
      _connfd.writeFD("Disconnecting...goodbye!\n");
      disconnect();
   } else if (cmd.compare("passwd") == 0) {
      _connfd.writeFD("New Password: ");
      _status = s_changepwd;
   } else if (cmd.compare("1") == 0) {
      msg += "You want a prediction about the weather? You're asking the wrong Phil.\n";
      msg += "I'm going to give you a prediction about this winter. It's going to be\n";
      msg += "cold, it's going to be dark and it's going to last you for the rest of\n";
      msg += "your lives!\n";
      _connfd.writeFD(msg);
   } else if (cmd.compare("2") == 0) {
      _connfd.writeFD("42\n");
   } else if (cmd.compare("3") == 0) {
      _connfd.writeFD("That seems like a terrible idea.\n");
   } else if (cmd.compare("4") == 0) {

   } else if (cmd.compare("5") == 0) {
      _connfd.writeFD("I'm singing, I'm in a computer and I'm siiiingiiiing! I'm in a\n");
      _connfd.writeFD("computer and I'm siiiiiiinnnggiiinnggg!\n");
   } else {
      msg = "Unrecognized command: ";
      msg += cmd;
      msg += "\n";
      _connfd.writeFD(msg);
   }

}

/**********************************************************************************************
 * sendMenu - sends the menu to the user via their socket
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::sendMenu() {
   std::string menustr;

   // Make this your own!
   menustr += "Available choices: \n";
   menustr += "  1). Provide weather report.\n";
   menustr += "  2). Learn the secret of the universe.\n";
   menustr += "  3). Play global thermonuclear war\n";
   menustr += "  4). Do nothing.\n";
   menustr += "  5). Sing. Sing a song. Make it simple, to last the whole day long.\n\n";
   menustr += "Other commands: \n";
   menustr += "  Hello - self-explanatory\n";
   menustr += "  Passwd - change your password\n";
   menustr += "  Menu - display this menu\n";
   menustr += "  Exit - disconnect.\n\n";

   _connfd.writeFD(menustr);
}


/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   std::string UserIP;
   getIPAddrStr(UserIP);
   ServerLog->Log("Disconnecting user (" + _username + "," + UserIP + ')');
   _connfd.closeFD();
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connfd.isOpen();
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
void TCPConn::getIPAddrStr(std::string &buf) {
   return _connfd.getIPAddrStr(buf);
}

bool TCPConn::checkIPWhitelist(const std::string userIP)
{
   //Open up the whitelist
   FileFD whitelistFD(whitelistfilename);

   //If whitelist exists,
   if(whitelistFD.openFile(FileFD::readfd))
   {
      //Read line-by-line, see if any match our user's IP
      std::string line;
      while(whitelistFD.readStr(line) > 0)
      {
         if(line.compare(userIP) == 0)
         {
            return true;
         }
      }
      //Otherwise, there are no matches. Return false.
      return false;
   }
   else
   {
      //We don't have a whitelist, return true.
      std::cout << "Cannot open IP whitelist.\n";
      return true;
   }
   
}
