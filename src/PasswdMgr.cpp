#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include <random>
#include <limits>
#include <fstream>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {



}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::vector<uint8_t> passwd, salt;

   ////std::cout << "(checkUser) Checking for user " << name << "...\n";
   bool result = findUser(name, passwd, salt);

   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> usersalt; //Salt derived from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd

   //std::cout<< "\n(checkPasswd)Looking for user " << name << "\n";
   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, usersalt))
   {
      //std::cout << "\n(checkPasswd)Did not find user " << name << "\n";
      return false;
   }
      
   //std::cout << "\n(checkPasswd)Hashing password " << passwd << "\n";
   hashArgon2(passhash, usersalt, passwd, &usersalt);

   if (userhash == passhash)
   {
      //std::cout << "\n(checkPasswd)Password match!\n";
      return true;
   }
   else
   {
      //std::cout << "\n(checkPasswd)No password match...\n";
      return false;
   }
      

   
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {


   //Check if user exists
   if(!checkUser(name)) { return false; } //(user not found)

   //Create an FD to deal with the file
   // FileFD passwordFD(_pwd_file.c_str());
   // if(!passwordFD.openFile(FileFD::appendfd))
   // {
   //    std::cout << "Couldn't open file for processing.\n";
   //    return false;
   // }

   std::fstream passwordFile;
   passwordFile.open(_pwd_file.c_str());

   std::string LoginInfo = "";
   std::string line;
   
   std::cout << "Opening file " << _pwd_file << "to change " << name << "'s password...\n";
   //Until we hit the end of our old file, get each line and
   // while(passwordFD.readStr(line) > 0)
   while(getline(passwordFile, line))
   {
      std::cout << "Reading line " << line << "... ";
      //Check the username
      //If the username doesn't match,keep the current line
      if(line.compare(name) != 0)
      {
         std::cout << "No match!\n";
         LoginInfo.append(line);
         LoginInfo.append("\n"); //readStr truncates the newline, so we have to add it back
      }
      else
      { 
         std::cout << "MATCH!\n";
         //We need to write the name with a new hash
         //(hash the password)
         std::vector<uint8_t> hash;
         std::vector<uint8_t> salt;
         std::vector<uint8_t> my_salt;

         //Write user to password file
         //Convert char array to string
         std::string s_name(name);

         //Create a random salt
         createNewSalt(salt);
         //Use salt to hash password
         this->hashArgon2(hash, salt, passwd, &salt);

         //Write the name
         LoginInfo.append(name);
         LoginInfo.append("\n");

         //Write the hash and salt
         //Convert to string
         std::string hashstr(hash.begin(), hash.end());
         std::string saltstr(salt.begin(), salt.end());

         LoginInfo.append(hashstr + saltstr);
         LoginInfo.append("\n");

         //Skip the next line
         //passwordFD.readStr(line);
         getline(passwordFile, line);      
      }
   }

   //Delete our old file
   std::cout << "Deleting old file\n";
   passwordFile.close();
   //passwordFD.closeFD();
   remove(_pwd_file.c_str());

   //Create a new file
   std::cout << "Creating new file\n";
   std::ofstream newfile;
   newfile.open(_pwd_file.c_str());

   //Write our new login info to the file
   std::cout << "Writing contents to console...\n";
   std::cout << LoginInfo;
   std::cout << "Writing contents to file...\n";
   newfile << LoginInfo;
   newfile.close();

   return true;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Insert your perfect code here!
   std::string line;
   //std::cout << "(readUser) Reading user " << name << "...\n";
   //Read the file line-by-line
   while(pwfile.readStr(line) > 0) //While we still have data to read,
   {
      //std::cout << "(readUser) Reading line: " << line << "...\n";
      //If the line we just read has our username as a substring,
      if(line.find(name) != std::string::npos)
      {
         //std::cout << "(readUser) Found name " << name << "\n";

         //Read in buffer
         pwfile.readBytes(hash, hashlen);

         //Read in salt
         pwfile.readBytes(salt, saltlen);


         //Return
         return true;
      }
   }

   //If we have no more data to read and we never found the user name, return false.
   //std::cout << "(readUser)User " << name << " not found.\n";
   return false;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   int results = 0;

   // Insert your wild code here!
   //TODO: Go the end of the file? Not sure if we're in append mode, we'll see

   //Write the user name
   //std::cout << "(writeUser) Writing name " << name << "\n";
   std::vector<char> name_vector(name.begin(), name.end());
   pwfile.writeBytes(name_vector);

   //Write the hash
   pwfile.writeByte('\n');
   pwfile.writeBytes(hash);
   //std::cout << "(writeUser) Wrote " << hash.size() << " bytes for hash\n";

   //Write the salt
   pwfile.writeBytes(salt);
   pwfile.writeByte('\n');
   //std::cout << "(writeUser) Wrote " << salt.size() << " bytes for salt\n";

   //results = name.length() + hash.size() + salt.size() + 2; //including newlines
   results = (hash.size() + salt.size() + name.size() + 2);
   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation
   //std::cout << "(findUser) Attempting to find user " << name << "...\n";

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("(findUser) Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      //std::string uname;
      std::string uname(name);

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         //std::cout << "(findUser) Username " << name << " matches user " << uname << "\n";
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   //std::cout << "(findUser) User " << name << "not found.\n";
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::vector<uint8_t> *in_salt) {
   // Hash those passwords!!!!

   const int t_cost = 3; //3 iterations (default)
   const int m_cost = (1<<16); //2^12 KiB memory usage (default)
   const int p_count = 1; //One thread/no parellelism (default)
   //const int hash_length = 32; //32 bytes hash length (default)
   //const int salt_length = 16; //16 byte salt length

   uint8_t return_hash_buffer[hashlen];

   //Convert salt to buffer
   uint8_t salt_buffer[saltlen];
   std::copy(in_salt->begin(), in_salt->begin()+(saltlen-1), salt_buffer);

   auto hashresult = argon2i_hash_raw(t_cost, m_cost, p_count, in_passwd, strlen(in_passwd), salt_buffer, saltlen, return_hash_buffer, hashlen);

   //auto hashresult = argon2i_hash_raw(t_cost, m_cost, p_count, in_passwd, strlen(in_passwd), in_salt, in_salt->size(), return_hash_buffer, hash_length);
   //auto hashresult = argon2i_hash_encoded(t_cost, m_cost, p_count, in_passwd, strlen(in_passwd), in_salt, in_salt->size(), hash_length, return_hash_buffer, hash_length);

   //std::cout << "\n(hashArgon2) Computed hash: " << return_hash_buffer << " with result " << hashresult << "\n";
  
   //Convert buffers to vectors
   // std::copy(return_hash_buffer, return_hash_buffer + (hashlen - 1), ret_hash);
   // std::copy(salt_buffer, salt_buffer + (saltlen - 1), ret_salt);
   ret_hash.clear();
   ret_salt.clear();
   ret_hash = std::vector<uint8_t>(std::begin(return_hash_buffer), std::end(return_hash_buffer));
   ret_salt = std::vector<uint8_t>(std::begin(salt_buffer), std::end(salt_buffer));

}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   // Add those users!

   //Check if a user exists
   //(hash the password)
   std::vector<uint8_t> hash;
   std::vector<uint8_t> salt;
   std::vector<uint8_t> my_salt;

   

   //Find the user
   //If the user doesn't exist, then add them
   //this->hashArgon2(hash, salt, passwd, &my_salt);
   if(!findUser(name, hash, salt))
   {
      //std::cout << "(addUser)User " << name << " not found, creating new user\n";
      
      //Open password file;
      FileFD pwfile(_pwd_file.c_str());
      //Set to write
      pwfile.openFile(FileFD::appendfd);

      //Write user to password file
      //Convert char array to string
      std::string s_name(name);


      //Create a random salt
      //salt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
      createNewSalt(salt);
      //Use salt to hash password
      this->hashArgon2(hash, salt, passwd, &salt);

      this->writeUser(pwfile, s_name, hash, salt);
      //std::cout << "(addUser)User " << name << " added with unprintable hash.\n";

   }
   else
   {
      //std::cout << "(addUser)User " << name << "already exists.\n";
   }
}

void PasswdMgr::createNewSalt(std::vector<uint8_t> &salt)
{
   //Clear the vector before we fill it
   salt.clear();

   //Create a random device
   std::random_device rnd_device;
   //Specify distribution
   std::uniform_int_distribution<int> dist(0, UINT8_MAX);
   //Specify generator/engine
   std::mt19937 engine;

   for(int i = 0; i < saltlen; i++)
   {
      salt.push_back(dist(engine));
   }



}

