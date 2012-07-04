//////////////////////////////////////////////////////////////////////////////
// aclconfigfile.cpp
// These routines support the ConfigFile Class
// CONSTRUCTOR(s):
//   ConfigFile()
//   ConfigFile(char *fn)
// DESTRUCTOR:
//   ~ConfigFile()
// MEMBER FUNCTIONS:
//   setSection(char *section)
//   seekToSection(char *section)
//   getNextLine(char line[])
//   GetKwValue (Keyword keyword, KwValue destStr, char *section)
//   GetGlobalKwValue(char *keyword, KwValue destStr)
//////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aclinternal.h"

_BEGIN_NAMESPACE_ACL

// CONSTRUCTOR:
//
ConfigFile::ConfigFile()
{
   m_pSection = NULL;
   fp = NULL;
   m_bSeekToTop = true;
} // END OF CONSTRUCTOR

// ALTERNATE CONSTRUCTOR:
//
ConfigFile::ConfigFile(char *fn)
{
   FUNC("ConfigFile::ConfigFile(char *fn)");
   try
   {
       m_pSection = NULL;
       seekToTop(true);
       fp = fopen(fn, "r");

       if (fp == NULL)
          throw ACL_EXCEPT(-1, "Can't open config file");
   }
   catch (SNACC::SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF ALTERNATE CONSTRUCTOR

// setSection:
//
void ConfigFile::setSection(char *section)
{
   if (m_pSection)
      free(m_pSection);
   m_pSection = strdup(section);
} // END OF MEMBER FUNCTION setSection

// DESTRUCTOR:
//
ConfigFile::~ConfigFile()
{
   fclose(fp);
   if (m_pSection)
      free(m_pSection);
} // END OF DESTRUCTOR

// seekToSection:
//
bool ConfigFile::seekToSection(char *section)
{
   char *sect_with_brackets = NULL;
   bool sectionFound = false;
   char line[ACL_MAX_LINE_LEN];

   sect_with_brackets = (char *) calloc(1, strlen(section) + 3);
   sprintf(sect_with_brackets,"[%s]", section);

   if (seekToTop())
      fseek(fp, 0, SEEK_SET);

   while (! feof(fp) && ! sectionFound )
   {
      fgets(line, ACL_MAX_LINE_LEN, fp);

      if (line[0] == '[')
      {
         if (strstr(line, sect_with_brackets) != NULL)
         {
            sectionFound = true;
            setSection(section);
         }
      }
   }
   if (sect_with_brackets)
   {
      free(sect_with_brackets);
   }
   return sectionFound;
} // END OF MEMBER FUNCTION seekToSection

// getNextLine:
// returns the next line that is not a comment or whitespace
//
bool ConfigFile::getNextLine(char line[])
{
   bool lineFound = false;
   int i = 0;

   while (! feof(fp) && ! lineFound)
   {
      fgets(line, ACL_MAX_LINE_LEN, fp);

      // strip trailing whitespace
      for (i = (strlen(line) - 1); line[i] == 0x0A || line[i] == 0x20 || line[i] == 0x0D; i--)
          line[i] = '\0';

      if (line[0] != '\0' && line[0] != '#' && line[0] != ';'
         && line[0] != '[')
      {
         lineFound=true;

      }
   }
   return lineFound;
} // END OF MEMBER FUNCTION getNextLine

//
// FUNCTION: GetKwValue()
//
// AUTHOR: Pierce Leonberger/VDA
//
// PURPOSE: get the value of the keyword from the configuration file (set
//          previously by the SetCfgFn() function) in the specified
//          section.  If the section is not provided (a NULL is passed in
//          it's place) it will look for keywords only and will abort it's
//          search when the keyword is found or a section is encountered
//          in the configuration file.
//
// FORMAT RULES:
// 1) no spaces between <keyword> and "=", or between "=" and <value>, or
//    after <value>.  Any white space or comments entered after <value> will
//    be stripped.
//
// 2) any line that has a "#" or ";" as the first character will be considered
//    a comment and ignored.
//
// 3) Comments can be added on the same line as the keyword value by placing
//    one of the comment indicators (';' or '#') and entering the comments
//    to the right of the indicator.
//
// NOTE:
//    It is assumed that the configuration file <filename> is in the
//    current directory.  If you want to specify a path you must include
//    it as part of <filename> when you call SetCfgFn().
//
// RETURN VALUES:
//                error condition return codes
//                ----------------------------
//                -2 section was specified and not found
//                -1 parameters missing
//
//                successful return codes
//                -----------------------
//                 0 success
//                 1 keyword not found
//
int ConfigFile::GetKwValue (Keyword keyword, KwValue destStr, char *section)
{
    char *sect_with_brackets = NULL;
    char line[ACL_MAX_LINE_LEN];
    int  found = 0;
    int  error = 0; // default error code to successful

    // check if keyword or destStr is null
    if (! keyword || ! destStr )
    {
        printf("GetKwValue: keyword or destination string not present!!\n");
        return (-1);
    }

   // if seekToTop is set then seek to the beginning in case we aren't already
   // there.
   //
   if (seekToTop())
   {
      fseek(fp,0L,SEEK_SET);
   }
   if (section == NULL && m_pSection != NULL)
      section = m_pSection;

    // if requested find the appropriate section first
    if (section != NULL)
    {
        sect_with_brackets = (char *) calloc(1, strlen(section) + 3);
        sprintf(sect_with_brackets,"[%s]", section);

        found = 0;
        while (! feof(fp) && ! found)
        {
            fgets(line, ACL_MAX_LINE_LEN, fp);
            if (! feof(fp) && line[0] == '[')
            {
                if (strstr(line, sect_with_brackets) != NULL)
                {
                   seekToTop(false);
                   found = 1;
                   if (section != m_pSection)
                      setSection(section);
                }
            }
        }
        if (!found)
            error = -2;       // section not found error
    }

    // If the section was not specified or it was specified and found check
    // for the keyword.
    //
    if (! error)
    {
       error = GetGlobalKwValue(keyword, destStr);
       if (found)
          seekToTop(true);
    }
    if (sect_with_brackets)
       free(sect_with_brackets);

    return error;
} // END OF MEMBER FUNCTION GetKwValue

// GetGlobalKwValue:
//
// Finds the first keyword value for specified keyword that occurs before the
// first section.  For example:
//
// keyword1=value1
// keyword2=value2
// [FirstSection]
//
// The search aborts at "FirstSection".
//
int ConfigFile::GetGlobalKwValue(char *keyword, KwValue destStr)
{
   Keyword tmp_kw;
   char *strPtr = NULL;
   char *p;                    // used for stripping comments from a line
   char line[ACL_MAX_LINE_LEN];
   int  found = 0;
   int  error = 0; // default error code to successful

   // if seekToTop is set then seek to the beginning in case we aren't already
   // there.
   //
   if (seekToTop())
   {
      fseek(fp,0L,SEEK_SET);
   }

   sprintf(tmp_kw,"%s=", keyword);
   while (! feof(fp) && ! found)
   {
      fgets(line, ACL_MAX_LINE_LEN, fp);

      if (!feof(fp) && line[0] != '#' && line[0] != ';' && line[0] != '[')
      {
          if ((strPtr = strstr(line, tmp_kw)) == line)
              found = 1;
      }
      else if (line[0] == '[') // stop when next section has been reached
          break;
   }

   if (found)
   {
      strPtr = strchr(strPtr, '=') + 1;

      // If there is not a comment then start stripping
      // whitespace from the end of the keyword value.  If a comment is
      // present then the strchr() will return a non-null pointer and
      // the white and comments will be stripped starting at the
      // beginning of the comment.
      //
      if ((p  = strchr(strPtr, '#')) == NULL &&
          (p  = strchr(strPtr, ';')) == NULL)
          p = strPtr + (strlen(strPtr) - 1);   // minus 1 cuz of newline

      // strip whitespace and any comments that may exist
      while ( *p == ' ' || *p == '\t' || *p == '\n' || *p == '#' ||
          *p == ';')
          *p-- = '\0';

      strncpy(destStr, strPtr, strlen(strPtr));
      destStr[strlen(strPtr)] = '\0';
   }
   else
   {
      error = 1; // keyword not found error
   }

   return error;
} // END OF MEMBER FUNCTION GetGlobalKwValue

_END_NAMESPACE_ACL

// EOF aclconfigfile.cpp
