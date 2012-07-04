/*****************************************************************************
File:     SRL_http.c
Project:  Storage & Retrieval Library
Contents: Functions used to retrieve Certs & Crls via HTTP

Created:  13 August 2003
Authors:  Robin Moeller <Robin.Moeller@DigitalNet.com>
          
Last Updated:  21 January 2004

Version:  2.4

*****************************************************************************/

#include "SRL_http.h"
#ifdef WIN32
	#pragma warning(push, 3)		// Save and set warning level to 3
	#include <io.h>
	//#include <winsock2.h>
	#pragma warning(pop)			// Restore warning level
#else
	#include <unistd.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <errno.h>
	#include <ctype.h>
	#ifdef Linux
		#include <asm/byteorder.h>
	#elif defined (SunOS) || defined (SCO_SV)
		#include <sys/byteorder.h>
	#endif
	#include <netdb.h>
	#define strnicmp strncasecmp
#endif

//
// Http_Init - Might be needed for Windows NT
void Http_Init(void)
{
}

/*
 * Http_Connect - connect to remote server
 * 
 * return 1 if connected, 0 if not
 */
int Http_Connect(const char *host, int port)
{
	int socket_d = 0;

	socket_d = Socket_Connect(host, port);
	if (socket_d > 1)
		return socket_d;
	else 
		return 0;
}

/*
 * Http_Send - send a command
 *
 * return 1 if successful , 0 if not
 */
static int Http_Send (char *cmd, int socket_d)
{
	unsigned int cmd_len;
	cmd_len = (unsigned int)strlen(cmd);
	if (netwrite(socket_d, cmd, cmd_len, 0) <= 0)
		return 0;
	else
		return 1;
}


/*
 * Http_Get - Retrieve the specified URL
 *
 * Return SRL_LDAP_SEARCH_FAILED if connection to ftp fails
 * Return SRL_SUCCESS or SRL_NOT_FOUND if file was retrieved or not found
 */
short Http_Get(const char *host, const char *path, Bytes_struct *inBuf, int socket_d)
{
	char	cmd[HTTP_BUF_MAX];
	int		send_stat = 0;

	short	status;

	// Build retrieval command and send
	// Command should be the following format:
	// GET /path HTTP1.1CRLF
	// HOST: hostCRLFCRLF

    sprintf(cmd, "GET /%s %s\r\n%s%s\r\n\r\n", path, HTTP_VERSION, HTTP_HOST,
            host);

	if ((send_stat = Http_Send(cmd, socket_d)) == 1)
		status = processHttpResponse(inBuf, socket_d);
	else
		status = SRL_TCP_CONNECTION_FAILED;
	return(status);

}

/*
 * processHttpResponse - Process HTTP response
 * 
 * return SRL_SUCCESS if found or not found
 * or SRL_MEMORY_ERROR if memory problem
 * or SRL_LDAP_SEARCH_FAILED if other problems
 */
static short processHttpResponse(Bytes_struct *inBuf, int socket_d)
{
	char	header_buf[HTTP_BUF_MAX];
	short	status = 0;
	int	    status_code;
	int     first = 1;
	int		len;
	long	content_length = 0;
	netbuf	*ctrl;

	ctrl = calloc(1,sizeof(netbuf));
	if (ctrl == NULL)
		return SRL_MEMORY_ERROR;
	ctrl->buf = malloc(FTP_BUFSIZ);
	if (ctrl->buf == NULL)
	{
		free (ctrl);
		return SRL_MEMORY_ERROR;
	}
	ctrl->handle = socket_d;
	ctrl->dir = HTTP_READ;

	// Read in a line at a time to process response headers
	// the content body is read in processContent
	while((len = 
          http_readline(header_buf, HTTP_BUF_MAX, ctrl, HTTP_HEADERS)) > 0)
	{
		// HTTP spec requires that we ignore leading empty lines
		// before the response line
		if (first)
		{
			if (header_buf[0] == '\r' && header_buf[1] == '\n')
				continue; // skip to next line
			else
			{
				status_code = processResponseLine(header_buf);
				if (status_code == HTTP_NOT_FOUND)
				{
					// Not found is considered success
					status = SRL_SUCCESS;
					break;
				}
				else if (status_code == HTTP_OK || status_code == HTTP_CONTINUE)
				{
					first = 0;
					continue;
				}
				else 
            {
					status = SRL_HTTP_ERROR;
					break;
				}
			}
		}
		// After the response and headers, a CRLF should occur
		if (header_buf[0] == '\r' && header_buf[1] == '\n')
		{
			// Next lines should contain the content
			if (content_length > 0)
			{
				status = processContent(content_length, inBuf, ctrl);
				break;
			}
			else 
			{
            // We don't know the content length read until 
            // we get a network error
            status = processContent (-1, inBuf, ctrl);
				break;
			}
		}
		else
		{
			// Process header line if content_length not found yet
			// else ignore the line
			if (content_length == 0)
				content_length = processHeaderLine(header_buf);
			if (content_length == -1) 
			{
				// Response sent back in "chunks" - Not supported
				status = SRL_HTTP_ERROR;
				break;
			}
		}
	}
	
	if (ctrl->buf)
		free (ctrl->buf);
	free (ctrl);
	return status;

}

/*
 * processContent - Get the body of the HTTP message
 *
 * return SRL_SUCCESS if read in correctly
 *        SRL_MEMORY_ERROR if memory problems
 *        SRL_LDAP_SEARCH_FAILED if entire file couldn't be read in
 */

static short processContent(long content_length, Bytes_struct *inbuf, netbuf *ctl)
{
	short status;
	int chars_read = 0;
   long buffer_len = 102400;
   char *readbuf;
   uchar *bp;

   if (content_length == -1)
   {
      // We have a Response without Content-Length
      // We want to read in 100K at a time
      readbuf = malloc ((buffer_len + 1) * sizeof (char));
      if (readbuf == NULL)
      {
         status = SRL_MEMORY_ERROR;
         return status;
      }
      inbuf->data = NULL;
      inbuf->num = 0;
      // Read in the netbuf again:
      ctl->cput = ctl->cput - ctl->cavail;
      if ((chars_read =
           http_readline (readbuf, buffer_len, ctl, HTTP_CONTENT_FIRST)) > 0)
      {
         inbuf->data = malloc (chars_read * sizeof (char));
         memcpy (inbuf->data, readbuf, chars_read);
         inbuf->num += chars_read;
      }
      while ((chars_read =
              http_readline (readbuf, buffer_len, ctl, HTTP_CONTENT)) > 0)
      {
         inbuf->data = realloc (inbuf->data, (inbuf->num + chars_read) *
                                sizeof (char));
         bp = inbuf->data + inbuf->num;
         memcpy (bp, readbuf, chars_read);
         inbuf->num += chars_read;
         if (chars_read < buffer_len)
            break;
      }
      status = SRL_SUCCESS;

   }
   else
   {
      inbuf->data = malloc(content_length+1);
      inbuf->num = content_length;
      if (inbuf->data != NULL)
      {
         chars_read = http_readline((char*)inbuf->data, content_length,
                                           ctl, HTTP_CONTENT_FIRST);
         if (chars_read == content_length)
            status = SRL_SUCCESS;
         else
         {
            status = SRL_HTTP_ERROR;
            free (inbuf->data);
            inbuf->data = NULL;
            inbuf->num = 0;
         }
      }
      else
      {
         status = SRL_MEMORY_ERROR;
         free (inbuf->data);
         inbuf->data = NULL;
         inbuf->num = 0;
      }
   }
   return status;
}


/*
 * processResponseLine - Process HTTP response status line
 *
 * return the HTTP status code or -1 if failure
 */
static int processResponseLine(const char *response_buf) 
{
	
	char status_code[4];
	const char *buf;

	// Response header has the following format
	// HTTP/#.# StatusCode Reason

	buf = response_buf;

	// Find HTTP Version string - Could be 1.1, 1.0
	// So just look for HTTP/
	if ( strstr( buf, HTTP_VERSION_SLASH) != NULL )
	{
		buf += HTTP_VERSION_SLASH_LEN;
		// Skip until whitespace encountered then skip whitespace
		for (buf; *buf != ' '; buf++);
		buf++;
		strncpy(status_code, buf, 3);
		status_code[3] = '\0';
		return (atoi(status_code));
	}
	else
		return -1;
}
	
/*
 * processHeaderLine - Process HTTP header lines
 * 
 * return 0 if header we don't care about
 * return -1 if we get the Transfer-Encoding header (chunked)
 * return size of content if given
 */
static long processHeaderLine(char *header_buf) 
{

	char	header_value[HTTP_CONTENT_LENGTH_SIZE];
	char	*buf;
	int		i;
	long	content_len = 0;

	buf = header_buf;

	// Headers have the following format:
	// <header type>: value [, value, value]
	// They are case insensitive
	//
	// If header line is the Content-Length header
	// return the content_len
	// Else if header line is the Transfer-Encoding: Chunked header
	// return -1  -  This is not supported
	// Else return 0 - Ignore this line

	// If this header is a content header 
    // Check to see if it's content-length

	if (strnicmp(buf, HTTP_CONTENT_LENGTH_HDR, HTTP_CONTENT_LEN_HDR_LEN) == 0)
	{
		buf += HTTP_CONTENT_LEN_HDR_LEN;
		// skip past all whitespace and copy the value
		for (buf; *buf == ' ';buf++);
		// Copy until whitespace or CR
		for (buf, i = 0; *buf != ' ' && *buf != '\r'; buf++, i++)
			header_value[i] = *buf;
		header_value[i] = '\0';

		content_len = atol(header_value);
	}
	else if (strnicmp (buf, HTTP_TRANSFER_ENC_HDR, HTTP_TRANSFER_ENC_HDR_LEN)== 0)
	{
		// Check value and determine if it's chunking
		buf += HTTP_TRANSFER_ENC_HDR_LEN;
		if (strstr(buf, HTTP_CHUNK_VALUE) != NULL)
		{
			// The response is being sent in chunks
			// Not supported at this time
			content_len = -1;
		}
		else
			content_len = 0;
	}
	else
		content_len = 0; // Ignore this header
	return content_len;
}
	
//
// Http_Quit - Close up socket
//
void Http_Quit (int socket_d)
{

	Socket_close(socket_d);
#ifdef WIN32
	// Clean up for windows
	WSACleanup();
#endif
}
