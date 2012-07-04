/*****************************************************************************
File:     SRL_Socket.c
Project:  Storage & Retrieval Library
Contents: Functions used to retrieve data via Sockets.

Created:  11 June 2003
Author:	  Robin Moeller <Robin.Moeller@DigitalNet.com>
		  
Last Updated:  21 January 2004

Version:  2.4

*****************************************************************************/

#include "SRL_internal.h"
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
#endif


extern int Ftp_Send(const char *cmd, char expresp, netbuf *nControl);

/*
 * Internal routine to clean up the socket
 */
void Socket_close (int sock_fd)
{
		 close (sock_fd);
}

/*
 * netread  - read len chars from the socket
 */
int netread(int handle, char *put, size_t len, int flags)
{
#ifdef WIN32
		return recv(handle, put, len, flags);
#else
		flags = flags;
    	return read(handle,put, len);
#endif

}

/*
 * netwrite - write len chars to the socket
 */
int netwrite(int handle, char *psend, size_t len, int flags)
{
#ifdef WIN32
			return send(handle, psend, len, flags);
#else
			flags = flags;
			return write(handle, psend, len);
#endif
}

/*
 * http_readline - read HTTP response/header lines if http_type is set to 
 * HTTP_HEADERS else read in the max # of chars (HTTP content body), if
 * http_type is HTTP_CONTENT_FIRST, then this is the first call to 
 * http_readline to read the content/body, otherwise, if http_type is set to 
 * HTTP_CONTENT, this is a continuation call.
 *
 * return -1 on error or bytecount
 */
int http_readline(char *buf,int max, netbuf *ctl, int http_type)
{
   int x = 0;
   int total_read = 0;
   char *end, *bp;
   int eof = 0;
	int do_flag = 1;
	int num_left;

	bp = buf;

    if (ctl->dir != HTTP_READ)
		return -1;
    if (max == 0)
		return 0;
    do
    {
    	if (ctl->cavail > 0)
    	{
         if (max > ctl->cavail && (http_type != HTTP_HEADERS))
			{
				// We're reading in the content of the URL
				// but there isn't enough left in cget
				// so copy the remaining and netread the rest
            if (http_type != HTTP_CONTENT)
            {
               memcpy (bp, ctl->cget, ctl->cavail);
               total_read += ctl->cavail;
               bp += ctl->cavail;
               num_left = max - ctl->cavail;
            }
            else
            {
               num_left = max;
            }
				do
				{
					x = netread(ctl->handle, bp, num_left, 0);
					if (x == 0 || x == -1)
					{
						return total_read;
						break;
					}
					else if (num_left > x) // got more
					{
						bp += x;
						num_left = num_left - x;
                  total_read += x;
					}
					else // done
					{
						total_read += x;
						num_left = 0;
					}
				}
				while (num_left > 0);
				break;
			}
			else
			{
				x = (max >= ctl->cavail) ? ctl->cavail : max-1;
				if (http_type == HTTP_HEADERS)
				{
					end = memccpy(bp,ctl->cget,'\n',x);
					if (end != NULL)
						x = end - bp;
               total_read += x;
				}
				else
				{
					end = memcpy(bp, ctl->cget, x);
               total_read += x;
				}
				bp += x;
				*bp = '\0';
				max -= x;
				ctl->cget += x;
				ctl->cavail -= x;
	    		break;
			}
		}
    	if (max == 1)
    	{
			*buf = '\0';
			break;
    	}
    	if (ctl->cput == ctl->cget)
    	{
			ctl->cput = ctl->cget = ctl->buf;
			ctl->cavail = 0;
			ctl->cleft = FTP_BUFSIZ; // set to 8192
    	}
		if (eof)
		{
			if (total_read == 0)
				total_read = -1;
			break;
		}
		if ((x = netread(ctl->handle, ctl->cput, ctl->cleft, 0)) == -1)
    	{
			total_read = -1;
			break;
    	}
		if (x == 0)
			eof = 1;
    	ctl->cleft -= x;
    	ctl->cavail += x;
    	ctl->cput += x;
	}
    while (do_flag);
    return total_read;
}

/*
 * read a line of text
 *
 * return -1 on error or bytecount
 */
int readline(char *buf,int max, netbuf *ctl)
{
    int x,retval = 0;
    char *end,*bp;
    int eof = 0;
	int do_flag = 1;

	bp = buf;

    if ((ctl->dir != FTP_CONTROL) && (ctl->dir != FTP_READ))
		return -1;
    if (max == 0)
		return 0;
    do
    {
    	if (ctl->cavail > 0)
    	{
			x = (max >= ctl->cavail) ? ctl->cavail : max-1;
			end = memccpy(bp,ctl->cget,'\n',x);
			if (end != NULL)
				x = end - bp;
			retval += x;
			bp += x;
			*bp = '\0';
			max -= x;
			ctl->cget += x;
			ctl->cavail -= x;
			if (end != NULL)
			{
				bp -= 2;
				if (strcmp(bp,"\r\n") == 0)
				{
					*bp++ = '\n';
					*bp++ = '\0';
					--retval;
				}
			}
	    	break;
		}
    	if (max == 1)
    	{
			*buf = '\0';
			break;
    	}
    	if (ctl->cput == ctl->cget)
    	{
			ctl->cput = ctl->cget = ctl->buf;
			ctl->cavail = 0;
			ctl->cleft = FTP_BUFSIZ; // set to 8192
    	}
		if (eof)
		{
			if (retval == 0)
				retval = -1;
			break;
		}
		if ((x = netread(ctl->handle, ctl->cput, ctl->cleft, 0)) == -1)
    	{
			retval = -1;
			break;
    	}
		if (x == 0)
			eof = 1;
    	ctl->cleft -= x;
    	ctl->cavail += x;
    	ctl->cput += x;
	}
    while (do_flag);
    return retval;
}

//
// Socket_Connect - create a TCP/IP socket connection
// Inputs:  char *host - hostname
int Socket_Connect(const char *host, ushort port)
{
    int				socket_d;
    struct			sockaddr_in sin;
    struct hostent	*phe;
    int				on=1;
    char			*lhost;

#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int WSAerr;
 
	wVersionRequested = MAKEWORD( 2, 2 );

	WSAerr = WSAStartup( wVersionRequested, &wsaData );
	if ( WSAerr != 0 ) {
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		return 0;
	}
 
	/* Confirm that the WinSock DLL supports 2.2.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.2 in addition to 2.2, it will still return */
	/* 2.2 in wVersion since that is the version we      */
	/* requested.                                        */
 
	if ( LOBYTE( wsaData.wVersion ) != 2 ||
        HIBYTE( wsaData.wVersion ) != 2 ) {
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		WSACleanup( );
		return 0; 
	}
#endif

    memset(&sin,0,sizeof(sin));
    sin.sin_family = AF_INET;
    lhost = strdup(host);

	sin.sin_port = htons(port);

    if ((sin.sin_addr.s_addr = inet_addr(lhost)) == -1)
    {
    	if ((phe = gethostbyname(lhost)) == NULL)
		{
			free(lhost);
		    return 0;
		}
    	memcpy((char *)&sin.sin_addr, phe->h_addr, phe->h_length);
    }
    free(lhost);
    socket_d = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_d == -1)
		return 0;
    if (setsockopt(socket_d,SOL_SOCKET,SO_REUSEADDR,
		   SETSOCKOPT_OPTVAL_TYPE &on, sizeof(on)) == -1)
		Socket_close(socket_d); 
    if (connect(socket_d, (struct sockaddr *)&sin, sizeof(sin)) == -1)
    {

		Socket_close(socket_d);
		return 0;
    }

    return socket_d;
}

/*
 * Ftp_OpenPort - Open a data connection for a FTP session

 *
 * return 1 if successful, 0 otherwise
 */
int Ftp_OpenPort(netbuf *nControl, netbuf **nData, int mode, int dir)
{
    int sData;
    union {
		struct sockaddr sa;
		struct sockaddr_in in;
    } sin;
    struct linger lng = { 0, 0 };
    int l;
    int on=1;
    char *cp;
    unsigned int v[6];
    netbuf *ctrl;

    if (nControl->dir != FTP_CONTROL)
		return -1;
    if ((dir != FTP_READ) && (dir != FTP_WRITE))
    {
		sprintf(nControl->response, "Invalid direction %d\n", dir);
		return -1;
    }
    if ((mode != FTP_ASCII) && (mode != FTP_IMAGE))
    {
		sprintf(nControl->response, "Invalid mode %c\n", mode);
		return -1;
    }
    l = sizeof(sin);
    memset(&sin, 0, l);
    sin.in.sin_family = AF_INET;
    if (!Ftp_Send("PASV",'2',nControl))
		return -1;
    cp = strchr(nControl->response,'(');
    if (cp == NULL)
		return -1;
    cp++;
    sscanf(cp,"%u,%u,%u,%u,%u,%u",&v[2],&v[3],&v[4],&v[5],&v[0],&v[1]);
    sin.sa.sa_data[2] = (char)v[2];
    sin.sa.sa_data[3] = (char)v[3];
    sin.sa.sa_data[4] = (char)v[4];
    sin.sa.sa_data[5] = (char)v[5];
    sin.sa.sa_data[0] = (char)v[0];
    sin.sa.sa_data[1] = (char)v[1];
    sData = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (sData == -1)
		return -1;
    if (setsockopt(sData,SOL_SOCKET,SO_REUSEADDR,
		   SETSOCKOPT_OPTVAL_TYPE &on,sizeof(on)) == -1)
	{
		Socket_close(sData);
		return -1;
    }
    if (setsockopt(sData,SOL_SOCKET,SO_LINGER,
		   SETSOCKOPT_OPTVAL_TYPE &lng,sizeof(lng)) == -1)
    {
		Socket_close(sData);
		return -1;
    }
    if (connect(sData, &sin.sa, sizeof(sin.sa)) == -1)
    {
		Socket_close(sData);
		return -1;
    }
    ctrl = calloc(1,sizeof(netbuf));
    if (ctrl == NULL)
    {
		Socket_close(sData);
		return -1;
    }
    if ((mode == 'A') && ((ctrl->buf = malloc(FTP_BUFSIZ)) == NULL))
    {
		Socket_close(sData);
		free(ctrl);
		return -1;
    }
    ctrl->handle = sData;
    ctrl->dir = dir;
    *nData = ctrl;
    return 1;
}

/*
 * Ftp_Socket_close - Socket_close an FTP data connection
 */
int Ftp_Socket_close(netbuf *nData)
{
    if (nData->buf)
    	free(nData->buf);
    shutdown(nData->handle,2);
    Socket_close(nData->handle);
	free (nData);
    return 1;
}
