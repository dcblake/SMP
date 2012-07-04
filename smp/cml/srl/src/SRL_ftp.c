/*****************************************************************************
File:     SRL_ftp.c
Project:  Storage & Retrieval Library
Contents: Functions used to retrieve data via FTP.

Created:  11 June 2003
Authors:  Robin Moeller <Robin.Moeller@DigitalNet.com>
		  
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


extern void Socket_close(int sock_fd);
extern int netread(int handle, char *put, size_t len, int flags);
extern int netwrite(int handle, char *psend, size_t len, int flags);
extern int readline(char *buf, int max, netbuf *ctl);
extern int Socket_Connect(const char *host, int port);
extern int Ftp_OpenPort(netbuf *nControl, netbuf **nData, int mode, int dir);
extern int Ftp_Socket_close(netbuf *nData);


/* Set to 1 to debug */

int debug_lib = 0;

// Linked list to hold file since
// ftp doesn't tell us the size
// up front

struct ftpbuf {
	unsigned char *buf;
	unsigned int len;
	struct ftpbuf *next;
};

/*
 * read a response from the server
 *
 * return 0 if first char doesn't match
 * return 1 if first char matches
 */
static int readresp(char c, netbuf *nControl)
{
    char match[5];
    if (readline(nControl->response,256,nControl) == -1)
		return 0;
    if (debug_lib > 1)
		fprintf(stderr,"%s",nControl->response);
    if (nControl->response[3] == '-')
    {
		strncpy(match,nControl->response,3);
		match[3] = ' ';
		match[4] = '\0';
		do
		{
			if (readline(nControl->response,256,nControl) == -1)
				return 0;
			if (debug_lib > 1)
				fprintf(stderr,"%s",nControl->response);
		}
		while (strncmp(nControl->response,match,4));
    }
    if (nControl->response[0] == c)
		return 1;
    return 0;
}


/*
 * Ftp_Init for stupid operating systems that require it (Windows NT)
 */
void Ftp_Init(void)
{
	/* Might not be needed with WIN32 */
}
/*
 * Ftp_LastResponse - return a pointer to the last response received
 */
char *Ftp_LastResponse(netbuf *nControl)
{
    if ((nControl) && (nControl->dir == FTP_CONTROL))
    	return nControl->response;
    return NULL;
}


/*
 * Ftp_Connect - connect to remote server
 *
 * return 1 if connected, 0 if not
 */
int Ftp_Connect(const char *host, int port, netbuf **nControl)
{
	int		socket_d = 0;
    netbuf	*ctrl;

    socket_d = Socket_Connect(host, port);
	if (socket_d > 0)
	{
		// allocate and fill in netbuf structure

		ctrl = calloc(1,sizeof(netbuf));
		if (ctrl == NULL)
		{

			Socket_close(socket_d);
			return 0;
		}
		ctrl->buf = malloc(FTP_BUFSIZ);
		if (ctrl->buf == NULL)
		{

			Socket_close(socket_d);
			free(ctrl);
			return 0;
		}
		ctrl->handle = socket_d;
		ctrl->dir = FTP_CONTROL;
		if (readresp('2', ctrl) == 0)
		{

			Socket_close(socket_d);
			free(ctrl->buf);
			free(ctrl);
			return 0;
		}
		*nControl = ctrl;
		return 1;
	}
	else
		return 0;
}


/*
 * Ftp_Send - send a command and wait for expected response
 *
 * return 1 if proper response received, 0 otherwise
 */
int Ftp_Send(const char *cmd, char expresp, netbuf *nControl)
{
    char buf[256];
    if (nControl->dir != FTP_CONTROL)
	return 0;
    if (debug_lib > 2)
		fprintf(stderr,"%s\n",cmd);
    sprintf(buf,"%s\r\n",cmd);
	if (netwrite(nControl->handle,buf,strlen(buf), 0) <= 0)
		return 0;
    return readresp(expresp, nControl);
}


/*
 * Ftp_Login - log in to remote server
 *
 * return 1 if logged in, 0 otherwise
 */
int Ftp_Login(const char *user, const char *pass, netbuf *nControl)
{
    char tempbuf[64];

    sprintf(tempbuf,"USER %s",user);
    if (!Ftp_Send(tempbuf,'3',nControl))
    {
		if (nControl->response[0] == '2')
			return 1;
		return 0;
    }
    sprintf(tempbuf,"PASS %s",pass);
    return Ftp_Send(tempbuf,'2',nControl);
}


/*
 * Ftp_Access - return a handle for a data stream
 *
 * return 1 if successful, 0 otherwise
 */
int Ftp_Access(const char *path, int mode, netbuf *nControl,
    netbuf **nData)
{
    char buf[256];
    int dir;
    if (path == NULL)
    {
		sprintf(nControl->response, "Missing path argument for file transfer\n");
		return 0;
    }
     sprintf(buf, "TYPE %c", mode); 
    if (!Ftp_Send(buf, '2', nControl))
		return 0;

	strcpy(buf,"RETR");
	dir = FTP_READ;
	
    if (path != NULL)
		sprintf(buf+strlen(buf)," %s",path);
    if (Ftp_OpenPort(nControl, nData, mode, dir) == -1)
		return 0;
    if (!Ftp_Send(buf, '1', nControl))
    {
		Ftp_Socket_close(*nData);
		*nData = NULL;
		return 0;
    }
    return 1;
}


/*
 * Ftp_Read - read from a data connection
 */
int Ftp_Read(void *buf, int max, netbuf *nData)
{
    if (nData->dir != FTP_READ)
		return 0;
    if (nData->buf)
    	return readline(buf, max, nData);
	return netread(nData->handle, buf, max, 0);

}


/*
 * addFtpBuf - Add new buffer to the linked list
 */
static int addFtpBuf(struct ftpbuf** headRef, char *newBuf, int len) 
{
	struct ftpbuf* newNode;
	
	newNode = (struct ftpbuf*) malloc(sizeof(struct ftpbuf));
	newNode->buf = (unsigned char *)calloc(1,len); 
	if (newNode->buf == NULL) {
		free (newNode);
		return 0;
	}
	memcpy(newNode->buf,newBuf, len); // put in the data
	newNode->len =  len;
	newNode->next = (*headRef); // link the old list off the new node
	(*headRef) = newNode; // move the head to point to the new node
	return 1;
}

/*
 * freeFtpBuf - Free the linked list
 */
static void freeFtpBuf(struct ftpbuf *head)
{
	struct ftpbuf *curr, *q;

	curr = head;
	while (curr)
	{
		q = curr->next;
		free (curr->buf);
		free (curr);
		curr = q;
	}
}
	
/*
 * Ftp_Xfer - issue a command and transfer data
 *
 * return SRL_SUCCESS if successful,  otherwise
 */
static short Ftp_Xfer(const char *path, Bytes_struct *inBuf,
	netbuf *nControl, int mode)
{
    int len = 0, totlen = 0, status = 0;
    char dbuf[FTP_BUFSIZ];
	struct ftpbuf *tail = NULL, *head = NULL;
	struct ftpbuf *curr;
    netbuf *nData;

    inBuf->num = 0;
	
    if (!Ftp_Access(path, mode, nControl, &nData))
		return SRL_TCP_CONNECTION_FAILED;
 
    while ((len = Ftp_Read(dbuf, FTP_BUFSIZ, nData)) > 0)
	{
		if (totlen == 0)
		{
			status = addFtpBuf(&head, dbuf, len);
			if (status == 0)
				return SRL_MEMORY_ERROR;
			tail = head;
			totlen = len;
		}
		else
		{		
			status = addFtpBuf(&(tail->next), dbuf, len); 
			if (status == 0)
				return SRL_MEMORY_ERROR;
			tail = tail->next; 
			totlen += len;
		}		
	}

	// Copy ftpData to inbuf->buf
	inBuf->data = (unsigned char *) calloc (1, totlen);
	if (inBuf->data == NULL)
	{
		// Could not allocate memory
		// Free fp & return 0
		freeFtpBuf(head);
		return SRL_SUCCESS;
	}

	inBuf->num = 0;
	len = 0;
	curr = head;
	while(curr != NULL)
	{
		memcpy(inBuf->data+len, curr->buf, curr->len);
		inBuf->num += curr->len;
		len = curr->len;
		curr = curr->next;
	}
    freeFtpBuf(head);
    Ftp_Socket_close(nData);

	if (readresp('2', nControl))
		return SRL_SUCCESS;
	else
		return SRL_FTP_ERROR;
}


/*
 * Ftp_Get - Get the file from ftp
 *
 * 1 is returned if successful, 0 if not
 */
short Ftp_Get(const char *path,
	char mode, netbuf *nControl, Bytes_struct *inBuf)
{
	short status;
	status = Ftp_Xfer(path, inBuf, nControl, mode);
    return status;
}

/*
 * Ftp_Quit - disconnect from remote
 *
 * return 1 if successful, 0 otherwise
 */
 void Ftp_Quit(netbuf *nControl)
{
    if (nControl->dir != FTP_CONTROL)
		return;
    Ftp_Send("QUIT",'2',nControl);
    Socket_close(nControl->handle);
    free(nControl->buf);
    free(nControl);
#ifdef WIN32
	// Clean up for windows
		 WSACleanup ();
#endif
}

