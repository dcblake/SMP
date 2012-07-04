/*****************************************************************************
File:     SRL_http.h
Project:  Storage & Retrieval library
Contents: Header file for the Storage & Retrieval library

Created:  28 August 2003
Author:   Robin Moeller <Robin.Moeller@digitalnet.com>

Last Updated:	

Version:  2.3

*****************************************************************************/
#ifndef _SRL_HTTP_H
#define _SRL_HTTP_H

#define HTTP_HOST					"Host: "
#define HTTP_CRLF					"\r\n"
#define HTTP_CONTENT_LENGTH_HDR		"Content-Length:"
#define HTTP_CONTENT_LEN_HDR_LEN	15
#define HTTP_CHUNK_VALUE			"chunked"
#define HTTP_TRANSFER_ENC_HDR		"Transfer-Encoding:"
#define HTTP_TRANSFER_ENC_HDR_LEN   18
#define HTTP_VERSION				"HTTP/1.1"
#define HTTP_VERSION_LEN			8
#define HTTP_VERSION_SLASH			"HTTP/"
#define HTTP_VERSION_SLASH_LEN		5
#define HTTP_CONTENT_LENGTH_SIZE    15

// HTTP status codes relevant to SRL
#define HTTP_CONTINUE				100
#define HTTP_OK						200
#define HTTP_MOVED_PERM				301
#define HTTP_MOVED_TEMP				302
#define HTTP_BAD_REQUEST			400
#define HTTP_UNAUTHORIZED			401
#define HTTP_NOT_FOUND				404
#define HTTP_URI_TOO_LONG			414
#define HTTP_SERVER_ERROR			500
#define HTTP_NOT_IMPLEMENTED		501
#define HTTP_BAD_GATEWAY			502
#define HTTP_VERSION_NOT_SUPPORTED	505

#define HTTP_BUF_MAX				256
#define HTTP_CONTENT_LEN_MAX		156

#include "SRL_internal.h"

void Socket_close(int sock_fd);
extern int netread(int handle, char *put, size_t len, int flags);
extern int netwrite(int handle, char *psend, size_t len, int flags);
extern int http_readline(char *buf, int max, netbuf *ctl, int cpyflg);
extern int Socket_Connect(const char *host, int port);

/*
 * Function definitions
 */

void Http_Init(void);
int Http_Connect(const char *host, int port);
static int Http_Send(char *cmd, int socket_d);
short Http_Get(const char *host, const char *path, Bytes_struct *inBuf, int socket_d);
static short processHttpResponse(Bytes_struct *inBuf, int socket_d);
static short processContent(long content_length, Bytes_struct *inbuf, netbuf *ctl);
static int processResponseLine(const char *response_buf);
static long processHeaderLine(char *header_buf);
void Http_Quit (int socket_d);

#endif
