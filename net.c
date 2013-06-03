/*
 * net.c
 *
 *  Created on: Mar 8, 2013
 *      Author: volpol
 *  Modifed:
 *		2013-05-31	support bind address, statics no more [uw]
 */

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <unistd.h>

#include "log.h"


int net_open_client( const char *host, unsigned short port, const char *bind_addr )
{
	int sock = -1;
	struct sockaddr_in server;
	struct hostent *he = NULL;

	//WHOAMI;
	DPRINT( "%s:%d [%s]", host, port, bind_addr ? bind_addr : "*" );
	if ( 0 > ( sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) ) )
		return perror( "socket()" ), -1;
	server.sin_port = htons( port );
	server.sin_family = AF_INET;
	if ( NULL == ( he = gethostbyname( host ) ) )
	{
		herror( "gethostbyname()" );
		goto ERROUT;
	}
	if ( NULL != bind_addr )
	{
		struct sockaddr_in lob;
		lob.sin_family = AF_INET;
		if ( 0 != strcmp( bind_addr, "*" ) )
		{
			if ( 0 == strcmp( bind_addr, "localhost" ) )
				bind_addr = "127.0.0.1";
			lob.sin_family = AF_INET;
			if ( 0 == inet_aton( bind_addr, (struct in_addr *)&lob.sin_addr.s_addr ) )
			{
				fprintf( stderr, "inet_aton() failed\n" );
				goto ERROUT;
			}
		}
		else
			lob.sin_addr.s_addr = INADDR_ANY;
		if ( 0 > bind( sock, (const struct sockaddr*)&lob, sizeof lob ) )
		{
			perror( "bind()" );
			goto ERROUT;
		}
	}
	server.sin_addr.s_addr = *((in_addr_t*)he->h_addr_list[0]);
	if ( 0 != connect( sock, (struct sockaddr *)&server, sizeof server ) )
	{
		perror( "connect()" );
		goto ERROUT;
	}
	return sock;
ERROUT:
	close( sock );
	return -1;
}

int net_accept( int sock )
{
	WHOAMI;
	int conn = -1;
	if ( 0 > ( conn = accept( sock, NULL, NULL ) ) )
		perror( "accept()" );
	else
	{
		DPRINT( "accepted conn: %d\n", conn );
	}
	return conn;
}

void net_close( int conn )
{
	WHOAMI;
	if ( 0 <= conn )
	{
		DPRINT( "shutting down conn: %d\n", conn );
		shutdown( conn, SHUT_RDWR );
		close( conn );
	}
}

int net_open_server( unsigned short port, const char *bind_addr  )
{
	int sock;
	int reuse = 1;
	struct sockaddr_in lob;

	//WHOAMI;
	DPRINT( "%d [%s]", port, bind_addr ? bind_addr : "*" );
	if ( 0 > ( sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) ) )
		return perror( "socket()" ), -1;
	if ( 0 != setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse ) )
	{
		perror( "setsockopt()" );
		goto ERROUT;
	}
	lob.sin_family = AF_INET;
	lob.sin_port = htons( port );
	if ( NULL != bind_addr && 0 != strcmp( bind_addr, "*" ) )
	{
		if ( 0 == strcmp( bind_addr, "localhost" ) )
			bind_addr = "127.0.0.1";
		lob.sin_family = AF_INET;
		if ( 0 == inet_aton( bind_addr, (struct in_addr *)&lob.sin_addr.s_addr ) )
		{
			fprintf( stderr, "inet_aton() failed\n" );
			goto ERROUT;
		}
	}
	else
		lob.sin_addr.s_addr = INADDR_ANY;
	if ( 0 > bind( sock, (const struct sockaddr*)&lob, sizeof lob ) )
	{
		perror( "bind()" );
		goto ERROUT;
	}
	if ( 0 > listen( sock, 0 ) )
	{
		perror( "listen()" );
		goto ERROUT;
	}
	return sock;
ERROUT:
	close( sock );
	return -1;
}
