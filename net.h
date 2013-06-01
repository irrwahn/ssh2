/*
 * net.h
 *
 *  Created on: Mar 8, 2013
 *      Author: volpol
 */

#ifndef NET_H_
#define NET_H_

int net_accept( int sock );
int net_open_server( unsigned short port, const char *bind_addr );
int net_open_client( const char *host, unsigned short port, const char *bind_addr );
void net_close( int conn );

#endif /* NET_H_ */
