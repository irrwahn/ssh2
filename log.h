/*
 * log.h
 *
 *  Created on: Jul 5, 2012
 *      Author: volpol
 */

#ifndef LOG_H_
#define LOG_H_

#ifdef DEBUG
	#define DPRINT(fmt, ...) do { fprintf( stderr, "%s:%s:%d:"fmt, __FILE__, __FUNCTION__, __LINE__ , ##__VA_ARGS__ ); } while (0)
#else
	#define DPRINT(...)
#endif

#define WHOAMI DPRINT("\n");

#endif /* LOG_H_ */
