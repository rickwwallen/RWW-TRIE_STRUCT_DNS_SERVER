/*
 * * FILE NAME:		dns_1.h
 * * STANDARD HEADER FILE
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	JUNE.27.2013
 * * DATE LAST MOD:	DECEMBER.16.2014
 * *     ___________
 * *    |           | 
 * *  [[|___________|]] 
 * *    \___________/ 
 * *   __|[ ]||||[ ]|__
 * *   \_| # |||| # |_/
 * *  ___ ===Jeep=== ___ 
 * * |\/\| ''    '' |\/\|
 * * |/\/|          |/\/|
 * * |_\_|          |_\_|
 * */
/**********************************************************************/
/*
 * * MODIFIED LOG:
 * *       <date>-<description>
 * *	July.3.2013- added libraries and defined constants
 * *	August.21.2013-added posix thread libraries and constants for
 * *			-multithreading
 * *	December.13.2014-changed udp port to 53 standard for dns queries
 * *	December.16.2014-added in conditional statements to ensure file/variables added only once
 * */
/**********************************************************************/
//Network and Structures
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
//Timestamps
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
//POSIX Threads
#include <pthread.h>
//#include <time.h>
//#include
//Daemonize Server
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>

// INCLUDE ONCE
#ifndef _PROJECT_GENERIC_
#define _PROJECT_GENERIC_ 1
int daemonProc;

/* DECLARATIONS */
#define QRY_NO 1
#define DNM_SZ 1025
#define LBL_SZ 63
#define SEG_SZ 17
#define LNE_SZ 1025
#define PKT_SZ 512 	//byte size of UDP Packet 512 - 12(header) 500
#define UDP_SZ 4096	//bit size of UDP Packet 500 bytes * 8
#define MAX_IP 65535	//Max byte size of IPv4 IPv6 is 65575 both include header
#define UDP_PT 53
//#define UDP_PT 32000
#define IPV4STRLEN 16
#define IPV6STRLEN 46
#define MAXFD 64
#define THD_MX 8

#endif //end if dns_1.h
