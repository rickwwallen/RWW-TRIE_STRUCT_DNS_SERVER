/*
 * * FILE NAME:		ricksMultithreadedDNS.h	
 * * HEADER FILE FOR ricksMultithreadedDNS.c
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	AUGUST.17.2013
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
 * *	August.17.2013-created 
 * *		-added function prototype
 * *	August.21.2013-changed prototype to match ricksMultithreadedDNS.c
 * *	December.16.2014-added in conditional statements to ensure file/variables added only once
 * */
/**********************************************************************/
// INCLUDE ONCE
#ifndef _DNS_MULTITHREAD_
#define _DNS_MULTITHREAD_ 1
/* PROCESS DNS QUERY AND SEND TO CLIENT */
void *runServ();

#endif //end if ricksMultithreadedDNS.h
