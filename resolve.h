/*
 * * FILE NAME: resolve.h
 * * HEADER FILE FOR resolve.c
 * * CREATED BY:   RICK W. WALLEN
 * * DATE CREATED: JULY.2.2013
 * * DATE LAST MOD:DECEMBER.16.2014
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
 * *	July.3.2013-function prototypes for createPktDNS.c
 * *	August.2.2013-added new prototype
 * *	August.21.2013-fixed names	
 * *	December.16.2014-added in conditional statements to ensure file/variables added only once
 * *	December.16.2014-added new functions one to read benchmark file one to prompt for user input
 * */
/**********************************************************************/
// INCLUDE ONCE
#ifndef _RESOLVER_
#define _RESOLVER_ 1
/* F(X) TO CREATE UDP PACKET */
int createUdpQuery(DnsHeader *head, DnsQuery *query, char **qn, char *dnsAddr);

/* F(X) TO PRINT ANSWER RECIEVED FROM SERVER */
void printAns(DnsHeader *head, char *ans);

/* F(X) FOR MANUAL CREATING PACKET */
int promptUser();

/* F(X) FOR MANUAL CREATING PACKET */
int readBenchFile();

#endif //end if resolve.h
