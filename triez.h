/*
 * * FILE NAME:		triez.h
 * * HEADER FILE FOR triez.c
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	JUNE.3.2013
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
 * *	July.5.2013-put in function prototypes
 * *	August.2.2013-added in prototypes from readZone.h
 * *	August.21.2013-added function prototypes from struct.h formally parseMsgeDNS.h
 * *	December.16.2014-added in conditional statements to ensure file/variables added only once
 * */
/**********************************************************************/
// INCLUDE ONCE
#ifndef _TRIEZ_
#define _TRIEZ_ 1
/* F(X) PROTOTYPES */
/* F(X) TO DAEMONIZE THE SERVER */
int daemonInit(const char *pname, int facility);

/* F(X) TO CHECK DOMAIN NAME DOESN'T CONTAIN INVALID CHARACTERS */
uint16_t checkDN(char *domName);

/* F(X) TO CREATE A RESOUCE RECORD */
RR *createResRec(char *rec, uint32_t *ttlMin, uint16_t *rclass);

/* F(X) TO CREATE A NODE IN TRIE */
Trie *createNode(char k, RR *v);

/* F(X) TO ADD TO TRIE */
void addTrie(Trie *root, char *name, RR *resrec);

/* F(X) TO SEARCH TRIE */
Trie *searchTrie(Trie *root, char *search, uint16_t qt, uint16_t qc);

/* F(X) TO PULL NAME FROM TRIE */
void findN(char *dest, Trie *start);

/* F(X) TO ADD TO TRIE */
void delTrie(Trie *root);

/* F(X) TO PULL DATA FROM NODE AND RETRIEVE KEY */
void putResRecStr(DnsHdrFlags *fl, DnsHeader *head, Trie *root, Trie *result, DnsQuery *qry, char *msg, int *offset, char *search);

/*F(X) TO MAKE DOMAIN NAME UPPER CASE FOR SEARCHING */
void uDN(char *dom);

/* F(X) TO TAKE IN STRING OF ZONE FILE NAME AND CREATE DB */
Trie *readZone(char *f );

/* F(X) TO REVERSE DOMAIN NAME */
int revDN(char *DN);

/* F(X) PROTOTYPES */
uint16_t chSup(DnsType clType, DnsClass clClass);

#endif //end if triez.h
