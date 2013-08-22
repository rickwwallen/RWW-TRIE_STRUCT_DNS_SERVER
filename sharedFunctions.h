/*
 * * FILE NAME: sharedFunctions.h
 * * HEADER FILE FOR sharedFunctions.c
 * * CREATED BY:   RICK W. WALLEN
 * * DATE CREATED: JULY.2.2013
 * * DATE LAST MOD: AUGUST.2.2013
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
 * *	August.2.2013-added function prototypes from test.h
 * *	August.21.2013-renamed sharedFunctions.h
 * */
/**********************************************************************/
/* FUNCTION PROTOTYPES */
/* F(X) PUT QUERY IN STRING TO SEND UDP */
int qryToStr(char *dest, DnsQuery *org1, char *org2, int *offset);

/* F(X) PULL QUERY FROM STRING IN UDP */
int strToQry(char *org, DnsQuery *dest1, char *dest2, int *offset);

/* F(X) PUT HEADER IN STRING TO SEND UDP */
int hdrToStr(char *dest, DnsHeader *org);

/* F(X) PUT STRING TO HEADER FROM UDP */
int strToHdr(char *org, DnsHeader *dest);

/* F(X) CONVERT DNS NAME FROM STD NOTATION TO QUERY NOTATION PER UNIVERSAL USE*/
int conDnsNameToSend(char *org, char *dest);

/*F(X) CONVERT DNS NAME FROM QUERY TO STD NOTATION */
void conDnsNameToPars(char *org, char *dest);

/*F(X) CONVERT DNS FLAGS TO 16BIT INT */
int flagsToU16I(DnsHdrFlags fg, uint16_t *hdr);

/*F(X) CONVERT 16 BIT INT FLAG INTO DNS FLAGS */
int u16IToFlags(DnsHdrFlags *fg, uint16_t hdr);

/*F(X) PRINT DNS HEADER */
void printHdr(DnsHeader hdr);

/*F(X) PRINT RESOURCE RECORD*/
void printResRec(RR *rec);
