/*
 * * FILE NAME:		ricksDNS.c
 * * DNS SERVER THE UTILIZES TRIE STRUCTURE AS THE LOOKUP DATABASE
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	JULY.4.2013
 * * DATE LAST MOD:	AUGUST.21.2013
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
 * *	July.4.2013-created 
 * *		-use parseMsge.c for functions to handle queries
 * *	August.21.2013-many changes have not been logged but works as of now
 * *			-redid include statements
 * */
/**********************************************************************/
#include "structs.h"
#include "sharedFunctions.c"
#include "triez.c"
#include "dns_1.h"

/* MAIN F(X) */
int main(int argc, char* argv[])
{
	char *zfil		= "rootTest.txt";	// zone file
	char *log		= "dnsServ.log";	// logs time it takes for query lookup in trie struct. and put into packet
	FILE *lgp;
	socklen_t serLen, cliLen;
	struct sockaddr_in serSockAddr, cliSockAddr;
	int udpSock = 0;

	DnsHeader head;		// Hold header information
	DnsHdrFlags fl;		// Hold flag information
	DnsQuery *qry;		// Holds all the queries' qtype and qclass
	Trie *root;		// Holds the start of the trie structure
	Trie *result;		// Holds the node that search returns
	char msg[PKT_SZ];	// Messages sent to and from server
	char nme[DNM_SZ];	// Name 
	char **dmn;		// Holds all the queries' domain names
	int offset = 0;		// Offset of message parsing
	int qdc = QRY_NO;	// Number of queries allowed in message
	int i = 0;			

	time_t tme;
	struct tm *tinfo;
	char t[25];
	double stlu, etlu, telu;
	double stps, etps, teps;
	
	qry = (DnsQuery *) malloc(qdc*sizeof(DnsQuery));
	dmn = (char **) malloc(qdc*sizeof(char *));
	
	udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	//udpSock = socket(AF_INET, SOCK_DGRAM, 0);

	bzero(&serSockAddr, sizeof(serSockAddr));
	bzero(&cliSockAddr, sizeof(cliSockAddr));
	serLen = sizeof(serSockAddr);
	cliLen = serLen;
	serSockAddr.sin_family = AF_INET;
	serSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serSockAddr.sin_port = htons(UDP_PT);

	bind(udpSock, (struct sockaddr *) &serSockAddr, serLen);

	if((lgp = fopen(log, "w+")) == NULL)
		return 1;// error

	fprintf(lgp, "Starting DNS server\n");
	fprintf(lgp, "    ___________\n");
	fprintf(lgp, "   |           | \n");
	fprintf(lgp, " [[|___________|]] \n");
	fprintf(lgp, "   \\___________/ \n");
	fprintf(lgp, "  __|[ ]||||[ ]|__\n");
	fprintf(lgp, "  \\_| # |||| # |_/\n");
	fprintf(lgp, " ___ ===Jeep=== ___ \n");
	fprintf(lgp, "|\\/\\| ''    '' |\\/\\|\n");
	fprintf(lgp, "|/\\/|          |/\\/|\n");
	fprintf(lgp, "|_\\_|          |_\\_|\n");
	fprintf(lgp, "\n\n\n");
	
	fprintf(lgp,"DATE TS,ID,QUERY QR,OPCODE,QDCOUNT,QUERY,QTYPE,QCLASS,RCODE,ANCOUNT,NSCOUNT,ARCOUNT,TIME TO LOOKUP(SECONDS),TIME TO SEND BACK(SECONDS)\n");
	fclose(lgp);

	root = readZone(zfil);
	for(i = 0; i < qdc; i++)
		dmn[i] = (char *) malloc(DNM_SZ*sizeof(char));

for(;;)
{
	offset = sizeof(DnsHeader);
	strcpy(msg, "");
	recvfrom(udpSock, msg, PKT_SZ, 0, (struct sockaddr *) &cliSockAddr, &cliLen);
	stps = getTime();

	if((lgp = fopen(log, "a+")) == NULL)
		return 1;// error

	time(&tme);
	tinfo = localtime(&tme);
	strftime(t, 25, "%m-%d-%Y %H:%M:%S", tinfo);

	strToHdr(msg, &head);
	u16IToFlags(&fl, head.flags);

	//DATETS,ID,QR,OPCODE,QDCOUNT
	fprintf(lgp, "%s,%d,%d,%d,%d,", t, (int) head.id, (int) fl.qr, (int) fl.opcode, (int) head.qdcount);

	if((fl.opcode != 0) || (head.qdcount > QRY_NO) || (fl.qr != 0))
	{
		//Only support standard queries
		fl.rcode = 4;	
		if(fl.opcode != 0)
		fprintf(lgp, "%s,%d,%d,", "ERROR REFUSED FROM OPCODE", 0, 0);
		else if(head.qdcount != QRY_NO)
		fprintf(lgp, "%s,%d,%d,", "ERROR REFUSED FROM QDCOUNT", 0, 0);
		else
		fprintf(lgp, "%s,%d,%d,", "ERROR REFUSED FROM QR", 0, 0);
	}	
	else
	{
		// set flags for response
		fl.qr = 1;
		// set recursion to not available
		fl.rd = 0;
		fl.ra = 0;
		// set authority
		fl.aa = 1;

		for(i = 0; i < qdc; i++)
		{
			strToQry(msg+offset, &qry[i], dmn[i], &offset);
			//QUERY,QTYPE,QCLASS
			fprintf(lgp, "%s,%d,%d,", dmn[i], (int) qry[i].qtype, (int) qry[i].qclass);
		}

		head.ancount = 0;
		head.nscount = 0;
		head.arcount = 0;

		for(i = 0; i < qdc; i++)
		{
			stlu = getTime();
			fl.rcode = chSup((DnsType) qry[i].qtype, (DnsClass) qry[i].qclass);
			if(fl.rcode == 0)
			{
				if(qry[i].qtype != (uint16_t) ptr)
					fl.rcode = checkDN(dmn[i]);
				if(fl.rcode == 0)
				{
					strcpy(nme , dmn[i]);
					revDN(dmn[i]);
					result = searchTrie(root, dmn[i], qry[i].qtype, qry[i].qclass);
					uDN(nme);
					if(result != NULL)
						putResRecStr(&fl, &head, root, result, &qry[i], msg+offset, &offset, nme);
					else if(result == NULL)
						fl.rcode = 3;
				}
			}
			etlu = getTime();
			telu = etlu - stlu;
		}//end 2nd for loop 

		if(fl.rcode == 0)
			if((head.ancount == 0) || (head.nscount > 0) || (head.arcount > 0))
				fl.rcode = 3;
	}//end else from opcode check

	//put header back in
	//RCODE,ANCOUNT,NSCOUNT,ARCOUNT,TIMELOOKUP,TIMETOTAL
	fprintf(lgp, "%d,%d,%d,%d,", (int) fl.rcode, (int) head.ancount, (int) head.nscount, (int) head.arcount);
	flagsToU16I(fl, &head.flags);
	hdrToStr(msg, &head);

	sendto(udpSock, msg, PKT_SZ, 0, (struct sockaddr *) &cliSockAddr, cliLen);
	etps = getTime();
	teps = etps - stps;
	//TIMELOOKUP,TIMETOTAL
	fprintf(lgp, "%lf,%lf\n", telu, teps);
	
	fclose(lgp);
}

	return 0;
}
