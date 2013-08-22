/*
 * * FILE NAME:		ricksMultithreadedDNS.c
 * * MULTITHREADED DNS SERVER
 * * DNS SERVER THE UTILIZES TRIE STRUCTURE AS THE LOOKUP DATABASE
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	AUGUST.17.2013
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
 * *	August.17.2013-copied from ricksDNS.c and modified to be multithreaded
 * *	August.20.2013-used posix threads to make server multithreaded
 * *	August.21.2013-fixed column headers
 * */
/**********************************************************************/
#include "ricksMultithreadedDNS.h"
#include "structs.h"
#include "sharedFunctions.c"
#include "triez.c"
#include "dns_1.h"

// Declare socket variables to be used by all threads
socklen_t serLen;
struct sockaddr_in serSockAddr;
int udpSock;
Trie *root;					// Holds the start of the trie structure
FILE *lgp;

// Thread variables to be used by all threads
struct sockaddr_in clientS[THD_MX];
char message[THD_MX][PKT_SZ];
double tm[THD_MX];

int cliget, cliput;

pthread_mutex_t mutexLog	= PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutexCli	= PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condCli		= PTHREAD_COND_INITIALIZER;

/* MAIN F(X) */
int main(int argc, char* argv[])
{
	socklen_t cliLen;
	struct sockaddr_in cliSockAddr;

	pthread_t tid[THD_MX];
	int i;

	double tme;
	char msg[PKT_SZ];		// Messages sent to and from server

	char *zfil		= "rootTest.txt";	// zone file
	char *log		= "dnsServ.log";	// logs time it takes for query lookup in trie struct. and put into packet

	udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	//udpSock = socket(AF_INET, SOCK_DGRAM, 0);

	cliLen = serLen = sizeof(serSockAddr);
	bzero(&serSockAddr, serLen);
	serSockAddr.sin_family = AF_INET;
	serSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serSockAddr.sin_port = htons(UDP_PT);

	bind(udpSock, (struct sockaddr *) &serSockAddr, serLen);

	//if((lgp = fopen(log, "a+")) == NULL)
	if((lgp = fopen(log, "w+")) == NULL)
		return 1;//Error

	fprintf(lgp, "Starting Multithreaded DNS Server\n");
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

	fprintf(lgp,"DATE TS,THREAD ID,ID,QUERY QR,OPCODE,QDCOUNT,QUERY,QTYPE,QCLASS,RCODE,ANCOUNT,NSCOUNT,ARCOUNT,TIME TO LOOKUP(SECONDS),TIME TO SEND BACK(SECONDS)\n");
	
	fclose(lgp);
	root = readZone(zfil);
	cliget = 0;
	cliput = 0;

	// Create pool of threads
	for(i = 0; i < THD_MX; i++)
		pthread_create(&tid[i], NULL, runServ, NULL);

for(;;)
{
	bzero(&cliSockAddr, sizeof(struct sockaddr_in));
	recvfrom(udpSock, msg, PKT_SZ, 0, (struct sockaddr *) &cliSockAddr, &cliLen);
	tme	= getTime();

	pthread_mutex_lock(&mutexCli);
	//printf("%d\n", (int) cliSockAddr.sin_addr.s_addr);
	clientS[cliput]	= cliSockAddr;
	tm[cliput]	= tme;
	memcpy((void *) message[cliput], (void *) msg, PKT_SZ);
	if(++cliput == THD_MX)
		cliput = 0;
	if(cliput == cliget)
		return 0;
	pthread_cond_signal(&condCli);
	pthread_mutex_unlock(&mutexCli);

}
	return 0;
}

void *runServ()
{
	socklen_t cliLen;
	struct sockaddr_in cliSockAddr;
	char *log		= "dnsServ.log";	// logs time it takes for query lookup in trie struct. and put into packet

	Trie *result;			// Holds the node that search returns
	DnsHeader head;			// Hold header information
	DnsHeader hosth;		// Hold host format header information
	DnsHdrFlags fl;			// Hold flag information
	DnsHdrFlags hostfl;		// Hold host formatflag information
	DnsQuery *qry;			// Holds all the queries' qtype and qclass
	DnsQuery *qry2;			// Holds all the queries' qtype and qclass
	char msg[PKT_SZ];		// Messages sent to and from server
	char nme[DNM_SZ];		// Name 
	char **dmn;			// Holds all the queries' domain names
	char **dmn2;			// Holds all the queries' domain names
	int qdc		= QRY_NO;	// Number of queries allowed in message
	int offset	= 0;		// Offset of message parsing
	int i 		= 0;			

	time_t tme;			// Vars for current time
	struct tm *tinfo;		// Vars for current time
	char t[25];			// Vars for current time
	double stlu, etlu, telu;	// Vars for timestamp of lookup
	double stps, etps, teps;	// Vars for timestamp of time to service a request

	pthread_t tid;			// Holds current thread id

	tid = pthread_self();
	cliLen		= sizeof(struct sockaddr_in);
	qry	= (DnsQuery *) malloc(qdc*sizeof(DnsQuery));
	qry2	= (DnsQuery *) malloc(qdc*sizeof(DnsQuery));
	dmn	= (char **) malloc(qdc*sizeof(char *));
	dmn2	= (char **) malloc(qdc*sizeof(char *));
	for(i = 0; i < qdc; i++)
	{
		dmn[i]	= (char *) malloc(DNM_SZ*sizeof(char));
		dmn2[i]	= (char *) malloc(DNM_SZ*sizeof(char));
	}
	
for(;;)
{
	pthread_mutex_lock(&mutexCli);
	while(cliget == cliput)
		pthread_cond_wait(&condCli, &mutexCli);
	bzero(&cliSockAddr, sizeof(struct sockaddr_in));
	cliSockAddr	= clientS[cliget];
	//printf("%d\n", (int) cliSockAddr.sin_addr.s_addr);
	stps		= tm[cliget];
	memcpy((void *)msg, (void *) message[cliget], PKT_SZ);
	if(++cliget == THD_MX)
		cliget = 0;
	pthread_mutex_unlock(&mutexCli);

	offset = sizeof(DnsHeader);
	strcpy(msg, "");

	strToHdr(msg, &head);
	u16IToFlags(&fl, head.flags);

	if((fl.opcode != 0) || (head.qdcount > QRY_NO) || (fl.qr != 0))
	{
		//Only support standard queries
		fl.rcode = 4;	
	}	
	else
	{
		for(i = 0; i < qdc; i++)
		{
			strToQry(msg+offset, &qry[i], dmn[i], &offset);
			strcpy(dmn2[i],dmn[i]);
			qry2[i].qtype	= qry[i].qtype;
			qry2[i].qclass	= qry[i].qclass;
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
		}//End 2nd for loop 

		if(fl.rcode == 0)
			if((head.ancount == 0) || (head.nscount > 0) || (head.arcount > 0))
				fl.rcode = 3;
	}//End else from opcode check

	hosth = head;
	hostfl = fl;

	// Set flags for response
	fl.qr = 1;
	// Set recursion to not available
	fl.rd = 0;
	fl.ra = 0;
	// Set authority
	fl.aa = 1;
	//Put header back in
	flagsToU16I(fl, &head.flags);
	hdrToStr(msg, &head);

	sendto(udpSock, msg, PKT_SZ, 0, (struct sockaddr *) &cliSockAddr, cliLen);

	etps = getTime();
	teps = etps - stps;

	pthread_mutex_lock(&mutexLog);
	//Start logging data probably need to lock mutex now
	lgp = fopen(log, "a+");
	time(&tme);
	tinfo = localtime(&tme);
	strftime(t, 25, "%m-%d-%Y %H:%M:%S", tinfo);

	//DATETS,THREAD ID,DNS HEADER ID,QR,OPCODE,QDCOUNT
	fprintf(lgp, "%s,%d,%d,%d,%d,%d,", t,(int) tid, (int) hosth.id, (int) fl.qr, (int) hostfl.opcode, (int) hosth.qdcount);

	//QUERY,QTYPE,QCLASS
	if(hostfl.opcode != 0)
		fprintf(lgp, "%s,%d,%d,", "ERROR REFUSED FROM OPCODE", 0, 0);
	else if(hosth.qdcount != QRY_NO)
		fprintf(lgp, "%s,%d,%d,", "ERROR REFUSED FROM QDCOUNT", 0, 0);
	else if(hostfl.qr != 0)
		fprintf(lgp, "%s,%d,%d,", "ERROR REFUSED FROM QR", 0, 0);
	else
	{
		for(i = 0; i < qdc; i++)
			fprintf(lgp, "%s,%d,%d,", dmn2[i], (int) qry2[i].qtype, (int) qry2[i].qclass);
	}

	//RCODE,ANCOUNT,NSCOUNT,ARCOUNT,TIMELOOKUP,TIMETOTAL
	fprintf(lgp, "%d,%d,%d,%d,", (int) hostfl.rcode, (int) hosth.ancount, (int) hosth.nscount, (int) hosth.arcount);

	//TIMELOOKUP,TIMETOTAL
	fprintf(lgp, "%lf,%lf\n", telu, teps);
	fclose(lgp);
	pthread_mutex_unlock(&mutexLog);
}

}
