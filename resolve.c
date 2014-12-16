/*
 * * FILE NAME: resolve.c
 * * CLIENT AKA THE RESOLVER 
 * * CREATED BY:   RICK W. WALLEN
 * * DATE CREATED: MAY.8.2013
 * * DATE LAST MOD: DECEMER.16.2014
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
 * *	May.8.2013-copied file triez.c as skeleton code for this file
 * *	June.27.2013-created functions to convert domain name to suitable 
 * * 		-format for domain transmission and to revert format to
 * *		-standard. 
 * *		-Added function to send query in UDP
 * *    July.2.2013-added function to take in flag structure and convert to unsigned 16 int
 * *		-added function to take unsigned 16 int and put it in flag structure
 * *	July.4.2013-modified function to send dns query(still a skeleton)
 * *	July.5.2013-use of memcpy to transfer structures into buff l#92-94
 * *	August.2.2013-added function to print message recieved from server
 * *	August.21.2013-redid include file
 * *	December.13.2014-added code to take in non-default ip of dns server
 * *	December.16.2014-added menu to choose between manual input and loading a benchmark file
 * *		-benchmark file to be added at a later date
 * *		-added new functions one to read benchmark file one to prompt for user input
 * */
/**********************************************************************/
#include "structs.h"
#include "sharedFunctions.c"
#include "dns_1.h"
#include "resolve.h"

/* MAIN F(X) */
int main( )
{
	int i = 0;
	int d = 0;
	char buff[DNM_SZ];
	char uppr[DNM_SZ];

	while(strcmp(buff, "q") != 0)
	{
		strcpy(buff,"");
		if(d == 0)
		{
			printf("Enter whether input will be manual or enter through file for benchmarking.\n"
				"\tBring up menu/options:\t h/H help/HELP\n"
				"\tManual User Input:\t i/I input/INPUT \n"
				"\tRead benchmark File:\t b/B benchmark/BENCHMARK\n"
				"\tQuit:\t x/X q/Q e/E exit/EXIT quit/QUIT\n");
			d++;
		}
		scanf("%s", buff);
		for(i = 0; i <= strlen(buff) + 1; i++)
			uppr[i] = toupper(buff[i]);
		if((strcmp(uppr,"I")==0) 
		|| (strcmp(uppr,"INPUT")==0))
			promptUser();
		else if((strcmp(uppr,"B")==0) || (strcmp(uppr,"BENCHMARK")==0))
			readBenchFile();
		else if   ((strcmp(uppr,"Q")==0) 
			|| (strcmp(uppr,"X")==0) 
			|| (strcmp(uppr,"E")==0) 
			|| (strcmp(uppr,"EXIT")==0)
			|| (strcmp(uppr,"QUIT")==0))
			break;
		else if   ((strcmp(uppr,"H")==0)
			|| (strcmp(uppr,"HELP")==0))
	                printf("Commands list\n" 
				"\tBring up menu/options:\t h/H help/HELP\n"
				"\tManual User Input:\t i/I input/INPUT \n"
                                "\tRead benchmark File:\t b/B benchmark/Benchmark\n"
                                "\tQuit:\t x/X q/Q e/E exit/EXIT quit/QUIT\n\n");
		else
	                printf("Invalid Response\n"
				"\tBring up menu/options:\t h/H help/HELP\n"
				"\tManual User Input:\t i/I input/INPUT \n"
                                "\tRead benchmark File:\t b/B benchmark/Benchmark\n"
                                "\tQuit:\t x/X q/Q e/E exit/EXIT quit/QUIT\n\n");

	}

	return 0;
}

/* F(X) FOR MANUAL CREATING PACKET */
int promptUser( )
{
	int noQ = QRY_NO;
	int addrsz = IPV4STRLEN;
	int addrchk;
	struct in_addr a_adr;
	int i;
	DnsHeader h;
	DnsHdrFlags fl;
	DnsQuery q[noQ];// = (DnsQuery **) malloc(2 * sizeof(DnsQuery *));

	char **buff2 = (char **) malloc(noQ * sizeof(char *));
	
	int recursion = 1;
	char buff[DNM_SZ];
	char uppr[DNM_SZ];
	char *addr = (char *) malloc(addrsz * sizeof(char));
	//char *addr = "127.0.0.1";
	//char *addr = "192.168.0.189";
	//strcpy(addr,"127.0.0.1");
	//strcpy(addr,"192.168.0.189");
	strcpy(addr,"192.168.0.100");

	strcpy(buff,"");
	printf("Enter the server adderess {Enter d for default:(%s)}\n", addr);
	scanf("%s", buff);
	for(i = 0; i <= strlen(buff) + 1; i++)
		uppr[i] = toupper(buff[i]);
	i=0;
	if(strcmp(uppr,"D") == 0||strcmp(uppr,"DEFAULT") == 0)
		printf("Using default ip address:\t %s\n", addr);
	else
	{
		printf("buff:\t %s\n", buff);
		//strcpy(addr,"");
		addrchk = inet_pton(AF_INET, buff, &a_adr);
		if(addrchk != 0)
		{
			strcpy(addr,buff);
			printf("Using user entered address:\t %s\n",addr);
		}
		else
			printf("Using default ip address:\t %s\n", addr);
	}
	//strcpy(buff,"q");
	strcpy(buff,"");
	while(strcmp(buff, "q") != 0)
	{
		//Create DNS Header for query
		fl.qr		= 0;
		//fl.qr		= 1;
		fl.opcode	= 0;
		//fl.opcode	= 1;
		fl.aa		= 0;
		fl.tc		= 0;
		fl.rd		= recursion;
		fl.ra		= recursion;
		fl.z		= 0;
		fl.rcode	= 0;
	
		flagsToU16I(fl, &h.flags);
	
		//printf( "Flags: %04x\n", h.flags );

		h.id		= getpid();	// ID number
		h.qdcount	= noQ;		// Only one query
		//h.qdcount	= 2;		// Only one query
		h.ancount	= 0;		// This is query we don't fill this
		h.nscount	= 0;
		h.arcount	= 0;		// This is query we don't fill this

		for(i = 0; i < noQ; i++)
		{
			strcpy(buff,"");
			q[i].qtype = 0;
			q[i].qclass = 0;
			printf("Please enter domain:\t");
			scanf("%s", buff);
			if(strcmp(buff,"q") == 0)
				break;
			printf("\nPlease enter query type[1,2,5,6,12,15,28]:\t");
			scanf("%hu", &q[i].qtype);
			printf("\nPlease enter query class [1-4]:\t");
			scanf("%hu", &q[i].qclass);
			buff2[i] = malloc(strlen(buff) * sizeof(char));
			buff2[i] = strdup(buff);
		}
		if(strcmp(buff, "q") == 0)
			break;
		createUdpQuery(&h, q, buff2, addr);
	}

	return 0;
}

/* F(X) FOR MANUAL CREATING PACKET */
int readBenchFile( )
{
	printf("STUBBED FOR LATER ADDITION\n");
	return 0;
}

/* F(X) TO CREATE UDP PACKET */
int createUdpQuery(DnsHeader *head, DnsQuery *query, char **qn, char *dnsAddr)
{
	char buff[PKT_SZ];
	socklen_t len;
	int udpSock;
	//int err;
	struct sockaddr_in serSockAddr;
	int offset = 0;
	int i;
	int qdc;
	double startTime, endTime, timeElap;

	qdc = QRY_NO;
	//qdc = (int) head->qdcount;

	//printHdr(*head);

	hdrToStr(buff, head);
	offset = sizeof(DnsHeader);

	for(i = 0; i < qdc; i++)
		qryToStr(buff+offset, &query[i], qn[i], &offset);

	//IPPROTO_UDP is an enum in netinet/in.h for the UDP protocol number
	udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	bzero(&serSockAddr, sizeof(serSockAddr));
	serSockAddr.sin_family = AF_INET;
	serSockAddr.sin_port = htons(UDP_PT);
	serSockAddr.sin_addr.s_addr = inet_addr(dnsAddr);//using inet_addr to conv str to IPv4 addr
	len = sizeof(serSockAddr);
/*
 * This is a way to support both IPv4 and IPv6
	err = inet_pton( AF_INET, qn, serSockAddr.sin_addr.s_addr );
	if( err < 1 )
		printf( "Error %d\n", err );
*/
	sendto(udpSock, buff, PKT_SZ, 0, (struct sockaddr *) &serSockAddr, len);
	startTime = getTime();

	recvfrom(udpSock, buff, PKT_SZ, 0, (struct sockaddr *) &serSockAddr, &len);
	//recvfrom(udpSock, buff, MAX_IP, 0, (struct sockaddr *) &serSockAddr, &len);

	endTime = getTime();
	timeElap = endTime - startTime;

	offset = sizeof(DnsHeader);
	strToHdr(buff, head);
	printAns(head, buff);	
	printf("TIME ELAPSED:\t%lf SECONDS\n", timeElap);
	close(udpSock);

	return 0;	
}

/* F(X) TO PRINT ANSWER RECIEVED FROM SERVER */
void printAns(DnsHeader *head, char *ans)
{
	char nme[DNM_SZ];
	char ipv4[IPV4STRLEN];
	char ipv6[IPV6STRLEN];
	struct in_addr	a_adr;
	struct in6_addr aaaa_adr;
	uint16_t	rtype;
	uint16_t	rclass;
	uint16_t	rdlen;
	uint16_t	pref;
	int32_t		ttl;
	int32_t		refresh;
	int32_t		retry;
	int32_t		expire;
	uint32_t	serial;
	uint32_t	minimum;
	int offset, i;
	DnsQuery query;

	offset = sizeof(DnsHeader);
	
	printHdr(*head);

	printf("QUERY\n");
	for(i = 0; i < head->qdcount; i++)
	{
		strToQry(ans+offset, &query, nme, &offset);
		printf("%s\n",nme);
		printf("QTYPE:\t%u\n", query.qtype);
		printf("QCLASS:\t%u\n", query.qclass);
	}

	printf("\nANSWER SECTION\n");
	for(i = 0; i < head->ancount; i++)
	{
		conDnsNameToPars(ans+offset, nme);
		offset	= offset +         strlen(nme) + 1;
		memcpy((void *) &rtype, (void *) ans + offset, sizeof(uint16_t));
		offset	= offset + sizeof(uint16_t);
		memcpy((void *) &rclass, (void *) ans + offset, sizeof(uint16_t));
		offset	= offset + sizeof(uint16_t);
		memcpy((void *) &ttl, (void *) ans + offset, sizeof(uint32_t));
		offset	= offset + sizeof(uint32_t);
		memcpy((void *) &rdlen, (void *) ans + offset, sizeof(uint16_t));
		offset	= offset + sizeof(uint16_t);

		rtype	= ntohs(rtype);
		rclass	= ntohs(rclass);
		ttl	= ntohl(ttl);
		rdlen	= ntohs(rdlen);

		printf("NAME:\t%s\n",	nme);
		printf("TTL:\t%d\n",	ttl);
		printf("RDLEN:\t%u\n",	rdlen);
		switch((DnsClass) rclass)
		{
			case in:
				printf("CLASS:\tIN\n");
				break;
			case cs:
				printf("CLASS:\tCS\n");
				break;
			case ch:
				printf("CLASS:\tCH\n");
				break;
			case hs:
				printf("CLASS:\tHS\n");
				break;
			default:
				printf("SHOULDN'T BE HERE\n");
				break;
		}
		switch((DnsType) rtype)
		{
			case a:
				printf("TYPE:\tA:\n");
				memcpy((void *) &a_adr, (void *) ans+offset, rdlen);
				offset	= offset + rdlen;
				printf("RDATA:\t%s\n", inet_ntop(AF_INET, &a_adr, ipv4, IPV4STRLEN));	
				break;
			case ns:
				printf("TYPE:\tNS:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen;
				printf("%s\n", nme);	
				break;
			case cname:
				printf("TYPE:\tCNAME:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen;
				printf("%s\n", nme);	
				break;
			case soa:
				printf("TYPE:\tSOA:\n");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + strlen(ans) + 1;
				printf("MNAME:\t%s\n", nme);	
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + strlen(ans) + 1;
				printf("RNAME:\t%s\n", nme);
				memcpy((void *) &serial, (void *) ans+offset, sizeof(uint32_t));
				offset = offset + sizeof(uint32_t);
				memcpy((void *) &refresh, (void *) ans+offset, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) &retry, (void *) ans+offset, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) &expire, (void *) ans+offset, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) &minimum, (void *) ans+offset, sizeof(uint32_t));
				offset = offset + sizeof(uint32_t);
				serial	= ntohl(serial);
				refresh	= ntohl(refresh);
				retry	= ntohl(retry);
				expire	= ntohl(expire);
				minimum	= ntohl(minimum);
				printf("SERIAL:\t%u\n",		serial);
				printf("REFRESH:\t%d\n",	refresh);
				printf("RETRY:\t%d\n",		retry);
				printf("EXPIRE:\t%d\n",		expire);
				printf("MINIMUM:\t%u\n",	minimum);
				break;
			case ptr:
				printf("TYPE:\tPTR:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen;
				printf("%s\n", nme);	
				break;
			case mx:
				printf("TYPE:\tMX\n");
				memcpy((void *) &pref, (void *) ans+offset, sizeof(uint16_t));
				offset = offset + sizeof(uint16_t);
				pref	= ntohs(pref);
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen - sizeof(uint16_t);
				printf("PREFERENCE:\t%u\n", pref);
				printf("EXCHANGE:\t%s\n", nme);	
				break;
			case aaaa:
				printf("TYPE:\tAAAA:\t");
				memcpy((void *) &aaaa_adr, (void *) ans+offset, rdlen);
				offset	= offset + rdlen;
				printf("RDATA:\t%s\n", inet_ntop(AF_INET6, &aaaa_adr, ipv6, IPV6STRLEN));	
				break;
			default:
				printf("SHOULDN'T BE HERE\n");
				break;
		}
	}

	printf("\nAUTHRORITY SECTION\n");
	for(i = 0; i < head->nscount; i++)
	{
		conDnsNameToPars(ans+offset, nme);
		offset	= offset +         strlen(nme) + 1;
		memcpy((void *) &rtype, (void *) ans + offset, sizeof(uint16_t));
		offset	= offset + sizeof(uint16_t);
		memcpy((void *) &rclass, (void *) ans + offset, sizeof(uint16_t));
		offset	= offset + sizeof(uint16_t);
		memcpy((void *) &ttl, (void *) ans + offset, sizeof(uint32_t));
		offset	= offset + sizeof(uint32_t);
		memcpy((void *) &rdlen, (void *) ans + offset, sizeof(uint16_t));
		offset	= offset + sizeof(uint16_t);

		rtype	= ntohs(rtype);
		rclass	= ntohs(rclass);
		ttl	= ntohl(ttl);
		rdlen	= ntohs(rdlen);

		printf("NAME:\t%s\n",	nme);
		printf("TTL:\t%d\n",	ttl);
		printf("RDLEN:\t%u\n",	rdlen);
		switch((DnsClass) rclass)
		{
			case in:
				printf("CLASS:\tIN\n");
				break;
			case cs:
				printf("CLASS:\tCS\n");
				break;
			case ch:
				printf("CLASS:\tCH\n");
				break;
			case hs:
				printf("CLASS:\tHS\n");
				break;
			default:
				printf("SHOULDN'T BE HERE\n");
				break;
		}
		switch((DnsType) rtype)
		{
			case a:
				printf("TYPE:\tA:\n");
				memcpy((void *) &a_adr, (void *) ans+offset, rdlen);
				offset	= offset + rdlen;
				printf("RDATA:\t%s\n", inet_ntop(AF_INET, &a_adr, ipv4, IPV4STRLEN));	
				break;
			case ns:
				printf("TYPE:\tNS:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen;
				printf("%s\n", nme);	
				break;
			case cname:
				printf("TYPE:\tCNAME:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen;
				printf("%s\n", nme);	
				break;
			case soa:
				printf("SHOULDN'T BE HERE\n");
				printf("TYPE:\tSOA:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + strlen(ans) + 1;
				printf("MNAME:\t%s\n", nme);	
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + strlen(ans) + 1;
				printf("RNAME:\t%s\n", nme);
				memcpy((void *) &serial, (void *) ans+offset, sizeof(uint32_t));
				offset = offset + sizeof(uint32_t);
				memcpy((void *) &refresh, (void *) ans+offset, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) &retry, (void *) ans+offset, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) &expire, (void *) ans+offset, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) &minimum, (void *) ans+offset, sizeof(uint32_t));
				offset = offset + sizeof(uint32_t);
				serial	= ntohl(serial);
				refresh	= ntohl(refresh);
				retry	= ntohl(retry);
				expire	= ntohl(expire);
				minimum	= ntohl(minimum);
				printf("SERIAL:\t%u\n",		serial);
				printf("REFRESH:\t%d\n",	refresh);
				printf("RETRY:\t%d\n",		retry);
				printf("EXPIRE:\t%d\n",		expire);
				printf("MINIMUM:\t%u\n",	minimum);
				break;
			case ptr:
				printf("TYPE:\tPTR:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen;
				printf("%s\n", nme);	
				break;
			case mx:
				printf("TYPE:\tMX\n");
				memcpy((void *) &pref, (void *) ans+offset, sizeof(uint16_t));
				offset = offset + sizeof(uint16_t);
				pref	= ntohs(pref);
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen - sizeof(uint16_t);
				printf("PREFERENCE:\t%u\n", pref);
				printf("EXCHANGE:\t%s\n", nme);	
				break;
			case aaaa:
				printf("TYPE:\tAAAA:\t");
				memcpy((void *) &aaaa_adr, (void *) ans+offset, rdlen);
				offset	= offset + rdlen;
				printf("RDATA:\t%s\n", inet_ntop(AF_INET6, &aaaa_adr, ipv6, IPV6STRLEN));	
				break;
			default:
				printf("SHOULDN'T BE HERE\n");
				break;
		}
	}

	printf("\nADDITIONAL RESOURCES SECTION\n");
	for(i = 0; i < head->arcount; i++)
	{
		conDnsNameToPars(ans+offset, nme);
		offset	= offset +         strlen(nme) + 1;
		memcpy((void *) &rtype, (void *) ans + offset, sizeof(uint16_t));
		offset	= offset + sizeof(uint16_t);
		memcpy((void *) &rclass, (void *) ans + offset, sizeof(uint16_t));
		offset	= offset + sizeof(uint16_t);
		memcpy((void *) &ttl, (void *) ans + offset, sizeof(uint32_t));
		offset	= offset + sizeof(uint32_t);
		memcpy((void *) &rdlen, (void *) ans + offset, sizeof(uint16_t));
		offset	= offset + sizeof(uint16_t);

		rtype	= ntohs(rtype);
		rclass	= ntohs(rclass);
		ttl	= ntohl(ttl);
		rdlen	= ntohs(rdlen);

		printf("NAME:\t%s\n",	nme);
		printf("TTL:\t%d\n",	ttl);
		printf("RDLEN:\t%u\n",	rdlen);
		switch((DnsClass) rclass)
		{
			case in:
				printf("CLASS:\tIN\n");
				break;
			case cs:
				printf("CLASS:\tCS\n");
				break;
			case ch:
				printf("CLASS:\tCH\n");
				break;
			case hs:
				printf("CLASS:\tHS\n");
				break;
			default:
				printf("SHOULDN'T BE HERE\n");
				break;
		}
		switch((DnsType) rtype)
		{
			case a:
				printf("TYPE:\tA:\n");
				memcpy((void *) &a_adr, (void *) ans+offset, rdlen);
				offset	= offset + rdlen;
				printf("RDATA:\t%s\n", inet_ntop(AF_INET, &a_adr, ipv4, IPV4STRLEN));	
				break;
			case ns:
				printf("TYPE:\tNS:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen;
				printf("%s\n", nme);	
				break;
			case cname:
				printf("TYPE:\tCNAME:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen;
				printf("%s\n", nme);	
				break;
			case soa:
				printf("SHOULDN'T BE HERE\n");
				printf("TYPE:\tSOA:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + strlen(ans) + 1;
				printf("MNAME:\t%s\n", nme);	
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + strlen(ans) + 1;
				printf("RNAME:\t%s\n", nme);
				memcpy((void *) &serial, (void *) ans+offset, sizeof(uint32_t));
				offset = offset + sizeof(uint32_t);
				memcpy((void *) &refresh, (void *) ans+offset, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) &retry, (void *) ans+offset, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) &expire, (void *) ans+offset, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) &minimum, (void *) ans+offset, sizeof(uint32_t));
				offset = offset + sizeof(uint32_t);
				serial	= ntohl(serial);
				refresh	= ntohl(refresh);
				retry	= ntohl(retry);
				expire	= ntohl(expire);
				minimum	= ntohl(minimum);
				printf("SERIAL:\t%u\n",		serial);
				printf("REFRESH:\t%d\n",	refresh);
				printf("RETRY:\t%d\n",		retry);
				printf("EXPIRE:\t%d\n",		expire);
				printf("MINIMUM:\t%u\n",	minimum);
				break;
			case ptr:
				printf("TYPE:\tPTR:\t");
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen;
				printf("%s\n", nme);	
				break;
			case mx:
				printf("TYPE:\tMX\n");
				memcpy((void *) &pref, (void *) ans+offset, sizeof(uint16_t));
				offset = offset + sizeof(uint16_t);
				pref	= ntohs(pref);
				conDnsNameToPars(ans+offset, nme);
				offset	= offset + rdlen - sizeof(uint16_t);
				printf("PREFERENCE:\t%u\n", pref);
				printf("EXCHANGE:\t%s\n", nme);	
				break;
			case aaaa:
				printf("TYPE:\tAAAA:\t");
				memcpy((void *) &aaaa_adr, (void *) ans+offset, rdlen);
				offset	= offset + rdlen;
				printf("RDATA:\t%s\n", inet_ntop(AF_INET6, &aaaa_adr, ipv6, IPV6STRLEN));	
				break;
			default:
				printf("SHOULDN'T BE HERE\n");
				break;
		}
	}

	return;
}
