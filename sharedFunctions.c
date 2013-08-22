/*
 * * FILE NAME: sharedFunctions.c
 * * CONTAINS FUNCTIONS SHARED BY CLIENT AND SERVER
 * * CREATED BY:   RICK W. WALLEN
 * * DATE CREATED: MAY.8.2013
 * * DATE LAST MOD: AUGUST.21.2013
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
 * *	August.2.2013-added code from test.c to this file
 * *	August.21.2013-renamed from createPktDNS.c to sharedFunctions.c
 * */
/**********************************************************************/
#include "sharedFunctions.h"
#include "dns_1.h"

/* F(X) FOR TIMESTAMPS */
double getTime()
{
	struct timeval t;
	struct timezone tzp;
	gettimeofday(&t, &tzp);
	return t.tv_sec + t.tv_usec*1e-6;
}

/* F(X) PUT QUERY IN STRING TO SEND UDP */
int qryToStr(char *dest, DnsQuery *org1, char *org2, int *offset)
{
	int offs = 0;
	
	offs = conDnsNameToSend(org2, dest);
		
	//strcpy(dest,org2);

	//offs = strlen(org2);

	org1->qtype = htons(org1->qtype);
	org1->qclass = htons(org1->qclass);

	memcpy((void *) (dest+offs), (void *) &org1->qtype, sizeof(uint16_t));
	offs = offs + sizeof(uint16_t);
	memcpy((void *) (dest+offs), (void *) &org1->qclass, sizeof(uint16_t));
	offs = offs + sizeof(uint16_t);
	(*offset) = *offset + offs;
	return 0;
}

/* F(X) PULL QUERY FROM STRING IN UDP */
int strToQry(char *org, DnsQuery *dest1, char *dest2, int *offset)
{
	int offs = 0;
	char buff[DNM_SZ];

	strcpy(buff, org);
	
	conDnsNameToPars(buff, dest2);

	offs = strlen(dest2) + 1;

	memcpy((void *) &dest1->qtype, (void *) (org+offs), sizeof(uint16_t));
	
	offs = offs + sizeof(uint16_t);

	memcpy((void *) &dest1->qclass, (void *) (org+offs), sizeof(uint16_t));
	offs = offs + sizeof(uint16_t);
		
        dest1->qtype = ntohs(dest1->qtype);
        dest1->qclass = ntohs(dest1->qclass);
	
	(*offset) = *offset + offs;

	return 0;
}

/* F(X) PUT HEADER IN STRING TO SEND UDP */
int hdrToStr(char *dest, DnsHeader *org)
{
	org->id      = htons(org->id);
	org->flags   = htons(org->flags);
	org->qdcount = htons(org->qdcount);
	org->ancount = htons(org->ancount);
	org->nscount = htons(org->nscount);
	org->arcount = htons(org->arcount);

	memcpy((void *) dest, (void *) &org->id, sizeof(uint16_t));
	memcpy((void *) (dest+sizeof(uint16_t)), (void *) &org->flags, sizeof(uint16_t));
	memcpy((void *) (dest+(sizeof(uint16_t)*2)), (void *) &org->qdcount, sizeof(uint16_t));
	memcpy((void *) (dest+(sizeof(uint16_t)*3)), (void *) &org->ancount, sizeof(uint16_t));
	memcpy((void *) (dest+(sizeof(uint16_t)*4)), (void *) &org->nscount, sizeof(uint16_t));
	memcpy((void *) (dest+(sizeof(uint16_t)*5)), (void *) &org->arcount, sizeof(uint16_t));	

	return 0;
}

/* F(X) PUT STRING TO HEADER FROM UDP */
int strToHdr(char *org, DnsHeader *dest)
{
	memcpy((void *) &dest->id, (void *) org, sizeof(uint16_t));
	memcpy((void *) &dest->flags, (void *) (org+sizeof(uint16_t)), sizeof(uint16_t));
	memcpy((void *) &dest->qdcount, (void *) (org+(sizeof(uint16_t)*2)), sizeof(uint16_t));
	memcpy((void *) &dest->ancount, (void *) (org+(sizeof(uint16_t)*3)), sizeof(uint16_t));
	memcpy((void *) &dest->nscount, (void *) (org+(sizeof(uint16_t)*4)), sizeof(uint16_t));
	memcpy((void *) &dest->arcount, (void *) (org+(sizeof(uint16_t)*5)), sizeof(uint16_t));

	dest->id      = ntohs(dest->id);
	dest->flags   = ntohs(dest->flags);
	dest->qdcount = ntohs(dest->qdcount);
	dest->ancount = ntohs(dest->ancount);
	dest->nscount = ntohs(dest->nscount);
	dest->arcount = ntohs(dest->arcount);

	return 0;
}

/* F(X) CONVERT DNS NAME FROM STD NOTATION TO QUERY NOTATION PER UNIVERSAL USE*/
int conDnsNameToSend(char *org, char *dest)
{
	int cnt;
	int i;
	int plc;

	cnt = 0;
	plc = 0;

	if((strlen(org) == 1) && (org[0] == '.'))
	{
		dest[0] = (uint8_t) 0;
		return 2;
	}
	for(i = 0; i <= strlen(org); i++)
	{
		if((org[i] == '.') || (org[i] == '\0'))
		{
			dest[plc] = (uint8_t) cnt;
			plc = i+1;
			if(cnt != 0)
			{
				dest[plc] = (uint8_t) 0;
			}
			cnt = 0;
		}
		else
		{
			dest[i+1] = org[i];
			cnt++;
		}
	}
	if(org[strlen(org)-1] != '.')
	{
		i++;
		dest[i] = (uint8_t) 0;
	}

	return i;
}

/*F(X) CONVERT DNS NAME FROM QUERY TO STD NOTATION */
void conDnsNameToPars( char *org, char *dest )
{
	uint8_t cnt;
	cnt = (uint8_t) *org++;

	if(cnt == 0)
	{
		*dest++ = '.';
		*dest++ = '\0';
		return;
	}
	while(cnt != 0)
	{
		cnt--;
		if(cnt == 0)
		{
			*dest++ = *org++;
			*dest++ = '.';
			cnt = (uint8_t) *org++;
		}
		else
			*dest++ = *org++;
	}
	*dest++ = '\0';

	return;
}

/*F(X) CONVERT DNS FLAGS TO 16BIT INT */
int flagsToU16I(DnsHdrFlags fg, uint16_t *hdr)
{
	*hdr = 0;
	*hdr   |= (((uint16_t) fg.qr) << 15)
		| (((uint16_t) fg.opcode) << 11)
		| (((uint16_t) fg.aa) << 10) 
		| (((uint16_t) fg.tc) << 9)
		| (((uint16_t) fg.rd) << 8)
		| (((uint16_t) fg.ra) << 7)
		| (((uint16_t) fg.z) << 4)
		| (((uint16_t) fg.rcode) << 0);

	return 0;
}

/*F(X) CONVERT 16 BIT INT FLAG INTO DNS FLAGS */
int u16IToFlags(DnsHdrFlags *fg, uint16_t hdr)
{
	fg->qr		= 0;	
	fg->opcode	= 0;
	fg->aa		= 0;
	fg->tc		= 0;
	fg->rd		= 0;
	fg->ra		= 0;
	fg->z		= 0;
	fg->rcode	= 0;

	fg->qr     |= (0x0001 & (hdr >> 15));
	fg->opcode |= (0x000F & (hdr >> 11));
	fg->aa     |= (0x0001 & (hdr >> 10));
	fg->tc     |= (0x0001 & (hdr >> 9));
	fg->rd     |= (0x0001 & (hdr >> 8));
	fg->ra     |= (0x0001 & (hdr >> 7));
	fg->z      |= (0x0007 & (hdr >> 4));
	fg->rcode  |= (0x000F & (hdr >> 0));
	
	return 0;
}

/*F(X) PRINT DNS HEADER */
void printHdr(DnsHeader hdr)
{
	DnsHdrFlags flg;
	u16IToFlags(&flg, hdr.flags);

	printf("ID:\t%u\n",hdr.id);
	//Print Flags
	printf("QR:\t%u\n", flg.qr);
	printf("OPCODE:\t%u\n", flg.opcode);
	printf("AA:\t%u\n", flg.aa);
	printf("TC:\t%u\n", flg.tc);
	printf("RD:\t%u\n", flg.rd);
	printf("RA:\t%u\n", flg.ra);
	printf("Z:\t%u\n", flg.z);
	printf("RCODE:\t%u\n", flg.rcode);

	printf("QDCOUNT:\t%u\n",hdr.qdcount);
	printf("ANCOUNT:\t%u\n",hdr.ancount);
	printf("NSCOUNT:\t%u\n",hdr.nscount);
	printf("ARCOUNT:\t%u\n",hdr.arcount);

	return;
}
/*F(X) PRINT RESOURCE RECORD*/
void printResRec(RR *rec)
{
	char ipv4[IPV4STRLEN];
	char ipv6[IPV6STRLEN];
	A	*ar;
	NS	*nsr;
	MX	*mxr;
	AAAA	*aaaar;

	printf("Resource Record\n");
	if(rec->ars != NULL)
	{
		
		printf("A address:\t%s\n",	
			inet_ntop(AF_INET, &rec->ars->address, ipv4, IPV4STRLEN));
		printf("A class:\t%u\n",	rec->ars->rclass);
		printf("A ttl:\t\t%d\n",	rec->ars->ttl);
		printf("A length:\t%u\n",	rec->ars->rdlen);
		ar = rec->ars;
		while(ar->anxt != NULL)
		{
			ar = ar->anxt;
			printf("A address:\t%s\n",	
				inet_ntop(AF_INET, &ar->address, ipv4, IPV4STRLEN));
			printf("A class:\t%u\n",	ar->rclass);
			printf("A ttl:\t\t%d\n",	ar->ttl);
			printf("A length:\t%u\n",	ar->rdlen);
		}	
	}
	if(rec->nsrs != NULL)
	{
		printf("NS name:\t%s\n",	rec->nsrs->nsdname);
		printf("NS class:\t%u\n",	rec->nsrs->rclass);
		printf("NS ttl:\t\t%d\n",	rec->nsrs->ttl);
		printf("NS length:\t%u\n",	rec->nsrs->rdlen);
		nsr = rec->nsrs;
		while(nsr->nsnxt != NULL)
		{
			nsr = nsr->nsnxt;
			printf("NS name:\t%s\n",	nsr->nsdname);
			printf("NS class:\t%u\n",	nsr->rclass);
			printf("NS ttl:\t\t%d\n",	nsr->ttl);
			printf("NS length:\t%u\n",	nsr->rdlen);
		}	
	}
	if(rec->cnamers != NULL)
	{
		printf("CNAME name:\t%s\n",	rec->cnamers->cname);
		printf("CNAME class:\t%u\n",	rec->cnamers->rclass);
		printf("CNAME ttl:\t\t%d\n",	rec->cnamers->ttl);
		printf("CNAME length:\t%u\n",	rec->cnamers->rdlen);
	}
	if(rec->ptrrs != NULL)
	{
		printf("PTR name:\t%s\n",	rec->ptrrs->ptrdname);
		printf("PTR class:\t%u\n",	rec->ptrrs->rclass);
		printf("PTR ttl:\t%d\n",	rec->ptrrs->ttl);
		printf("PTR length:\t%u\n",	rec->ptrrs->rdlen);
	}
	if(rec->mxrs != NULL)
	{
		printf("MX preference:\t%u\n",	rec->mxrs->preference);
		printf("MX exchange:\t%s\n",	rec->mxrs->exchange);
		printf("MX class:\t%u\n",	rec->mxrs->rclass);
		printf("MX ttl:\t\t%d\n",	rec->mxrs->ttl);
		printf("MX length:\t%u\n",	rec->mxrs->rdlen);
		mxr = rec->mxrs;
		while(mxr->mxnxt != NULL)
		{
			mxr = mxr->mxnxt;
			printf("MX preference:\t%u\n",	mxr->preference);
			printf("MX exchange:\t%s\n",	mxr->exchange);
			printf("MX class:\t%u\n",	mxr->rclass);
			printf("MX ttl:\t\t%d\n",	mxr->ttl);
			printf("MX length:\t%u\n",	mxr->rdlen);
		}	
	}
	if(rec->aaaars != NULL)
	{
		printf("AAAA address:\t%s\n",	
			inet_ntop( AF_INET6, &rec->aaaars->address, ipv6, IPV6STRLEN));
		printf("AAAA class:\t%u\n",	rec->aaaars->rclass);
		printf("AAAA ttl:\t\t%d\n",	rec->aaaars->ttl);
		printf("AAAA length:\t%u\n",	rec->aaaars->rdlen);
		aaaar = rec->aaaars;
		while(aaaar->aaaanxt != NULL)
		{
			aaaar = aaaar->aaaanxt;
			printf("AAAA address:\t%s\n",	
				inet_ntop( AF_INET6, &aaaar->address, ipv6, IPV6STRLEN));
			printf("AAAA class:\t%u\n",	aaaar->rclass);
			printf("AAAA ttl:\t\t%d\n",	aaaar->ttl);
			printf("AAAA length:\t%u\n",	aaaar->rdlen);
		}	
	}
	if(rec->soars != NULL)
	{
		printf("SOA mail:\t%s\n",	rec->soars->mname);
		printf("SOA name:\t%s\n",	rec->soars->rname);
		printf("SOA serial:\t%u\n",	rec->soars->serial);
		printf("SOA refresh:\t%d\n",	rec->soars->refresh);
		printf("SOA retry:\t%d\n",	rec->soars->retry);
		printf("SOA expire:\t%d\n",	rec->soars->expire);
		printf("SOA minimum:\t%u\n",	rec->soars->minimum);
		printf("SOA class:\t%u\n",	rec->soars->rclass);
		printf("SOA length:\t%u\n",	rec->soars->rdlen);
	}

	return;
}
