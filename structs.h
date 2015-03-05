/*
 * * FILE NAME:		structs.h
 * * STRUCTURES FOR THE DNS SERVER
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	JUNE.6.2013
 * * DATE LAST MOD:	MARCH.4.2015
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
 * *	June.6.2013-solidified enumerated constants into typedefs and merged query with regular
 * *			-need to check out structure dnsHeader construct to see if can use with enums
 * *	June.27.2013-changed some unsigned to uint16_t 
 * *			-(used for network transmission so don't have to worry about endianness)
 * *	June.27.2013-added new structure and type to form header flags and change the structure type 
 * *			-DnsHeader to contain only uint16_t
 * *	July.4.2013-put in function prototype for function in parseMsgeDNS.c
 * *	July.13.2013-added/modified resouce records
 * *	August.21.2013-changed name to structs.h from parseMsgeDNS.h
 * *			-removed function prototype so that it can be moved to triez.h
 * *	December.16.2014-added in conditional statements to ensure file/variables added only once
 * *	March.4.2015-Altered ordering in resource records structures
 * */
/**********************************************************************/
// INCLUDE ONCE
#ifndef _STRUCTS_
#define _STRUCTS_ 1
#include <arpa/inet.h>
#include "dns_1.h"

/* Structures */
	/*Server Structs*/
/*
 * For use if ever switch to one client per thread
typedef struct cliInfo
{
	socklen_t		len;
	struct sockaddr_in	sockAddrInfo;
	char			msg[PKT_SZ];
	struct trieptr		*rt;
	double			start;
	FILE			*fptr;
}CliInfo;
*/
	/*Trie Structs*/
typedef struct trieptr
{
	char key;
	struct rr *val;
	struct trieptr *par;
	struct trieptr *snt;
	struct trieptr *spv;
	struct trieptr *cdn;
}Trie;

	/*Header Structs*/
typedef struct
{
	unsigned qr	: 1;
	unsigned opcode	: 4;
	unsigned aa	: 1;
	unsigned tc	: 1;
	unsigned rd	: 1;
	unsigned ra	: 1;
	unsigned z	: 3;
	unsigned rcode	: 4;
} DnsHdrFlags;

typedef struct 
{
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
}DnsHeader;

	/*Record Structs*/
typedef struct
{
	uint16_t qtype;
	uint16_t qclass;
}DnsQuery;

typedef struct rr
{
	struct arec 	*ars;
	struct nsrec	*nsrs;
	struct cnamerec	*cnamers;
	struct ptrrec	*ptrrs;
	struct mxrec	*mxrs;
	struct aaaarec	*aaaars; 
	struct soarec	*soars;
}RR;

typedef struct arec
{
	uint16_t	rdlen;
	uint16_t	rclass;
	int32_t		ttl;
	struct in_addr	address;

	struct arec	*anxt;
} A;

typedef struct nsrec
{
	uint16_t	rdlen;	
	uint16_t	rclass;
	int32_t		ttl;
	char		*nsdname;

	struct nsrec	*nsnxt;
} NS;

typedef struct cnamerec
{
	uint16_t	rdlen;
	uint16_t	rclass;
	int32_t		ttl;
	char		*cname;
} CNAME;

typedef struct soarec
{
	uint16_t	rdlen;
	uint16_t	rclass;
	char 		*mname;
	char		*rname;
	uint32_t	serial;
	int32_t		refresh;
	int32_t		retry;
	int32_t		expire;
	uint32_t	minimum;
} SOA;

typedef struct ptrrec
{
	uint16_t	rdlen;
	uint16_t	rclass;
	int32_t		ttl;
	char		*ptrdname;
} PTR;
	
typedef struct mxrec
{
	uint16_t	rdlen;
	uint16_t	rclass;
	int32_t		ttl;
	uint16_t	preference;
	char		*exchange;

	struct mxrec	*mxnxt;
} MX;

typedef struct aaaarec
{
	uint16_t	rdlen;
	uint16_t	rclass;
	int32_t		ttl;
	struct in6_addr	address;

	struct aaaarec	*aaaanxt;
} AAAA;

typedef enum 
{
	a = 1,
	ns,
	md,
	mf,
	cname,
	soa,
	mb,
	mg,
	mr,
	null,
	wks,
	ptr,
	hinfo,
	minfo,
	mx,
	txt,
	aaaa = 28,
	axfr = 252,
	mailb,
	maila,
	allTypes
}DnsType;

typedef enum
{
	in = 1,
	cs,
	ch,
	hs,
	allClasses = 255
}DnsClass;

#endif //end if structs.h
