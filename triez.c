/*
 * * FILE NAME:		triez.c
 * * CONTAINS ALL FUNCTIONS UTILIZED BY DNS SERVER EXCEPT THOSE PERTAINING TO 
 * *	MULTITHREADING
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	APRIL.22.2013
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
 * *	April.22.2013-created revDN to reverse the domain name into the appropriate format
 * *	April.23.2013-modified revDN to be more efficient
 * *		-moved reading file into main f(x)
 * *	April.24.2013-moved reading file back into its own function so that a reload need 
 * * 			-do a function call
 * *		-modded revDN to accept root 
 * *	April.25.2013-modded f(x) to read file to read the rest of file separating fields by tabs
 * *	April.29.2013-created new f(x) to read file by character( able to determine delimiters and comments)
 * *	April.30.2013-found bug in revDN that if the domain was root then it didn't like it added a conditional to fix
 * *	May.8.2013-found/fixed bug in revDN...conditional was not set correctly for checking if the domain is root
 * *			- was just jumping out of function and not reversing domain names
 * *	July.13.2013-added/modifeid functions to add node to trie, create trie node, and search trie
 * *	July.14.2013-partially completed function to createResRec and tested to make sure it works
 * *	August.2.2013-added code from readZone.c to this file
 * *		-added a function to put the resource record in message buffer to send 
 * *	August.21.2013-added function from what was parseMsgeDNS.c that checks support of query type and query class
 * */
/**********************************************************************/
#include "triez.h"
#include "dns_1.h"

extern int daemonProc;
/* F(X) TO DAEMONIZE THE SERVER */
int daemonInit(const char *pname, int facility)
{
	int	i;
	pid_t	pid;
	
	if((pid = fork()) < 0)
		return(-1);
	else if(pid)
		_exit(0);//terminate parents

	//child 1 cont...
	
	if(setsid() < 0)
		return(-1);

	signal(SIGHUP, SIG_IGN);
	if((pid = fork()) < 0)
		return(-1);
	else if(pid)
		_exit(0);//terminate child 1
	
	//child 2 cont...
	
	daemonProc = 1;//for err_XXX() functions

	chdir("/");//change working directory to root directory

	//close off file descriptors
	for(i = 0; i < MAXFD; i++)
		close(i);

	//redirect stdin, stdout, & stderr to /dev/null
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);

	openlog(pname, LOG_PID, facility);

	return(0);
}

/* F(X) TO CHECK DOMAIN NAME DOESN'T CONTAIN INVALID CHARACTERS */
uint16_t checkDN(char *domName)
{
	int i;
	int sz;
	int de = 0;
	
	sz = strlen(domName);
	for(i = 0; i < sz; i++)
	{
		if(de > 63)
			return 1;
		else if((i == 0) || (de == 0))
		{
			if((isdigit(domName[i])) || (domName[i] == '-'))
				return 1;
			else if((isalpha(domName[i])) || (domName[i] == '-'))
				de++;
			else if(domName[i] == '.')
			{
				if((i == 0) && (sz > 1))
					return 1;
				else
					de = 0;
			}
			else
				return 1;
		}			
		else if((isalnum(domName[i])) || (domName[i] == '-'))
			de++;
		else if(domName[i] == '.')
			de = 0;
		else
			return 1;		
	}
	return 0;
}

/* F(X) TO CREATE A RESOUCE RECORD */
RR *createResRec(char *rec, uint32_t *ttlMin, uint16_t *rclass)
{
	int i, seg, c;
	uint32_t ttl;
	uint16_t class;
	uint16_t type;

	RR	*resrec;
	resrec = (RR *) malloc(sizeof(RR));

	resrec->ars	= NULL;
	resrec->nsrs	= NULL;
	resrec->cnamers	= NULL;
	resrec->ptrrs	= NULL;
	resrec->mxrs	= NULL;
	resrec->aaaars	= NULL;
	resrec->soars	= NULL;

	i = 0;
	seg = 0;
	class = 0;
	type = 0;

	if(strcmp(rec, "") == 0)
		return NULL;
	// Count number of delimiters
	for(i = 0; i <= strlen(rec); i++)
	{
		if(rec[i] == ',')
			seg++;
	}
	// Allocate 2d array
	char **buff = (char**) malloc(seg * sizeof (char*));
	// Variable for the current segment
	char *buff2 = (char *) malloc(LNE_SZ *sizeof(char));
	buff2 = strtok(rec, ",");
	
	for(i = 0; buff2 != NULL; i++)
	{
		buff[i] = malloc(strlen(buff2)*sizeof(char));
		buff[i] = strdup(buff2);
		buff2 = strtok(NULL, ",");
	}

	class = *rclass;

	if((seg-1 == 2 && strcmp(buff[0],"MX") != 0) || (seg-1 == 3 && strcmp(buff[0],"MX") == 0))
	{
		if(isdigit(buff[0][0]))
		{
			ttl =(uint32_t) atoi(buff[0]);
			c = 1;
		}
		else
			c = 0;
	}
	else if((seg-1 == 3 && strcmp(buff[1],"MX") != 0) || (seg-1 == 4 && strcmp(buff[1],"MX") == 0))
	{
		if(isdigit(buff[0][0]))
			ttl =(uint32_t) atoi(buff[0]);
		c = 1;
	}
	else
	{ 
		ttl = *ttlMin; 
		c = 0;
	}

	if(ttl < *ttlMin)
		ttl = *ttlMin;

	for(; c < seg; c++)
	{
		if(strcmp(buff[c], "IN") == 0)
			class = (uint16_t) in;
        
		else if(strcmp(buff[c], "CS") == 0)
			class = (uint16_t) cs;
        
		else if(strcmp(buff[c], "CH") == 0)
			class = (uint16_t) ch;
        
		else if(strcmp(buff[c], "HS") == 0)
			class = (uint16_t) hs;
        
		else if(strcmp(buff[c], "A") == 0)
			type = (uint16_t) a;
        
		else if(strcmp(buff[c], "NS") == 0)
			type = (uint16_t) ns;
        
		else if(strcmp(buff[c], "CNAME") == 0)
			type = (uint16_t) cname;
        
		else if(strcmp(buff[c], "SOA") == 0)
			type = (uint16_t) soa;
        
		else if(strcmp(buff[c], "PTR") == 0)
			type = (uint16_t) ptr;
        
		else if(strcmp(buff[c], "MX") == 0)
			type = (uint16_t) mx;
        
		else if(strcmp(buff[c], "AAAA") == 0)
			type = (uint16_t) aaaa;
		else
			break;
	}
        
	switch((DnsType) type)
	{
		case a:
			resrec->ars =		(A *) malloc(sizeof(A));
			if(inet_pton(AF_INET, buff[c], &resrec->ars->address) == 1);
			else
				printf("\n\nERROR\t%s\n\n", buff[c]);
			//resrec->ars->address =		strdup(buff[c]);
			resrec->ars->rclass =		class;
			resrec->ars->ttl =		ttl;
			resrec->ars->rdlen = 		sizeof(struct in_addr);
			//resrec->ars->rdlen = 		strlen(resrec->ars->address) +
			//				1;
			resrec->ars->anxt =		NULL;
			break;
		case ns:
			resrec->nsrs =		(NS *) malloc(sizeof(NS));
			resrec->nsrs->nsdname =		strdup(buff[c]);
			resrec->nsrs->rclass =		class;
			resrec->nsrs->ttl =		ttl;
			resrec->nsrs->rdlen = 		strlen(resrec->nsrs->nsdname) + 1;
			resrec->nsrs->nsnxt =		NULL;
			break;
		case cname:
			resrec->cnamers =		(CNAME *) malloc(sizeof(CNAME));
			resrec->cnamers->cname =	strdup(buff[c]);
			resrec->cnamers->rclass =	class;
			resrec->cnamers->ttl =		ttl;
			resrec->cnamers->rdlen = 	strlen(resrec->cnamers->cname) + 1;
			break;
		case soa:
			resrec->soars =			(SOA *) malloc(sizeof(SOA));
			resrec->soars->mname =		strdup(buff[c]);
			resrec->soars->rname =		strdup(buff[c+1]);
			resrec->soars->serial =		(uint32_t) atoi(buff[c+2]);
			resrec->soars->refresh =	(int32_t) atoi(buff[c+3]);
			resrec->soars->retry =		(int32_t) atoi(buff[c+4]);
			resrec->soars->expire =		(int32_t) atoi(buff[c+5]);
			resrec->soars->minimum =	(uint32_t) atoi(buff[c+6]);
			resrec->soars->rclass =		class;
			resrec->soars->rdlen =		strlen(resrec->soars->mname) + 1 +
							strlen(resrec->soars->rname) + 1 +
							sizeof(resrec->soars->serial) +
							sizeof(resrec->soars->refresh) +
							sizeof(resrec->soars->expire) +
							sizeof(resrec->soars->minimum);
			(*ttlMin) = (uint32_t) atoi(buff[c+6]);
			(*rclass) = class;
			break;
		case ptr:
			resrec->ptrrs =			(PTR *) malloc(sizeof(PTR));
			resrec->ptrrs->ptrdname =	strdup(buff[c]);
			resrec->ptrrs->rclass =		class;
			resrec->ptrrs->ttl =		ttl;
			resrec->ptrrs->rdlen = 		strlen(resrec->ptrrs->ptrdname) + 1;
			break;
		case mx:
			resrec->mxrs =			(MX *) malloc(sizeof(MX));
			resrec->mxrs->preference =	(uint16_t) atoi(buff[c]);	
			resrec->mxrs->exchange =	strdup(buff[c+1]);
			resrec->mxrs->rclass =		class;
			resrec->mxrs->ttl =		ttl;
			resrec->mxrs->rdlen = 		sizeof(resrec->mxrs->preference) +
							strlen(resrec->mxrs->exchange) + 1;
			resrec->mxrs->mxnxt =		NULL;
			break;
		case aaaa:
			resrec->aaaars =		(AAAA *) malloc(sizeof(AAAA));
			if(inet_pton(AF_INET6, buff[c], &resrec->aaaars->address) == 1);
			else
				printf("\n\nERROR\n\n");
			//resrec->aaaars->address =	strdup(buff[c]);
			resrec->aaaars->rclass =	class;
			resrec->aaaars->ttl =		ttl;
			resrec->aaaars->rdlen = 	sizeof(struct in6_addr);
			//resrec->aaaars->rdlen = 	strlen(resrec->aaaars->address) +
			//				1;
			resrec->aaaars->aaaanxt = NULL;
			break;
		default:
			return NULL;
			break;
	}

	return resrec;
}

/* F(X) TO CREATE A NODE IN TRIE */
Trie *createNode(char k, RR *v)
{
	Trie *node;
	node = (Trie *) malloc(sizeof(Trie));

	RR      *resrec;
	
	node->key = k;  
	node->par = NULL;
	node->snt = NULL;
	node->spv = NULL;
	node->cdn = NULL;
	if(v != NULL)
		node->val = v;
	else
	{
		resrec = (RR *) malloc(sizeof(RR));

		resrec->ars     = NULL;
		resrec->nsrs    = NULL;
		resrec->cnamers = NULL;
		resrec->ptrrs   = NULL;
		resrec->mxrs    = NULL;
		resrec->aaaars  = NULL;
		resrec->soars   = NULL;	

		node->val = resrec;
	}
	
	return node;
}

/* F(X) TO ADD TO TRIE */
void addTrie(Trie *root, char *name, RR *resrec)
{
	Trie *plc = NULL;
	int i = 0;
	int stl;
	struct arec     *aptr;
	struct nsrec    *nsptr;
	struct mxrec    *mxptr;
	struct aaaarec  *aaaaptr;

	stl = strlen(name);
	plc = root;
	if(plc->cdn == NULL)
	{
		for(i = 0; i <= stl; i++)
		{
			if(name[i+1] == '\0')
			{
				plc->cdn = createNode(name[i],resrec);
				plc->cdn->par = plc;
				plc =  plc->cdn;
			}
			else 
			{
				plc->cdn = createNode(name[i], NULL);
				plc->cdn->par = plc;
				plc = plc->cdn;
			}
		}
	}
	else
	{
		plc = plc->cdn;
		while(name[i] != '\0')
		{
			if(plc->key == name[i])
			{
				if((name[i+1] != '\0') && (plc->cdn != NULL))
				{
					plc = plc->cdn;
					i++;
				}
				else if(name[i+1] == '\0') 
				{ 
					//add the rr to plc
					if(resrec->ars != NULL)
					{
						aptr = plc->val->ars;
						if(aptr == NULL)
						{
							plc->val->ars = (A *) malloc(sizeof(A));
							plc->val->ars = resrec->ars;
						}
						else
						{
							while(aptr->anxt != NULL)
								aptr = aptr->anxt;
							aptr->anxt = resrec->ars;
						}
					}
					else if(resrec->nsrs != NULL)
					{
						nsptr = plc->val->nsrs;
						if(nsptr == NULL)
						{
							plc->val->nsrs = (NS *) malloc(sizeof(NS));
							plc->val->nsrs = resrec->nsrs;
						}
						else
						{
							while(nsptr->nsnxt != NULL)	
								nsptr = nsptr->nsnxt;
							nsptr->nsnxt = resrec->nsrs;
						}
					}
					else if(resrec->cnamers != NULL)
					{
						if(plc->val->cnamers == NULL)
						{
							plc->val->cnamers = (CNAME *) malloc(sizeof(CNAME) + resrec->cnamers->rdlen);
							plc->val->cnamers = resrec->cnamers;
						}
					}
					else if(resrec->ptrrs != NULL)
					{
						if(plc->val->ptrrs == NULL)
						{
							plc->val->ptrrs = (PTR *) malloc(sizeof(PTR) + resrec->ptrrs->rdlen);
							plc->val->ptrrs = resrec->ptrrs;
						}
					}
					else if(resrec->mxrs != NULL)
					{
						mxptr = plc->val->mxrs;
						if(mxptr == NULL)
						{
							plc->val->mxrs = (MX *) malloc(sizeof(MX) + resrec->mxrs->rdlen);
							plc->val->mxrs = resrec->mxrs;
						}
						else
						{
							while(mxptr->mxnxt != NULL)	
								mxptr->mxnxt = mxptr->mxnxt;
							mxptr = resrec->mxrs;
						}
					}
					else
					{
						aaaaptr = plc->val->aaaars;
						if(aaaaptr == NULL)
						{
							plc->val->aaaars = (AAAA *) malloc(sizeof(AAAA));
							plc->val->aaaars = resrec->aaaars;
						}
						else
						{
							while(aaaaptr->aaaanxt != NULL)	
								aaaaptr = aaaaptr->aaaanxt;
							aaaaptr->aaaanxt = resrec->aaaars;
						}
					}
					i++;
				}
				else
				{
					printf("Should never be here\n");
				}
			}
			else if(plc->snt != NULL)
				plc = plc->snt;
			else
			{
				if(name[i+1] != '\0')
				{
					//add trie plc->snt then point pls->snt->spv then put rest 
					//of the string down 
					plc->snt = createNode(name[i], NULL);
					plc->snt->spv = plc;
					plc = plc->snt;
					i++;					
					//add trie plc->cdn until string done
					while(name[i+1] != '\0')
					{
						plc->cdn = createNode(name[i], NULL);
						plc->cdn->par = plc;
						plc = plc->cdn;
						i++;
					}
					plc->cdn = createNode(name[i], resrec);
					plc->cdn->par = plc;
					plc = plc->cdn;
					i++;					
					plc->cdn = createNode(name[i], NULL);
					plc->cdn->par = plc;
					plc = plc->cdn;
				}
				else
				{
					plc->snt = createNode(name[i], resrec);
					plc->snt->spv = plc;
					plc = plc->snt;
					i++;					
					plc->cdn = createNode(name[i], NULL);
					plc->cdn->par = plc;
					plc = plc->cdn;
				}
			}
		}
	}
	return;
}

/* F(X) TO SEARCH TRIE */
Trie *searchTrie(Trie *root, char *search, uint16_t qt, uint16_t qc)
{
	Trie *plc;
	Trie *ans = NULL;
	int i = 0;
	struct arec     *aptr;
	struct nsrec    *nsptr;
	struct mxrec    *mxptr;
	struct aaaarec  *aaaaptr;

	if(root->cdn == NULL)
		return NULL;
	plc = root->cdn;
	while(search[i] != '\0')
	{
		if(toupper(search[i]) == toupper(plc->key))
		{
			i++;
			if(plc->val != NULL)
			{
				switch((DnsType) qt)
				{
					case a:
						if((plc->val->ars != NULL) && (search[i] == '\0'))
						{
							aptr = plc->val->ars;
							while(aptr != NULL)
							{
								if(aptr->rclass == qc)
									ans = plc;
								aptr = aptr->anxt;
							}
						}
						else if((plc->val->cnamers != NULL) && (search[i] == '\0'))
						{
							if(plc->val->cnamers->rclass == qc)
								ans = plc;
						}
						else if(plc->val->nsrs != NULL)
						{
							nsptr = plc->val->nsrs;
							while(nsptr != NULL)
							{
								if(nsptr->rclass == qc)
									ans = plc;
								nsptr = nsptr->nsnxt;
							}
						}
						break;  
					case ns:
						if(plc->val->nsrs != NULL)
						{
							nsptr = plc->val->nsrs;
							while(nsptr != NULL)
							{
								if(nsptr->rclass == qc)
									ans = plc;
								nsptr = nsptr->nsnxt;
							}
						}
						else if((plc->val->cnamers != NULL) && (search[i] == '\0'))
						{
							if(plc->val->cnamers->rclass == qc)
								ans = plc;
						}
						break;  
					case cname:
						if((plc->val->cnamers != NULL) && (search[i] == '\0'))
						{
							if(plc->val->cnamers->rclass == qc)
								ans = plc;
						}
						else if(plc->val->nsrs != NULL)
						{
							nsptr = plc->val->nsrs;
							while(nsptr != NULL)
							{
								if(nsptr->rclass == qc)
									ans = plc;
								nsptr = nsptr->nsnxt;
							}
						}
						break; 
					
					case soa:
						if((plc->val->soars != NULL) && (search[i] == '\0'))
						{
							if(plc->val->soars->rclass == qc)
								ans = plc;
						}
						else if((plc->val->cnamers != NULL) && (search[i] == '\0'))
						{
							if(plc->val->cnamers->rclass == qc)
								ans = plc;
						}
						else if(plc->val->nsrs != NULL)
						{
							nsptr = plc->val->nsrs;
							while(nsptr != NULL)
							{
								if(nsptr->rclass == qc)
									ans = plc;
								nsptr = nsptr->nsnxt;
							}
						}
						break;  
					
					case ptr:
						if((plc->val->ptrrs != NULL) && (search[i] == '\0'))
						{
							if(plc->val->ptrrs->rclass == qc)
								ans = plc;
						}
						else if((plc->val->cnamers != NULL) && (search[i] == '\0'))
						{
							if(plc->val->cnamers->rclass == qc)
								ans = plc;
						}
						else if(plc->val->nsrs != NULL)
						{
							nsptr = plc->val->nsrs;
							while(nsptr != NULL)
							{
								if(nsptr->rclass == qc)
									ans = plc;
								nsptr = nsptr->nsnxt;
							}
						}
						break;
					case mx:
						if((plc->val->mxrs != NULL) && (search[i] == '\0'))
						{
							mxptr = plc->val->mxrs;
							while(mxptr != NULL)
							{
								if(mxptr->rclass == qc)
									ans = plc;
								mxptr = mxptr->mxnxt;
							}
						}
						else if((plc->val->cnamers != NULL) && (search[i] == '\0'))
						{
							if(plc->val->cnamers->rclass == qc)
								ans = plc;
						}
						else if(plc->val->nsrs != NULL)
						{
							nsptr = plc->val->nsrs;
							while(nsptr != NULL)
							{
								if(nsptr->rclass == qc)
									ans = plc;
								nsptr = nsptr->nsnxt;
							}
						}
						break;
					case aaaa:
						if((plc->val->aaaars != NULL) && (search[i] == '\0'))
						{
							aaaaptr = plc->val->aaaars;
							while(aaaaptr != NULL)
							{
								if(aaaaptr->rclass == qc)
									ans = plc;
								aaaaptr = aaaaptr->aaaanxt;
							}
						}
						else if((plc->val->cnamers != NULL) && (search[i] == '\0'))
						{
							if(plc->val->cnamers->rclass == qc)
								ans = plc;
						}
						else if(plc->val->nsrs != NULL)
						{
							nsptr = plc->val->nsrs;
							while(nsptr != NULL)
							{
								if(nsptr->rclass == qc)
									ans = plc;
								nsptr = nsptr->nsnxt;
							}
						}
						break;
					default:
						if(plc->val->nsrs != NULL)
						{
							if(plc->val->nsrs->rclass == qc)
								ans = plc;
						}
						break;
				}
			}
			if(plc->cdn != NULL)
				plc = plc->cdn;
		}
		else if(plc->snt != NULL)
			plc = plc->snt;
		else
			break;
	}

	return ans;
}

/* F(X) TO PULL NAME FROM TRIE */
void findN(char *dest, Trie *start)
{
	Trie *plc;
	char buff[DNM_SZ];
	char buff2[DNM_SZ];
	int i = 0;
	int c;
	int seg = 0;
	int sz = 0;

	plc = start;
	while(plc->key != '*')
	{
		if(plc->key != '\0')
		{
			buff[i] = plc->key;
			i++;
		}
		if(plc->par != NULL)
			plc = plc->par;
		else
		{
			while(plc->spv != NULL)
				plc = plc->spv;
			plc = plc->par;
		}
	}
	buff[i] = '\0';

	if(strlen(buff) > 1)
	{
		c = strlen(buff)-1;
		for(i = 0; i <= strlen(buff); i++)
		{
			buff2[i] = buff[c];
			c--;
		}
		buff2[strlen(buff)+1] = '\0';

		for(i = 0; i <= strlen(buff2); i++)
		{
			if(buff2[i] == '.')
				seg++;
		}

		char **label = (char**) malloc(seg * sizeof (char*));
		char *curLabel = strtok(buff2, ".");

		for(i = 0; curLabel != NULL; i++)
		{
			label[i] = malloc(strlen(curLabel)*sizeof(char));
			label[i] = strdup(curLabel);
			curLabel = strtok(NULL, ".");
		}
		strcpy(buff,"");
		sz = i-1;
		for(i = sz; i >= 0; i--)
		{
			if(i != sz)
				strcat(buff, ".");
			strcat(buff, label[i]);
		}
		strcat(buff, ".");

		// Deallocate 2d array
		for(i = 0; i < seg; i++)
			free(label[i]);
		free(label);
	}
		strcpy(dest, buff);

		return;
}

/* F(X) TO DEL TO TRIE */
void delTrie(Trie *root)
{

	return;
}

/* F(X) TO PULL DATA FROM NODE AND RETRIEVE KEY */
void putResRecStr(DnsHdrFlags *fl, DnsHeader *head, Trie *root, Trie *result, DnsQuery *qry, char *msg, int *offs, char *search)
{
	struct arec     *aptr;
	struct nsrec    *nsptr;
	struct mxrec    *mxptr;
	struct aaaarec  *aaaaptr;
	uint16_t	rtype	= 0;
	uint16_t	rclass	= 0;
	uint16_t	rdlen	= 0;
	uint16_t	pref	= 0;
	int32_t		ttl	= 0;
	int32_t		refresh	= 0;	// SOA
	int32_t		retry	= 0;	// SOA
	int32_t		expire	= 0;	// SOA
	uint32_t	serial	= 0;	// SOA
	uint32_t	minimum	= 0;	// SOA
	int		sz	= 0;
	char		ans[DNM_SZ];	// Result of search 
	char		nme[DNM_SZ];	// Name 
	char		snme[DNM_SZ];	// Name 
	char		nsn[DNM_SZ];	// Name
	int offset;
	
	offset = 0;

	findN(nme, result);
	strcpy(snme, nme);
	uDN(snme);
	if((result->val->cnamers != NULL) && (qry->qtype != (uint16_t) cname) && (strcmp(search, snme) == 0))
	{
		//Restart search with cname and put cname in ans. sect.
		//Put result in msg and increment offset
		if(result->val->cnamers->rclass == qry->qclass)
		{
			rtype	= (uint16_t)cname;
			rclass	= result->val->cnamers->rclass;
			ttl	= result->val->cnamers->ttl;
			rdlen	= result->val->cnamers->rdlen;
			rtype	= htons(rtype);
			rclass	= htons(rclass);
			ttl	= htonl(ttl);
			rdlen	= htons(rdlen);

			strcpy(ans, result->val->cnamers->cname);
			sz = conDnsNameToSend(nme, msg + offset);
			offset = offset + sz;
			sz = 0;
			memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
			offset = offset + sizeof(uint16_t);
			memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
			offset = offset + sizeof(uint16_t);
			memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
			offset = offset + sizeof(int32_t);
			memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
			offset = offset + sizeof(uint16_t);
			sz = conDnsNameToSend(ans, msg + offset);
			offset = offset + sz;
			sz = 0;
			head->ancount = head->ancount + 1;

			revDN(ans);
			//uDN(ans);
			result = searchTrie(root, ans, qry->qtype, qry->qclass);
			if(result != NULL)
			{
				findN(nme, result);
				strcpy(snme,nme);
				uDN(snme);
				revDN(ans);
				uDN(ans);
			}
		}
		else
			result = NULL;
		if(result == NULL);
		else if((result->val->nsrs != NULL) && (strcmp(ans, snme) != 0))
		{
			//Put result in auth. sect restart search with all ns
			//put those results in addit. res. sect.
			nsptr = result->val->nsrs;
			while(nsptr != NULL)
			{
				if(nsptr->rclass == qry->qclass)
				{
					head->nscount = head->nscount + 1;

					rtype	= (uint16_t) ns;
					rclass	= nsptr->rclass;
					ttl	= nsptr->ttl;
					rdlen	= nsptr->rdlen;
					rtype	= htons(rtype);
					rclass	= htons(rclass);
					ttl	= htonl(ttl);
					rdlen	= htons(rdlen);

					strcpy(ans, nsptr->nsdname);
					sz = conDnsNameToSend(nme, msg + offset);
					offset = offset + sz;
					sz = 0;
					memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
					offset = offset + sizeof(int32_t);
					memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					sz = conDnsNameToSend(ans, msg + offset);
					offset = offset + sz;
					sz = 0;
				}
				nsptr = nsptr->nsnxt;					
			}
			nsptr = result->val->nsrs;
			while(nsptr != NULL)
			{
				if(nsptr->rclass == qry->qclass)
				{
					strcpy(nsn, nsptr->nsdname);
					revDN(nsn);
					strcpy(nme, nsptr->nsdname);
					result = searchTrie(root, nsn, (uint16_t) a, qry->qclass);
					if(result == NULL)
						aptr = NULL;
					else
						aptr = result->val->ars;
					while(aptr != NULL)
					{
						if(aptr->rclass == qry->qclass)
						{
							head->arcount = head->arcount + 1;

							rtype	= (uint16_t) a;
							rclass	= aptr->rclass;
							ttl	= aptr->ttl;
							rdlen	= aptr->rdlen;
							rtype	= htons(rtype);
							rclass	= htons(rclass);
							ttl	= htonl(ttl);
							rdlen	= htons(rdlen);

							sz = conDnsNameToSend(nme, msg + offset);
							offset = offset + sz;
							sz = 0;
							memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
							offset = offset + sizeof(int32_t);
							memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &aptr->address,  sizeof(struct in_addr));
							offset = offset + sizeof(struct in_addr);
						}
						aptr = aptr->anxt;
					}
					result = searchTrie(root, nsn, (uint16_t) aaaa, qry->qclass);
					if(result == NULL)
						aaaaptr = NULL;
					else
						aaaaptr = result->val->aaaars;
					while(aaaaptr != NULL)
					{
						if(aaaaptr->rclass == qry->qclass)
						{
							head->arcount = head->arcount + 1;

							rtype	= (uint16_t) aaaa;
							rclass	= aaaaptr->rclass;
							ttl	= aaaaptr->ttl;
							rdlen	= aaaaptr->rdlen;
							rtype	= htons(rtype);
							rclass	= htons(rclass);
							ttl	= htonl(ttl);
							rdlen	= htons(rdlen);

							sz = conDnsNameToSend(nme, msg + offset);
							offset = offset + sz;
							sz = 0;
							memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
							offset = offset + sizeof(int32_t);
							memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &aaaaptr->address,  sizeof(struct in6_addr));
							offset = offset + sizeof(struct in6_addr);
						}
						aaaaptr = aaaaptr->aaaanxt;
					}
				}
				nsptr = nsptr->nsnxt;
			}
		}//end ns and additional records
		else
		{
			//Check to see if there is a RR coresponding to type
			switch((DnsType) qry->qtype)
			{
				case a:
					aptr = result->val->ars;
					while(aptr != NULL)
					{
						if(aptr->rclass == qry->qclass)
						{
							head->ancount = head->ancount + 1;

							rtype	= (uint16_t) a;
							rclass	= aptr->rclass;
							ttl	= aptr->ttl;
							rdlen	= aptr->rdlen;
							rtype	= htons(rtype);
							rclass	= htons(rclass);
							ttl	= htonl(ttl);
							rdlen	= htons(rdlen);

							sz = conDnsNameToSend(nme, msg + offset);
							offset = offset + sz;
							sz = 0;
							memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
							offset = offset + sizeof(int32_t);
							memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &aptr->address,  sizeof(struct in_addr));
							offset = offset + sizeof(struct in_addr);
						}
						aptr = aptr->anxt;
					}
					break;
				case ns:
					nsptr = result->val->nsrs;
					while(nsptr != NULL)
					{
						if(nsptr->rclass == qry->qclass)
						{
							head->ancount = head->ancount + 1;

							rtype	= (uint16_t) ns;
							rclass	= nsptr->rclass;
							ttl	= nsptr->ttl;
							rdlen	= nsptr->rdlen;
							rtype	= htons(rtype);
							rclass	= htons(rclass);
							ttl	= htonl(ttl);
							rdlen	= htons(rdlen);

							strcpy(ans, nsptr->nsdname);
							sz = conDnsNameToSend(nme, msg + offset);
							offset = offset + sz;
							sz = 0;
							memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
							offset = offset + sizeof(int32_t);
							memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							sz = conDnsNameToSend(ans, msg + offset);
							offset = offset + sz;
							sz = 0;
						}
						nsptr = nsptr->nsnxt;					
					}	
					break;
				case soa:
					if(result->val->soars->rclass == qry->qclass)
					{
						head->ancount = head->ancount + 1;

						rtype	= (uint16_t) soa;
						rclass	= result->val->soars->rclass;
						rdlen	= result->val->soars->rdlen;
						serial	= result->val->soars->serial;
						refresh	= result->val->soars->refresh;
						retry	= result->val->soars->retry;
						expire	= result->val->soars->expire;
						minimum	= result->val->soars->minimum;
						rtype	= htons(rtype);
						rclass	= htons(rclass);
						ttl	= htonl((int32_t)0);
						rdlen	= htons(rdlen);
						serial	= htonl(serial);
						refresh	= htonl(refresh);
						retry	= htonl(retry);
						expire	= htonl(expire);
						minimum	= htonl(minimum);

						sz = conDnsNameToSend(nme, msg + offset);
						offset = offset + sz;
						sz = 0;
						memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						strcpy(ans, result->val->soars->mname);
						sz = conDnsNameToSend(ans, msg + offset);
						offset = offset + sz;
						sz = 0;
						strcpy(ans, result->val->soars->rname);
						sz = conDnsNameToSend(ans, msg + offset);
						offset = offset + sz;
						sz = 0;
						memcpy((void *) msg + offset, (void *) &serial, sizeof(uint32_t));
						offset = offset + sizeof(uint32_t);
						memcpy((void *) msg + offset, (void *) &refresh, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &retry, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &expire, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &minimum, sizeof(uint32_t));
						offset = offset + sizeof(uint32_t);
					}
					break;
				case mx:
					mxptr = result->val->mxrs;
					while(mxptr != NULL)
					{
						if(mxptr->rclass == qry->qclass)
						{
							head->ancount = head->ancount + 1;

							rtype	= (uint16_t) mx;
							rclass	= mxptr->rclass;
							ttl	= mxptr->ttl;
							rdlen	= mxptr->rdlen;
							pref	= mxptr->preference;
							rtype	= htons(rtype);
							rclass	= htons(rclass);
							ttl	= htonl(ttl);
							rdlen	= htons(rdlen);
							pref	= htons(pref);

							strcpy(ans, mxptr->exchange);
							sz = conDnsNameToSend(nme, msg + offset);
							offset = offset + sz;
							sz = 0;
							memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
							offset = offset + sizeof(int32_t);
							memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &pref, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							sz = conDnsNameToSend(ans, msg + offset);
							offset = offset + sz;
							sz = 0;
						}
						mxptr = mxptr->mxnxt;
					}
					break;
				case aaaa:
					aaaaptr = result->val->aaaars;
					while(aaaaptr != NULL)
					{
						if(aaaaptr->rclass == qry->qclass)
						{
							head->ancount = head->ancount + 1;

							rtype	= (uint16_t) aaaa;
							rclass	= aaaaptr->rclass;
							ttl	= aaaaptr->ttl;
							rdlen	= aaaaptr->rdlen;
							rtype	= htons(rtype);
							rclass	= htons(rclass);
							ttl	= htonl(ttl);
							rdlen	= htons(rdlen);

							sz = conDnsNameToSend(nme, msg + offset);
							offset = offset + sz;
							sz = 0;
							memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
							offset = offset + sizeof(int32_t);
							memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &aaaaptr->address,  sizeof(struct in6_addr));
							offset = offset + sizeof(struct in6_addr);
						}
						aaaaptr = aaaaptr->aaaanxt;
					}
					break;
				default:
					//we didn't catch something
					fl->rcode = 2;
					break;
			}//end switch
			if((result->val->nsrs != NULL) && (head->ancount == 1))
			{
				//Put result in auth. sect restart search with all ns
				//put those results in addit. res. sect.
				nsptr = result->val->nsrs;
				while(nsptr != NULL)
				{
					if(nsptr->rclass == qry->qclass)
					{
						head->nscount = head->nscount + 1;

						rtype	= (uint16_t) ns;
						rclass	= nsptr->rclass;
						ttl	= nsptr->ttl;
						rdlen	= nsptr->rdlen;
						rtype	= htons(rtype);
						rclass	= htons(rclass);
						ttl	= htonl(ttl);
						rdlen	= htons(rdlen);

						strcpy(ans, nsptr->nsdname);
						sz = conDnsNameToSend(nme, msg + offset);
						offset = offset + sz;
						sz = 0;
						memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						sz = conDnsNameToSend(ans, msg + offset);
						offset = offset + sz;
						sz = 0;
					}
					nsptr = nsptr->nsnxt;					
				}
				nsptr = result->val->nsrs;
				while(nsptr != NULL)
				{
					if(nsptr->rclass == qry->qclass)
					{
						strcpy(nsn, nsptr->nsdname);
						revDN(nsn);
						strcpy(nme, nsptr->nsdname);
						result = searchTrie(root, nsn, (uint16_t) a, qry->qclass);
						if(result == NULL)
							aptr = NULL;
						else
							aptr = result->val->ars;
						while(aptr != NULL)
						{
							if(aptr->rclass == qry->qclass)
							{
								head->arcount = head->arcount + 1;

								rtype	= (uint16_t) a;
								rclass	= aptr->rclass;
								ttl	= aptr->ttl;
								rdlen	= aptr->rdlen;
								rtype	= htons(rtype);
								rclass	= htons(rclass);
								ttl	= htonl(ttl);
								rdlen	= htons(rdlen);

								sz = conDnsNameToSend(nme, msg + offset);
								offset = offset + sz;
								sz = 0;
								memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
								offset = offset + sizeof(uint16_t);
								memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
								offset = offset + sizeof(uint16_t);
								memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
								offset = offset + sizeof(int32_t);
								memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
								offset = offset + sizeof(uint16_t);
								memcpy((void *) msg + offset, (void *) &aptr->address,  sizeof(struct in_addr));
								offset = offset + sizeof(struct in_addr);
							}
							aptr = aptr->anxt;
						}
						result = searchTrie(root, nsn, (uint16_t) aaaa, qry->qclass);
						if(result == NULL)
							aaaaptr = NULL;
						else
							aaaaptr = result->val->aaaars;
						while(aaaaptr != NULL)
						{
							if(aaaaptr->rclass == qry->qclass)
							{
								head->arcount = head->arcount + 1;

								rtype	= (uint16_t) aaaa;
								rclass	= aaaaptr->rclass;
								ttl	= aaaaptr->ttl;
								rdlen	= aaaaptr->rdlen;
								rtype	= htons(rtype);
								rclass	= htons(rclass);
								ttl	= htonl(ttl);
								rdlen	= htons(rdlen);

								sz = conDnsNameToSend(nme, msg + offset);
								offset = offset + sz;
								sz = 0;
								memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
								offset = offset + sizeof(uint16_t);
								memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
								offset = offset + sizeof(uint16_t);
								memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
								offset = offset + sizeof(int32_t);
								memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
								offset = offset + sizeof(uint16_t);
								memcpy((void *) msg + offset, (void *) &aaaaptr->address,  sizeof(struct in6_addr));
								offset = offset + sizeof(struct in6_addr);
							}
							aaaaptr = aaaaptr->aaaanxt;
						}
					}//end class check
					nsptr = nsptr->nsnxt;
				}//end while
			}//end ns and additional records
		}//end else
	}//end cname
	else if((result->val->nsrs != NULL) && (strcmp(search, snme) != 0))
	{
		//Put result in auth. sect restart search with all ns
		//put those results in addit. res. sect.
		nsptr = result->val->nsrs;
		while(nsptr != NULL)
		{
			if(nsptr->rclass == qry->qclass)
			{
				head->nscount = head->nscount + 1;

				rtype	= (uint16_t) ns;
				rclass	= nsptr->rclass;
				ttl	= nsptr->ttl;
				rdlen	= nsptr->rdlen;
				rtype	= htons(rtype);
				rclass	= htons(rclass);
				ttl	= htonl(ttl);
				rdlen	= htons(rdlen);

				strcpy(ans, nsptr->nsdname);
				sz = conDnsNameToSend(nme, msg + offset);
				offset = offset + sz;
				sz = 0;
				memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
				offset = offset + sizeof(uint16_t);
				memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
				offset = offset + sizeof(uint16_t);
				memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
				offset = offset + sizeof(int32_t);
				memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
				offset = offset + sizeof(uint16_t);
				sz = conDnsNameToSend(ans, msg + offset);
				offset = offset + sz;
				sz = 0;
			}
			nsptr = nsptr->nsnxt;					
		}
		nsptr = result->val->nsrs;
		while(nsptr != NULL)
		{
			if(nsptr->rclass == qry->qclass)
			{
				strcpy(nsn, nsptr->nsdname);
				revDN(nsn);
				strcpy(nme, nsptr->nsdname);
				result = searchTrie(root, nsn, (uint16_t) a, qry->qclass);
				if(result == NULL)
					aptr = NULL;
				else
					aptr = result->val->ars;
				while(aptr != NULL)
				{
					if(aptr->rclass == qry->qclass)
					{
						head->arcount = head->arcount + 1;

						rtype	= (uint16_t) a;
						rclass	= aptr->rclass;
						ttl	= aptr->ttl;
						rdlen	= aptr->rdlen;
						rtype	= htons(rtype);
						rclass	= htons(rclass);
						ttl	= htonl(ttl);
						rdlen	= htons(rdlen);

						sz = conDnsNameToSend(nme, msg + offset);
						offset = offset + sz;
						sz = 0;
						memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &aptr->address,  sizeof(struct in_addr));
						offset = offset + sizeof(struct in_addr);
					}
					aptr = aptr->anxt;
				}
				result = searchTrie(root, nsn, (uint16_t) aaaa, qry->qclass);
				if(result == NULL)
					aaaaptr = NULL;
				else
					aaaaptr = result->val->aaaars;
				while(aaaaptr != NULL)
				{
					if(aaaaptr->rclass == qry->qclass)
					{
						head->arcount = head->arcount + 1;

						rtype	= (uint16_t) aaaa;
						rclass	= aaaaptr->rclass;
						ttl	= aaaaptr->ttl;
						rdlen	= aaaaptr->rdlen;
						rtype	= htons(rtype);
						rclass	= htons(rclass);
						ttl	= htonl(ttl);
						rdlen	= htons(rdlen);

						sz = conDnsNameToSend(nme, msg + offset);
						offset = offset + sz;
						sz = 0;
						memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &aaaaptr->address,  sizeof(struct in6_addr));
						offset = offset + sizeof(struct in6_addr);
					}
					aaaaptr = aaaaptr->aaaanxt;
				}
			}//end class check
			nsptr = nsptr->nsnxt;
		}//end while
	}//end ns and additional record
	else
	{
		//Check to see if there is a RR coresponding to type
		switch((DnsType) qry->qtype)
		{
			case a:
				aptr = result->val->ars;
				while(aptr != NULL)
				{
					if(aptr->rclass == qry->qclass)
					{
						head->ancount = head->ancount + 1;

						rtype	= (uint16_t) a;
						rclass	= aptr->rclass;
						ttl	= aptr->ttl;
						rdlen	= aptr->rdlen;
						rtype	= htons(rtype);
						rclass	= htons(rclass);
						ttl	= htonl(ttl);
						rdlen	= htons(rdlen);

						sz = conDnsNameToSend(nme, msg + offset);
						offset = offset + sz;
						sz = 0;
						memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &ttl, sizeof(uint32_t));
						offset = offset + sizeof(uint32_t);
						memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &aptr->address,  sizeof(struct in_addr));
						offset = offset + sizeof(struct in_addr);
					}
					aptr = aptr->anxt;
				}
				break;
			case ns:
				nsptr = result->val->nsrs;
				while(nsptr != NULL)
				{
					if(nsptr->rclass == qry->qclass)
					{
						head->ancount = head->ancount + 1;

						rtype	= (uint16_t) ns;
						rclass	= nsptr->rclass;
						ttl	= nsptr->ttl;
						rdlen	= nsptr->rdlen;
						rtype	= htons(rtype);
						rclass	= htons(rclass);
						ttl	= htonl(ttl);
						rdlen	= htons(rdlen);

						strcpy(ans, nsptr->nsdname);
						sz = conDnsNameToSend(nme, msg + offset);
						offset = offset + sz;
						sz = 0;
						memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						sz = conDnsNameToSend(ans, msg + offset);
						offset = offset + sz;
						sz = 0;
					}
					nsptr = nsptr->nsnxt;
				}
				break;
			case cname:
				if(result->val->cnamers->rclass == qry->qclass)
				{
					head->ancount = head->ancount + 1;

					rtype	= (uint16_t) cname;
					rclass	= result->val->cnamers->rclass;
					ttl	= result->val->cnamers->ttl;
					rdlen	= result->val->cnamers->rdlen;
					rtype	= htons(rtype);
					rclass	= htons(rclass);
					ttl	= htonl(ttl);
					rdlen	= htons(rdlen);

					strcpy(ans, result->val->cnamers->cname);
					sz = conDnsNameToSend(nme, msg + offset);
					offset = offset + sz;
					sz = 0;
					memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
					offset = offset + sizeof(int32_t);
					memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					sz = conDnsNameToSend(ans, msg + offset);
					offset = offset + sz;
					sz = 0;
				}
				break;
			case soa:
				if(result->val->soars->rclass == qry->qclass)
				{
					head->ancount = head->ancount + 1;

					rtype	= (uint16_t) soa;
					rclass	= result->val->soars->rclass;
					rdlen	= result->val->soars->rdlen;
					serial	= result->val->soars->serial;
					refresh	= result->val->soars->refresh;
					retry	= result->val->soars->retry;
					expire	= result->val->soars->expire;
					minimum	= result->val->soars->minimum;
					rtype	= htons(rtype);
					rclass	= htons(rclass);
					ttl	= htonl((int32_t)0);
					rdlen	= htons(rdlen);
					serial	= htonl(serial);
					refresh	= htonl(refresh);
					retry	= htonl(retry);
					expire	= htonl(expire);
					minimum	= htonl(minimum);

					sz = conDnsNameToSend(nme, msg + offset);
					offset = offset + sz;
					sz = 0;
					memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
					offset = offset + sizeof(int32_t);
					memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					strcpy(ans, result->val->soars->mname);
					sz = conDnsNameToSend(ans, msg + offset);
					offset = offset + sz;
					sz = 0;
					strcpy(ans, result->val->soars->rname);
					sz = conDnsNameToSend(ans, msg + offset);
					offset = offset + sz;
					sz = 0;
					memcpy((void *) msg + offset, (void *) &serial, sizeof(uint32_t));
					offset = offset + sizeof(uint32_t);
					memcpy((void *) msg + offset, (void *) &refresh, sizeof(int32_t));
					offset = offset + sizeof(int32_t);
					memcpy((void *) msg + offset, (void *) &retry, sizeof(int32_t));
					offset = offset + sizeof(int32_t);
					memcpy((void *) msg + offset, (void *) &expire, sizeof(int32_t));
					offset = offset + sizeof(int32_t);
					memcpy((void *) msg + offset, (void *) &minimum, sizeof(uint32_t));
					offset = offset + sizeof(uint32_t);
				}
				break;
			case ptr:
				if(result->val->ptrrs->rclass == qry->qclass)
				{
					head->ancount = head->ancount + 1;

					rtype	= (uint16_t) ptr;
					rclass	= result->val->ptrrs->rclass;
					ttl	= result->val->ptrrs->ttl;
					rdlen	= result->val->ptrrs->rdlen;
					rtype	= htons(rtype);
					rclass	= htons(rclass);
					ttl	= htonl(ttl);
					rdlen	= htons(rdlen);

					strcpy(ans, result->val->ptrrs->ptrdname);
					sz = conDnsNameToSend(nme, msg + offset);
					offset = offset + sz;
					sz = 0;
					memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
					offset = offset + sizeof(int32_t);
					memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					sz = conDnsNameToSend(ans, msg + offset);
					offset = offset + sz;
					sz = 0;
				}
				break;
			case mx:
				mxptr = result->val->mxrs;
				while(mxptr != NULL)
				{
					if(mxptr->rclass == qry->qclass)
					{
						head->ancount = head->ancount + 1;

						rtype	= (uint16_t) mx;
						rclass	= mxptr->rclass;
						ttl	= mxptr->ttl;
						rdlen	= mxptr->rdlen;
						pref	= mxptr->preference;
						rtype	= htons(rtype);
						rclass	= htons(rclass);
						ttl	= htonl(ttl);
						rdlen	= htons(rdlen);
						pref 	= htons(pref);

						strcpy(ans, mxptr->exchange);
						sz = conDnsNameToSend(nme, msg + offset);
						offset = offset + sz;
						sz = 0;
						memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &pref, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						sz = conDnsNameToSend(ans, msg + offset);
						offset = offset + sz;
						sz = 0;
					}
					mxptr = mxptr->mxnxt;
				}
				break;
			case aaaa:
				aaaaptr = result->val->aaaars;
				while(aaaaptr != NULL)
				{
					if(aaaaptr->rclass == qry->qclass)
					{
						head->ancount = head->ancount + 1;

						rtype	= (uint16_t) aaaa;
						rclass	= aaaaptr->rclass;
						ttl	= aaaaptr->ttl;
						rdlen	= aaaaptr->rdlen;
						rtype	= htons(rtype);
						rclass	= htons(rclass);
						ttl	= htonl(ttl);
						rdlen	= htons(rdlen);

						sz = conDnsNameToSend(nme, msg + offset);
						offset = offset + sz;
						sz = 0;
						memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
						offset = offset + sizeof(int32_t);
						memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
						offset = offset + sizeof(uint16_t);
						memcpy((void *) msg + offset, (void *) &aaaaptr->address,  sizeof(struct in6_addr));
						offset = offset + sizeof(struct in6_addr);
					}
					aaaaptr = aaaaptr->aaaanxt;
				}
				break;
			default:
				//we didn't catch something
				fl->rcode = 2;
				break;
		}//end switch
		if((result->val->nsrs != NULL) && (head->ancount == 0))
		{
			//Put result in auth. sect restart search with all ns
			//put those results in addit. res. sect.
			nsptr = result->val->nsrs;
			while(nsptr != NULL)
			{
				if(nsptr->rclass == qry->qclass)
				{
					head->nscount = head->nscount + 1;

					rtype	= (uint16_t) ns;
					rclass	= nsptr->rclass;
					ttl	= nsptr->ttl;
					rdlen	= nsptr->rdlen;
					rtype	= htons(rtype);
					rclass	= htons(rclass);
					ttl	= htonl(ttl);
					rdlen	= htons(rdlen);

					strcpy(ans, nsptr->nsdname);
					sz = conDnsNameToSend(nme, msg + offset);
					offset = offset + sz;
					sz = 0;
					memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
					offset = offset + sizeof(int32_t);
					memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
					offset = offset + sizeof(uint16_t);
					sz = conDnsNameToSend(ans, msg + offset);
					offset = offset + sz;
					sz = 0;
				}
				nsptr = nsptr->nsnxt;					
			}
			nsptr = result->val->nsrs;
			while(nsptr != NULL)
			{
				if(nsptr->rclass == qry->qclass)
				{
					strcpy(nsn, nsptr->nsdname);
					revDN(nsn);
					strcpy(nme, nsptr->nsdname);
					result = searchTrie(root, nsn, (uint16_t) a, qry->qclass);
					if(result == NULL)
						aptr = NULL;
					else
						aptr = result->val->ars;
					while(aptr != NULL)
					{
						if(aptr->rclass == qry->qclass)
						{
							head->arcount = head->arcount + 1;

							rtype	= (uint16_t) a;
							rclass	= aptr->rclass;
							ttl	= aptr->ttl;
							rdlen	= aptr->rdlen;
							rtype	= htons(rtype);
							rclass	= htons(rclass);
							ttl	= htonl(ttl);
							rdlen	= htons(rdlen);

							sz = conDnsNameToSend(nme, msg + offset);
							offset = offset + sz;
							sz = 0;
							memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
							offset = offset + sizeof(int32_t);
							memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &aptr->address,  sizeof(struct in_addr));
							offset = offset + sizeof(struct in_addr);
						}
						aptr = aptr->anxt;
					}
					result = searchTrie(root, nsn, (uint16_t) aaaa, qry->qclass);
					if(result == NULL)
						aaaaptr = NULL;
					else
						aaaaptr = result->val->aaaars;
					while(aaaaptr != NULL)
					{
						if(aaaaptr->rclass == qry->qclass)
						{
							head->arcount = head->arcount + 1;

							rtype	= (uint16_t) aaaa;
							rclass	= aaaaptr->rclass;
							ttl	= aaaaptr->ttl;
							rdlen	= aaaaptr->rdlen;
							rtype	= htons(rtype);
							rclass	= htons(rclass);
							ttl	= htonl(ttl);
							rdlen	= htons(rdlen);

							sz = conDnsNameToSend(nme, msg + offset);
							offset = offset + sz;
							sz = 0;
							memcpy((void *) msg + offset, (void *) &rtype, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &rclass, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &ttl, sizeof(int32_t));
							offset = offset + sizeof(int32_t);
							memcpy((void *) msg + offset, (void *) &rdlen, sizeof(uint16_t));
							offset = offset + sizeof(uint16_t);
							memcpy((void *) msg + offset, (void *) &aaaaptr->address,  sizeof(struct in6_addr));
							offset = offset + sizeof(struct in6_addr);
						}
						aaaaptr = aaaaptr->aaaanxt;
					}
				}//end class check
				nsptr = nsptr->nsnxt;
			}//end while
		}//end ns and additional records
	}//end else ie normal query

	*offs = *offs + offset;
	return;
} 

/*F(X) TO MAKE DOMAIN NAME UPPER FOR COMPARISON AND APPENDS A '.' IF NOT AT THE END*/
void uDN(char *dom)
{
	int i;
	char *u = (char *) malloc(sizeof(char) * strlen(dom) + 1);

	for(i = 0; i <= strlen(dom); i++)
		u[i] = toupper(dom[i]);
	
	if(dom[strlen(dom)-1] != '.' && dom[0] != '@')
	{
		u[strlen(dom)] = '.';
		u[strlen(dom)+1] = '\0';
	}

	strcpy(dom, u);
		
	return;
}

/* F(X) TO TAKE IN STRING OF ZONE FILE NAME AND CREATE DB */
Trie *readZone(char *fn)
{
	FILE *fp;
	char buff;
	char domNme[DNM_SZ];
	char domNme2[DNM_SZ];
	char rR[LNE_SZ];
	char rR2[LNE_SZ];
	int i;
	uint32_t dTtl = 0; //default ttl gets redefined by SOA
	uint16_t dClass = 0; //default class gets redefined by SOA
	RR *rrs;
	Trie *root;

	root = createNode('*',  NULL);
	
	if((fp = fopen(fn, "r")) == NULL)
		return NULL;

	while(!feof(fp))
	{
		buff = fgetc(fp);
		if(buff == EOF)
			break;

		// If line is a comment then ignore it
		else if(buff == ';')
		{
			while(buff != '\n' && buff != EOF)
				buff = fgetc(fp);
		}	

		// Read in Domain Name
		if(buff != '\t' && buff != ' ' && buff != '\n')
		{
			i = 0;
			strcpy(domNme,"");
			while(buff != ';' && buff != '(' && buff != '\t' && buff != ' ' && buff != EOF)
			{
				domNme[i] = buff;
				i++;
				buff = fgetc(fp);
			}
			domNme[i] = '\0';
			strcpy(domNme2, domNme);
			revDN(domNme);
		}

		// Read in Resource Record
		strcpy(rR2,"");
		while(buff != '\n' && buff != EOF)
		{
			if(buff == ';' || buff == '(');
			else
				buff = fgetc(fp);
			// Reached the beginning of a comment therefore ignore ignore the rest of the line
			if(buff == ';')
			{
				while(buff != '\n' && buff != EOF)
					buff = fgetc(fp);
			}
			// Reached the beginning of a multilined statement, this usually is with the SOA
			else if(buff == '(')
			{
				while(buff != ')')
				{
					// Reached the beginning of a comment so we can ignore the rest of the line
					if(buff == ';')
					{
						while(buff != '\n' && buff != EOF)
							buff = fgetc(fp);
					}
					buff = fgetc(fp);
					i = 0;
					strcpy(rR, "");
					while(buff != ';' && buff != ')' && buff != '\t' && buff != ' ' && buff != '\n' && buff != EOF)
					{
						rR[i] = buff;
						i++;
						buff = fgetc(fp);
					}
					rR[i] = '\0';
					if(strcmp(rR, "") != 0)
					{
						strcat(rR2, rR);
						strcat(rR2, ",");
					}
				}
			}
			else
			{
				i = 0;
				strcpy(rR, "");
				while(buff != ';' && buff != '(' && buff != '\t' && buff != ' ' && buff != '\n' && buff != EOF)
				{
					rR[i] = buff;
					i++;
					buff = fgetc(fp);
				}
				rR[i] = '\0';
				if(strcmp(rR, "" ) != 0)
				{
					strcat(rR2, rR);
					strcat(rR2, ",");
				}
			}
		}
		//This is where we call to make trie but before do we need to put the chars into RR's?
		if(strcmp(rR2, "") != 0)
		{
			rrs = createResRec(rR2, &dTtl, &dClass);
			if(rrs != NULL)
			{
				if(rrs->ptrrs != NULL)
					addTrie(root, domNme, rrs);
				else if(checkDN(domNme2) == 0)
					addTrie(root, domNme, rrs);					
			}
		}

	}

	fclose(fp);
	return root;
}

/* F(X) TO REVERSE DOMAIN NAME */
int revDN(char *DN)
{
	int i = 0;
	int sz = 0;
	int seg = 0;
	char tmp[DNM_SZ] = "";
	char last = DN[strlen(DN) - 1];

	if (strcmp(DN, "") == 0)
		return 1;
	else if(strcmp(DN, ".") == 0)
		return 0;
	// Count number of delimiters
	for(i=0; i <= strlen(DN); i++)
	{
		if(DN[i] == '.')
			seg++;
	}
	// Allocate 2d array
	char **label = (char**) malloc(seg * sizeof (char*));
	// Variable for the current label
	char *curLabel = strtok(DN, ".");
	
	for(i = 0; curLabel != NULL; i++)
	{
		label[i] = malloc(strlen(curLabel)*sizeof(char));
		label[i] = strdup(curLabel);
		curLabel = strtok(NULL, ".");
	}
	// Reverse domain name
	sz = i-1;
	if(last == '.')
		strcat(tmp, ".");
	for(i = sz; i >= 0; i--)
	{
		if(i != sz)
			strcat(tmp, ".");
		strcat(tmp, label[i]);
	}
	// Deallocate 2d array
	for(i = 0; i < seg; i++)
		free(label[i]);
	free(label);
	// Put the reversed domain name back into the variable passed in
	strcpy(DN, tmp);

	return 0;
}

/* F(X) TO CHECK THE DNS QUERY CLASS AND TYPE FOR SUPPORT */
uint16_t chSup(DnsType clType, DnsClass clClass)
{
	uint16_t rc = 0;
	switch(clClass)
	{
		case in:
			//printf("INTERNET CLASS");
			break;
		case cs:
			//printf("CSNET CLASS");
			break;
		case ch:
			//printf("CHAOS NETWORK CLASS");
			break;
		case hs:
			//printf("HESIOD CLASS");
			break;
		case allClasses:
			//printf("ALL CLASS RETURN NOT SUPPORTED");
			rc = 4;
			break;
		default :
			//printf("ERROR CLASS NOT KNOWN");
			rc = 1;
			break;
	}

	if(rc != 0)
		return rc;
	//printf("\n");

	switch(clType)
	{
		case a:
			//printf("TYPE A RESOURCE RECORD");
			break;
		case ns:
			//printf("TYPE NS RESOURCE RECORD");
			break;
		case md:
			//printf("TYPE MD RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case mf:
			//printf("TYPE MF RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case cname:
			//printf("TYPE CNAME RESOURCE RECORD");
			break;
		case soa:
			//printf("TYPE SOA RESOURCE RECORD");
			rc = 5;
			break;
		case mb:
			//printf("TYPE MB RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case mg:
			//printf("TYPE MG RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case mr:
			//printf("TYPE MR RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case null:
			//printf("TYPE NULL RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case wks:
			//printf("TYPE WKS RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case ptr:
			//printf("TYPE PTR RESOURCE RECORD");
			break;
		case hinfo:
			//printf("TYPE HINFO RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case minfo:
			//printf("TYPE MINFO RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case mx:
			//printf("TYPE MX RESOURCE RECORD");
			break;
		case txt:
			//printf("TYPE TXT RESOURCE RECORD NOT SUPPORTED");
			rc = 4;
			break;
		case aaaa:
			//printf("TYPE AAAA RESOURCE RECORD");
			break;
		case axfr:
			//printf("QUERY TYPE ZONE TRANSFER ONLY PERMITTED WITH FPGA???");
			rc = 4;
			break;
		case mailb:
			//printf("QUERY TYPE MAILB NOT PERMITTED");
			rc = 4;
			break;
		case maila:
			//printf("QUERY TYPE MAILA NOT PERMITTED");
			rc = 4;
			break;
		case allTypes:
			//printf("QUERY TYPE ALL RESOURCE RECORDS NOT PERMITTED???");
			rc = 4;
			break;
		default:
			//printf("ERROR TYPE NOT KNOWN");
			rc = 1;
			break;
	}
	return rc;
}
