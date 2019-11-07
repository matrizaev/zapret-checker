//#define SMTP_RECIPIENTS_LIST_ATTACH 0
//#define SMTP_RECIPIENTS_LIST_NOATTACH 1
#define SMTP_RECIPIENTS_LIST_COUNT 2

#define IP4_HDRLEN 20
#define TCP_PSEUDO_LEN 12
#define PSEUDO_HDR_OFFSET (IP4_HDRLEN - TCP_PSEUDO_LEN)

#pragma pack(push, 1)
typedef struct
{
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t length;
} TPseudoHeader;

typedef struct
{
	uint16_t id;
	//uint8_t flags[2];
	uint8_t rd:1; //recursion desired    
	uint8_t tc:1; //truncated message
	uint8_t aa:1; //authorative answer
	uint8_t opcode:4; //purpose of message
	uint8_t qr:1; //query/response flag
	uint8_t rcode:4; //response code
	uint8_t cd:1; //checking disabled
	uint8_t ad:1; //authenticated data
	uint8_t z:1; //reserved
	uint8_t ra:1; //recursion available
	uint16_t questionCount;
	uint16_t answerCount;
	uint16_t nsCount;
	uint16_t additionalCount;
} TDNSHeader;

typedef struct
{
	uint16_t name;
	uint16_t type;
	uint16_t addrClass;
	uint32_t ttl;
	uint16_t rdlength;
	uint32_t rdata;
} TDNSAnswer;
#pragma pack(pop)


typedef enum {NETFILTER_TYPE_HTTP, NETFILTER_TYPE_DNS, NETFILTER_TYPE_IP, NETFILTER_TYPE_COUNT} TNetfilterType;


/*************************************************************************
* Контекст последнего SMTP взаимодействия.                               *
*************************************************************************/
typedef struct
{
	char	*smtpHost;
	char	*smtpSender;	
	struct curl_slist *recipients[SMTP_RECIPIENTS_LIST_COUNT];
} TSMTPContext;


/*************************************************************************
* Контекст потока обработки трафика.                                     *
*************************************************************************/
typedef struct TNetfilterContextStruct
{
	pfHashTable	*hashTable;
	struct nfq_q_handle *nfQueue;
	uint8_t *redirectNetworkPacket;
	struct nfq_handle *nfqHandle;
	size_t	redirectDataLen;
	pthread_t threadId;
	int redirectSocket;
	int	ifIndex;
	bool (*nfqParseCallback) (uint8_t*, size_t, struct TNetfilterContextStruct*, uint8_t[8]);
	
} TNetfilterContext;


/*************************************************************************
* Контекст последнего SOAP взаимодействия.                               *
*************************************************************************/
typedef struct
{
	char	*lastDumpDate;
	char	*lastDumpDateUrgently;
	char	*dumpFormatVersion;
	char	*webServiceVersion;
	char	*docVersion;
	char	*requestCode;
	char	*requestResult;
	char	*requestComment;
	char	*registerZipArchive;
	char	*resultResult;
	char	*resultComment;
	char	*operatorName;
	char	*operatorINN;
	int		resultCode;
	bool	soapResult;
	char	*privateKeyId;
	char	*privateKeyPassword;
} TSOAPContext;


/*************************************************************************
* Основной контекст демона.                                              *
*************************************************************************/
typedef struct
{
	char	*redirectHost;
	char	*redirectIface;
	char	*redirectIpsetList;
	char	*blacklistHost;
	char	*timestampFile;
	char	*customBlacklist;
	char	*privateKeyId;
	char	*privateKeyPassword;
	TSOAPContext		*soapContext;
	TSMTPContext		*smtpContext;
	TNetfilterContext	**httpThreadsContext;
	TNetfilterContext	**dnsThreadsContext;
	pfHashTable			*hashTables[NETFILTER_TYPE_COUNT];
	xmlDocPtr			requestXmlDoc;
	size_t	redirectHTTPQueue;
	size_t	redirectHTTPCount;
	size_t	redirectDNSQueue;
	size_t	redirectDNSCount;
	time_t	blacklistCooldownPositive;
	time_t	blacklistCooldownNegative;
	bool	redirectNSLookup;
} TZapretContext;