
#define BASE64_MINIMUM_LEN 4


typedef struct
{
	void * memory;
	size_t size;
} TMemoryStruct;


extern char *GetDateTime (const char *dateTimeFormat);
extern bool ValidateXmlFile (const char *xmlFileName, const char *schemaFileName);
extern bool ValidateXmlFile2 (const char *xmlFileName, const char *schemaBuf, size_t schemaBufLen);
extern char *TrimWhiteSpaces (char *str);
extern char *Base64Encode (const void *data, size_t inputLength, size_t *outputLength);
extern void Base64Cleanup ();
extern void *Base64Decode (const char *data, size_t inputLength, size_t *outputLength);
extern void DecodeURL (char *inputStr);
extern void LowerStringCase (char *inputStr);
extern uint16_t checksum (uint16_t *addr, size_t len);
extern void FillIPHeader (struct iphdr *ipHdr, uint32_t clientIP, uint32_t serverIP, uint16_t totalLength, uint8_t proto);
extern void *SendHTTPPost (const char *url, const void *payload, char *httpHeaders[], size_t httpHeadersCount, size_t inputLength, size_t *outputLength);
extern bool DNSNotation2String (uint8_t *str);
extern uint8_t *String2DNSNotation (char *str);