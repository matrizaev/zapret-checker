typedef struct sTStringList
{
	char *value;
	struct sTStringList *next;
	uint32_t hash;
} TStringList;

typedef struct sPfHashNode
{
	char *key;
	TStringList *data;
	struct sPfHashNode *next;
	uint32_t hash;
} pfHashNode;

typedef struct
{
	uint32_t (*fn) (const char *);
	uint32_t numEntries;
	pfHashNode *lookup[];
} pfHashTable;

extern TStringList *StringListAdd(TStringList *head, const char *data);
extern bool StringListFind(TStringList *head, const char *value);
extern void StringListDestroy(TStringList *head);
extern bool pfHashCheckExists (pfHashTable *tbl, const char *key, const char *value);

pfHashTable *pfHashCreate (uint32_t (*)(const char*), uint32_t numEntries);
extern void pfHashDestroy (pfHashTable *tbl);
extern bool pfHashSet (pfHashTable* tbl, const char* key , const char* value);
extern bool pfHashDel (pfHashTable* tbl, const char* key);
extern TStringList *pfHashFind (const pfHashTable* tbl, const char* key);
extern bool pfHashCheckKey (const pfHashTable *tbl, const char *key);
extern void pfHashDebug (pfHashTable* tbl,const char* desc);
