#include "pfhash.h"

#include "errorstrings.h"


static void PrintHashDebugged (const uint8_t *str)
{
	if (str != NULL)
	{
		while (*str != 0)
		{
			if (isalnum (*str) || *str == '-')
				printf ("%c ", *str);
			else
				printf ("0x%02x ", *str);
			str++;
		}
	}
}


static uint32_t defaultFnKnR (const char *key)
{
	if (key == NULL)
		return 0;
	
	uint32_t hashval;
    for (hashval = 0; *key != '\0'; key++)
        hashval = (uint32_t)(*key) + 31 * hashval;
    return hashval;
}

TStringList *StringListAdd(TStringList *head, const char *value)
{
	if (value == NULL || StringListFind (head, value) == true)
		return head;
	TStringList *prev = calloc (sizeof (TStringList), 1);
	if (prev != NULL)
	{
		if (head == NULL)
		{
			head = prev;
			prev->next = NULL;
		}
		else
		{
			prev->next = head;
			head = prev;
		}
		head->value = strdup(value);
		if (head->value != NULL)
		{
			head->hash = defaultFnKnR(value);
			return head;
		}
	}
	StringListDestroy (head);
	return NULL;
}

bool StringListFind(TStringList *head, const char *value)
{
	
	if (value == NULL || head == NULL)
		return false;
	uint32_t hash = defaultFnKnR(value);
	while (head != NULL)
	{
		if (hash == head->hash)
		{
			if (!strcmp(head->value, value))
				return true;
		}
		head = head->next;
	}
	return false;
}

void StringListDestroy(TStringList *head)
{
	TStringList *temp = head;

	while (head != NULL)
	{
		temp = head;
		head = head->next;
		free(temp->value);
		free(temp);
	}
	return;
}


// Local function to locate a key, will populate
//   hash entry, node before and node matching.
// If node matching is null, it wasn't found.
// If node before is null, it was the first at that
//   entry.

static void locate (const pfHashTable *tbl, const char *key,
    int *pEntry, pfHashNode **pPrev,
    pfHashNode **pNode)
{

	if (tbl == NULL || key == NULL || pEntry == NULL || pPrev == NULL || pNode == NULL)
		return;
    // Get the hash entry as first step.
	uint32_t hash = tbl->fn (key);
    *pEntry = hash % tbl->numEntries;

    // Iterate through list at that entry until
    // you find key, or reach end.

    *pPrev = NULL;
    *pNode = tbl->lookup[*pEntry];
    while (*pNode != NULL)
	{
		if ((*pNode)->hash == hash)
			if (strcmp (key, (*pNode)->key) == 0)
				break;
        *pPrev = *pNode;
        *pNode = (*pNode)->next;
    }
}

// Create a hash table, giving only the hashing
//   function.

pfHashTable *pfHashCreate (uint32_t (*fn)(const char *), uint32_t numEntries)
{
    // Use default if none given, and get number
    //   of entries allowed.

    if (fn == NULL)
        fn = defaultFnKnR;

    // Allocate the hash table, including entries
    //   for lists of nodes.

    pfHashTable *tbl = malloc (sizeof (pfHashTable)
        + numEntries * sizeof (pfHashNode*));
    if (tbl == NULL)
        return NULL;

    // Store function and set hash entries to empty.

    tbl->fn = fn;
	tbl->numEntries = numEntries;

    for (uint32_t i = 0; i < numEntries; i++)
        tbl->lookup[i] = NULL;

    return tbl;
}

// Destroys a hash table, freeing all data.

void pfHashDestroy (pfHashTable *tbl)
{
    // Get size first.
	
	if (tbl == NULL)
		return;

    // For each lookup entry, free its node list.

    for (uint32_t i = 0; i < tbl->numEntries; i++)
	{
        // Iterate through the linked list,
        //   freeing one node at a time.

        pfHashNode *node = tbl->lookup[i];
        while (node != NULL)
		{
            pfHashNode *next = node->next;
            free (node->key);
            StringListDestroy (node->data);
            free (node);
            node = next;
        }
    }
	free (tbl);
}

// Set a hash value (key/data), creating it if it doesn't
//   already exist.

bool pfHashSet (pfHashTable *tbl, const char *key, const char *value)
{
	bool result = false;
    int entry = 0;
    pfHashNode *prev = NULL, *node = NULL;

	check (tbl != NULL && key != NULL, ERROR_STR_INVALIDINPUT);
    locate (tbl, key, &entry, &prev, &node);

    if (node != NULL)
	{
		if (value == NULL)
			return true;
		node->data = StringListAdd (node->data, value);
		return (node->data != NULL);
    }
	else
	{
		node = calloc (sizeof (pfHashNode), 1);
		check_mem(node);
		node->key = strdup (key);
		check_mem(node->key);
		node->data = StringListAdd (NULL, value);
		if (value != NULL)
		{
			check (node->data != NULL, ERROR_STR_STRINGLISTERROR);
		}
		node->next = tbl->lookup[entry];
		tbl->lookup[entry] = node;
		node->hash = tbl->fn(key);
		node = NULL;
	}
    result = true;
error:
	if (result != true)
	{
		if (node != NULL)
		{
			if (node->key != NULL)
				free(node->key);
			if (node->data != NULL)
				StringListDestroy (node->data);
			free (node);
		}
	}
	return result;
}


// Delete a hash entry, returning error if not found.

bool pfHashDel (pfHashTable *tbl, const char *key)
{
    int entry = 0;
    pfHashNode *prev = NULL, *node = NULL;

	if (tbl == NULL || key == NULL)
		return false;
    locate (tbl, key, &entry, &prev, &node);

    if (node == NULL)
        return false;

    if (prev != NULL)
        prev->next = node->next;
    else
        tbl->lookup[entry] = node->next;

    free (node->key);
    StringListDestroy (node->data);
    free (node);
	return true;
}

// Find a hash entry, and return the data. If not found,
//   returns NULL.

TStringList *pfHashFind (const pfHashTable *tbl, const char *key)
{
    int entry = 0;
    pfHashNode *prev = NULL, *node = NULL;

	if (tbl == NULL || key == NULL)
		return NULL;
    locate (tbl, key, &entry, &prev, &node);

    if (node == NULL)
        return NULL;

    return node->data;
}

bool pfHashCheckKey (const pfHashTable *tbl, const char *key)
{
    int entry = 0;
    pfHashNode *prev = NULL, *node = NULL;

	if (tbl == NULL || key == NULL)
		return false;
    locate (tbl, key, &entry, &prev, &node);

    if (node == NULL)
        return false;

    return true;
}

bool pfHashCheckExists (pfHashTable *tbl, const char *key, const char *value)
{
    int entry = 0;
    pfHashNode *prev = NULL, *node = NULL;

	if ((tbl == NULL) || (key == NULL) || (value == NULL))
		return false;
	
    locate (tbl, key, &entry, &prev, &node);

    if (node == NULL)
        return false;
	
    return StringListFind(node->data, value);
}

// Output debugging info about the hash table.

void pfHashDebug (pfHashTable *tbl, const char *desc)
{
	if ((tbl == NULL) || (desc == NULL))
		return;
	
    printf ("=====: %s %u entries\n", desc, tbl->numEntries);


    for (uint32_t i = 0; i < tbl->numEntries; i++)
	{

		if (tbl->lookup[i] != NULL)
		{
            int sz = 0;
            printf ("Entry #%3u:\n", i);
            pfHashNode *node = tbl->lookup[i];
            while (node != NULL)
			{
				char *key = node->key;
				if (key != NULL)
				{
					printf ("\t[' ");
					PrintHashDebugged ((uint8_t *)key);
					puts ("']\n");
					TStringList *temp = node->data;
					while (temp != NULL)
					{
						printf("\t\t[%u] '%s'\n", temp->hash, temp->value);
						temp = temp->next;
					}
				}
                node = node->next;
                sz++;
            }
            printf ("size=%d\n\n", sz);
        }
    }

    printf ("\n");
}
