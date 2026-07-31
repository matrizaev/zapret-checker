/*************************************************************************
 * Standalone blacklist hash-table benchmark.                            *
 *************************************************************************/

#include "allheaders.h"

#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <malloc.h>

#include <libxml/parser.h>

#include "zapret-checker.h"

#define DEFAULT_QUERY_COUNT 1000000U
#define DEFAULT_SAMPLE_COUNT 65536U
#define DEFAULT_RANDOM_SEED UINT64_C(0x8f3f73b5cf1c9ade)
#define MISS_KEY_SIZE 80U

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

typedef struct {
  const char *inputPath;
  uint32_t bucketCounts[NETFILTER_TYPE_COUNT];
  size_t queryCount;
  size_t sampleCount;
  uint64_t randomSeed;
} TBenchmarkOptions;

typedef struct {
  size_t keyCount;
  size_t valueCount;
  size_t nonemptyBucketCount;
  size_t maxChainLength;
  size_t maxValuesPerKey;
  size_t estimatedBytes;
  long double successfulProbeTotal;
} TTableStats;

typedef struct {
  const char *key;
  const char *value;
} TRuleSample;

typedef struct {
  const char **keys;
  size_t keyCount;
  size_t keyCapacity;
  TRuleSample *rules;
  size_t ruleCount;
  size_t ruleCapacity;
} TTableSamples;

typedef struct {
  const char *key;
  const char *value;
  uint64_t rank;
} TSampleCandidate;

static const char *const tableNames[NETFILTER_TYPE_COUNT] = {
    "http", "dns", "ip"};

static void PrintUsage(FILE *stream, const char *programName) {
  fprintf(stream,
          "Usage: %s --input FILE [OPTIONS]\n"
          "\n"
          "Load FILE with the production blacklist parser, using configurable\n"
          "bucket counts for the HTTP, DNS, and IP hash tables.\n"
          "\n"
          "Options:\n"
          "  -i, --input FILE       blacklist.xml to load (required)\n"
          "  -b, --buckets COUNT    override buckets for every table\n"
          "      --http-buckets N   HTTP buckets (default: %u)\n"
          "      --dns-buckets N    DNS buckets (default: %u)\n"
          "      --ip-buckets N     IP buckets (default: %u)\n"
          "  -q, --queries COUNT    timed lookups per operation (default: %u)\n"
          "  -s, --samples COUNT    resident keys sampled for queries (default: %u)\n"
          "      --seed VALUE       deterministic random seed\n"
          "  -h, --help             show this help\n",
          programName, ZAPRET_HTTP_HASH_BUCKET_COUNT,
          ZAPRET_DNS_HASH_BUCKET_COUNT, ZAPRET_IP_HASH_BUCKET_COUNT,
          DEFAULT_QUERY_COUNT, DEFAULT_SAMPLE_COUNT);
}

static bool ParseUnsigned(const char *value, uintmax_t maximum,
                          uintmax_t *result) {
  char *end = NULL;
  uintmax_t parsed = 0;

  if (value == NULL || result == NULL || *value == '\0' || *value == '-')
    return false;
  errno = 0;
  parsed = strtoumax(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0 ||
      parsed > maximum)
    return false;
  *result = parsed;
  return true;
}

static bool ParseOptions(int argc, char **argv, TBenchmarkOptions *options) {
  static const struct option longOptions[] = {
      {"input", required_argument, NULL, 'i'},
      {"buckets", required_argument, NULL, 'b'},
      {"queries", required_argument, NULL, 'q'},
      {"samples", required_argument, NULL, 's'},
      {"seed", required_argument, NULL, 1},
      {"http-buckets", required_argument, NULL, 2},
      {"dns-buckets", required_argument, NULL, 3},
      {"ip-buckets", required_argument, NULL, 4},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0},
  };
  int option = 0;

  if (options == NULL)
    return false;
  *options = (TBenchmarkOptions){
      .bucketCounts = {ZAPRET_HTTP_HASH_BUCKET_COUNT,
                       ZAPRET_DNS_HASH_BUCKET_COUNT,
                       ZAPRET_IP_HASH_BUCKET_COUNT},
      .queryCount = DEFAULT_QUERY_COUNT,
      .sampleCount = DEFAULT_SAMPLE_COUNT,
      .randomSeed = DEFAULT_RANDOM_SEED,
  };

  while ((option = getopt_long(argc, argv, "i:b:q:s:h", longOptions, NULL)) !=
         -1) {
    uintmax_t parsed = 0;
    switch (option) {
    case 'i':
      options->inputPath = optarg;
      break;
    case 'b':
      if (!ParseUnsigned(optarg, UINT32_MAX, &parsed))
        return false;
      for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++)
        options->bucketCounts[i] = (uint32_t)parsed;
      break;
    case 'q':
      if (!ParseUnsigned(optarg, SIZE_MAX, &parsed))
        return false;
      options->queryCount = (size_t)parsed;
      break;
    case 's':
      if (!ParseUnsigned(optarg, SIZE_MAX, &parsed))
        return false;
      options->sampleCount = (size_t)parsed;
      break;
    case 1:
      if (!ParseUnsigned(optarg, UINT64_MAX, &parsed))
        return false;
      options->randomSeed = (uint64_t)parsed;
      break;
    case 2:
    case 3:
    case 4:
      if (!ParseUnsigned(optarg, UINT32_MAX, &parsed))
        return false;
      options->bucketCounts[option - 2] = (uint32_t)parsed;
      break;
    case 'h':
      PrintUsage(stdout, argv[0]);
      exit(EXIT_SUCCESS);
    default:
      return false;
    }
  }
  return options->inputPath != NULL && optind == argc;
}

static bool AddSize(size_t *total, size_t value) {
  if (total == NULL || value > SIZE_MAX - *total)
    return false;
  *total += value;
  return true;
}

static bool MultiplySize(size_t left, size_t right, size_t *result) {
  if (result == NULL || (left != 0 && right > SIZE_MAX / left))
    return false;
  *result = left * right;
  return true;
}

static uint64_t NextRandom(uint64_t *state) {
  uint64_t value = *state;

  if (value == 0)
    value = DEFAULT_RANDOM_SEED;
  value ^= value >> 12;
  value ^= value << 25;
  value ^= value >> 27;
  *state = value;
  return value * UINT64_C(2685821657736338717);
}

static uint64_t ElapsedNanoseconds(const struct timespec *start,
                                   const struct timespec *end) {
  uint64_t seconds = (uint64_t)(end->tv_sec - start->tv_sec);
  int64_t nanoseconds = end->tv_nsec - start->tv_nsec;

  if (nanoseconds < 0) {
    seconds--;
    nanoseconds += 1000000000L;
  }
  return seconds * UINT64_C(1000000000) + (uint64_t)nanoseconds;
}

static bool ReadMemoryStatus(size_t *rssKiB, size_t *peakRssKiB) {
  FILE *status = NULL;
  char line[256];
  bool rssFound = false;
  bool peakFound = false;

  if (rssKiB == NULL || peakRssKiB == NULL)
    return false;
  *rssKiB = 0;
  *peakRssKiB = 0;
  status = fopen("/proc/self/status", "r");
  if (status == NULL)
    return false;
  while (fgets(line, sizeof(line), status) != NULL) {
    if (sscanf(line, "VmRSS: %zu kB", rssKiB) == 1)
      rssFound = true;
    else if (sscanf(line, "VmHWM: %zu kB", peakRssKiB) == 1)
      peakFound = true;
  }
  fclose(status);
  return rssFound && peakFound;
}

static bool GatherTableStats(const pfHashTable *table, TTableStats *stats) {
  size_t bucketBytes = 0;

  if (table == NULL || stats == NULL || table->numEntries == 0)
    return false;
  memset(stats, 0, sizeof(*stats));
  if (!MultiplySize(table->numEntries, sizeof(pfHashNode *), &bucketBytes) ||
      !AddSize(&stats->estimatedBytes, sizeof(*table)) ||
      !AddSize(&stats->estimatedBytes, bucketBytes))
    return false;

  for (uint32_t i = 0; i < table->numEntries; i++) {
    size_t chainLength = 0;
    for (const pfHashNode *node = table->lookup[i]; node != NULL;
         node = node->next) {
      size_t valuesForKey = 0;
      size_t keyBytes = 0;

      if (node->key == NULL || stats->keyCount == SIZE_MAX)
        return false;
      keyBytes = strlen(node->key);
      if (keyBytes == SIZE_MAX || chainLength == SIZE_MAX)
        return false;
      keyBytes++;
      if (!AddSize(&stats->estimatedBytes, sizeof(*node)) ||
          !AddSize(&stats->estimatedBytes, keyBytes))
        return false;
      stats->keyCount++;
      chainLength++;

      for (const TStringList *value = node->data; value != NULL;
           value = value->next) {
        size_t valueBytes = 0;
        if (value->value == NULL || stats->valueCount == SIZE_MAX)
          return false;
        valueBytes = strlen(value->value);
        if (valueBytes == SIZE_MAX || valuesForKey == SIZE_MAX)
          return false;
        valueBytes++;
        if (!AddSize(&stats->estimatedBytes, sizeof(*value)) ||
            !AddSize(&stats->estimatedBytes, valueBytes))
          return false;
        stats->valueCount++;
        valuesForKey++;
      }
      if (valuesForKey > stats->maxValuesPerKey)
        stats->maxValuesPerKey = valuesForKey;
    }
    if (chainLength > 0) {
      stats->nonemptyBucketCount++;
      stats->successfulProbeTotal +=
          ((long double)chainLength * (chainLength + 1)) / 2.0L;
      if (chainLength > stats->maxChainLength)
        stats->maxChainLength = chainLength;
    }
  }
  return true;
}

static bool AllocateSamples(TTableSamples *samples, size_t keyCapacity,
                            size_t ruleCapacity) {
  size_t bytes = 0;

  if (samples == NULL)
    return false;
  memset(samples, 0, sizeof(*samples));
  samples->keyCapacity = keyCapacity;
  samples->ruleCapacity = ruleCapacity;
  if (keyCapacity > 0) {
    if (!MultiplySize(keyCapacity, sizeof(*samples->keys), &bytes))
      return false;
    samples->keys = malloc(bytes);
    if (samples->keys == NULL)
      return false;
  }
  if (ruleCapacity > 0) {
    if (!MultiplySize(ruleCapacity, sizeof(*samples->rules), &bytes))
      goto error;
    samples->rules = malloc(bytes);
    if (samples->rules == NULL)
      goto error;
  }
  return true;

error:
  free(samples->keys);
  memset(samples, 0, sizeof(*samples));
  return false;
}

static void DestroySamples(TTableSamples *samples) {
  if (samples == NULL)
    return;
  free(samples->keys);
  free(samples->rules);
  memset(samples, 0, sizeof(*samples));
}

static uint64_t RankString(uint64_t rank, const char *value) {
  const unsigned char *cursor = (const unsigned char *)value;

  while (*cursor != '\0') {
    rank ^= *cursor++;
    rank *= UINT64_C(1099511628211);
  }
  return rank;
}

static uint64_t SampleRank(const char *key, const char *value,
                           uint64_t randomSeed) {
  uint64_t rank = UINT64_C(14695981039346656037) ^ randomSeed;

  rank = RankString(rank, key);
  rank ^= UINT64_C(0xff);
  rank *= UINT64_C(1099511628211);
  if (value != NULL)
    rank = RankString(rank, value);
  return rank;
}

static int CompareSampleCandidates(const void *left, const void *right) {
  const TSampleCandidate *leftCandidate = left;
  const TSampleCandidate *rightCandidate = right;
  int comparison = 0;

  if (leftCandidate->rank < rightCandidate->rank)
    return -1;
  if (leftCandidate->rank > rightCandidate->rank)
    return 1;
  comparison = strcmp(leftCandidate->key, rightCandidate->key);
  if (comparison != 0 || leftCandidate->value == rightCandidate->value)
    return comparison;
  if (leftCandidate->value == NULL)
    return -1;
  if (rightCandidate->value == NULL)
    return 1;
  return strcmp(leftCandidate->value, rightCandidate->value);
}

static bool CollectSamples(const pfHashTable *table, TTableSamples *samples,
                           size_t keyTotal, size_t ruleTotal,
                           uint64_t randomSeed) {
  TSampleCandidate *candidates = NULL;
  size_t bytes = 0;
  size_t candidateCount = 0;

  if (table == NULL || samples == NULL)
    return false;
  if (keyTotal > 0) {
    if (!MultiplySize(keyTotal, sizeof(*candidates), &bytes))
      return false;
    candidates = malloc(bytes);
    if (candidates == NULL)
      return false;
    for (uint32_t i = 0; i < table->numEntries; i++) {
      for (const pfHashNode *node = table->lookup[i]; node != NULL;
           node = node->next) {
        if (candidateCount >= keyTotal)
          goto error;
        candidates[candidateCount++] = (TSampleCandidate){
            .key = node->key,
            .rank = SampleRank(node->key, NULL, randomSeed),
        };
      }
    }
    if (candidateCount != keyTotal)
      goto error;
    qsort(candidates, candidateCount, sizeof(*candidates),
          CompareSampleCandidates);
    for (size_t i = 0; i < samples->keyCapacity; i++)
      samples->keys[i] = candidates[i].key;
    samples->keyCount = samples->keyCapacity;
    free(candidates);
    candidates = NULL;
  }

  candidateCount = 0;
  if (ruleTotal > 0) {
    if (!MultiplySize(ruleTotal, sizeof(*candidates), &bytes))
      return false;
    candidates = malloc(bytes);
    if (candidates == NULL)
      return false;
    for (uint32_t i = 0; i < table->numEntries; i++) {
      for (const pfHashNode *node = table->lookup[i]; node != NULL;
           node = node->next) {
        for (const TStringList *value = node->data; value != NULL;
             value = value->next) {
          if (candidateCount >= ruleTotal)
            goto error;
          candidates[candidateCount++] = (TSampleCandidate){
              .key = node->key,
              .value = value->value,
              .rank = SampleRank(node->key, value->value, randomSeed),
          };
        }
      }
    }
    if (candidateCount != ruleTotal)
      goto error;
    qsort(candidates, candidateCount, sizeof(*candidates),
          CompareSampleCandidates);
    for (size_t i = 0; i < samples->ruleCapacity; i++) {
      samples->rules[i] = (TRuleSample){
          .key = candidates[i].key,
          .value = candidates[i].value,
      };
    }
    samples->ruleCount = samples->ruleCapacity;
    free(candidates);
  }
  return true;

error:
  free(candidates);
  return false;
}

static char *CreateMissKeys(const char *tableName, size_t count) {
  char *keys = NULL;
  size_t bytes = 0;

  if (tableName == NULL || count == 0 ||
      !MultiplySize(count, MISS_KEY_SIZE, &bytes))
    return NULL;
  keys = calloc(1, bytes);
  if (keys == NULL)
    return NULL;
  for (size_t i = 0; i < count; i++) {
    int written = snprintf(keys + i * MISS_KEY_SIZE, MISS_KEY_SIZE,
                           "__zapret_benchmark_%s_miss_%zu.invalid", tableName,
                           i);
    if (written <= 0 || (size_t)written >= MISS_KEY_SIZE) {
      free(keys);
      return NULL;
    }
  }
  return keys;
}

static void WarmKeyLookups(const pfHashTable *table,
                           const TTableSamples *samples, const char *missKeys,
                           size_t queryCount, uint64_t randomSeed) {
  size_t warmupCount = queryCount < 10000 ? queryCount : 10000;
  uint64_t state = randomSeed;
  volatile size_t found = 0;

  for (size_t i = 0; i < warmupCount; i++) {
    size_t index = (size_t)(NextRandom(&state) % samples->keyCount);
    found += pfHashCheckKey(table, samples->keys[index]);
    found += pfHashCheckKey(table, missKeys + index * MISS_KEY_SIZE);
  }
  (void)found;
}

static void RunKeyLookup(const char *tableName, const char *operation,
                         const pfHashTable *table,
                         const TTableSamples *samples, const char *missKeys,
                         size_t queryCount, uint64_t randomSeed, bool hit) {
  struct timespec start;
  struct timespec end;
  uint64_t elapsed = 0;
  uint64_t state = randomSeed;
  size_t found = 0;

  clock_gettime(CLOCK_MONOTONIC, &start);
  for (size_t i = 0; i < queryCount; i++) {
    size_t index = (size_t)(NextRandom(&state) % samples->keyCount);
    const char *key =
        hit ? samples->keys[index] : missKeys + index * MISS_KEY_SIZE;
    found += pfHashCheckKey(table, key);
  }
  clock_gettime(CLOCK_MONOTONIC, &end);
  elapsed = ElapsedNanoseconds(&start, &end);
  printf("query table=%s operation=%s queries=%zu found=%zu total_ns=%" PRIu64
         " ns_per_query=%.2f million_queries_per_second=%.3f\n",
         tableName, operation, queryCount, found, elapsed,
         (double)elapsed / (double)queryCount,
         (double)queryCount * 1000.0 / (double)elapsed);
}

static void RunRuleLookup(const char *operation, const pfHashTable *table,
                          const TTableSamples *samples, size_t queryCount,
                          uint64_t randomSeed, bool hit) {
  static const char missingValue[] =
      "/__zapret_benchmark_missing_url_value__";
  struct timespec start;
  struct timespec end;
  uint64_t elapsed = 0;
  uint64_t state = randomSeed;
  size_t found = 0;

  clock_gettime(CLOCK_MONOTONIC, &start);
  for (size_t i = 0; i < queryCount; i++) {
    size_t index = (size_t)(NextRandom(&state) % samples->ruleCount);
    const TRuleSample *sample = &samples->rules[index];
    found += pfHashCheckExists((pfHashTable *)table, sample->key,
                               hit ? sample->value : missingValue);
  }
  clock_gettime(CLOCK_MONOTONIC, &end);
  elapsed = ElapsedNanoseconds(&start, &end);
  printf("query table=http operation=%s queries=%zu found=%zu total_ns=%" PRIu64
         " ns_per_query=%.2f million_queries_per_second=%.3f\n",
         operation, queryCount, found, elapsed,
         (double)elapsed / (double)queryCount,
         (double)queryCount * 1000.0 / (double)elapsed);
}

static void DestroyTables(pfHashTable *tables[NETFILTER_TYPE_COUNT]) {
  if (tables == NULL)
    return;
  for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++) {
    pfHashDestroy(tables[i]);
    tables[i] = NULL;
  }
}

int main(int argc, char **argv) {
  TBenchmarkOptions options;
  pfHashTable *tables[NETFILTER_TYPE_COUNT] = {NULL};
  TTableStats stats[NETFILTER_TYPE_COUNT];
  TTableSamples samples[NETFILTER_TYPE_COUNT];
  char *missKeys[NETFILTER_TYPE_COUNT] = {NULL};
  struct stat inputStatus;
  struct timespec loadStart;
  struct timespec loadEnd;
  uint64_t loadNanoseconds = 0;
  size_t baselineRssKiB = 0;
  size_t baselinePeakRssKiB = 0;
  size_t postParseRssKiB = 0;
  size_t postParsePeakRssKiB = 0;
  size_t loadedRssKiB = 0;
  size_t loadedPeakRssKiB = 0;
  int memoryTrimmed = 0;
  int exitCode = EXIT_FAILURE;

  memset(stats, 0, sizeof(stats));
  memset(samples, 0, sizeof(samples));
  if (!ParseOptions(argc, argv, &options)) {
    PrintUsage(stderr, argv[0]);
    return EXIT_FAILURE;
  }
  if (stat(options.inputPath, &inputStatus) != 0 ||
      !S_ISREG(inputStatus.st_mode)) {
    fprintf(stderr, "Cannot read regular input file '%s': %s\n",
            options.inputPath, strerror(errno));
    return EXIT_FAILURE;
  }

  xmlInitParser();
  ReadMemoryStatus(&baselineRssKiB, &baselinePeakRssKiB);
  printf("benchmark input=%s input_bytes=%jd http_buckets=%u dns_buckets=%u "
         "ip_buckets=%u queries=%zu samples=%zu seed=%" PRIu64 "\n",
         options.inputPath, (intmax_t)inputStatus.st_size,
         options.bucketCounts[NETFILTER_TYPE_HTTP],
         options.bucketCounts[NETFILTER_TYPE_DNS],
         options.bucketCounts[NETFILTER_TYPE_IP], options.queryCount,
         options.sampleCount, options.randomSeed);
  fflush(stdout);

  for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++) {
    tables[i] = pfHashCreate(NULL, options.bucketCounts[i]);
    if (tables[i] == NULL) {
      fprintf(stderr, "Cannot allocate %u buckets for the %s table.\n",
              options.bucketCounts[i], tableNames[i]);
      goto cleanup;
    }
  }

  clock_gettime(CLOCK_MONOTONIC, &loadStart);
  if (!ProcessRegisterCustomBlacklist(false, (char *)options.inputPath,
                                      tables)) {
    fprintf(stderr, "Cannot parse blacklist '%s'.\n", options.inputPath);
    goto cleanup;
  }
  clock_gettime(CLOCK_MONOTONIC, &loadEnd);
  loadNanoseconds = ElapsedNanoseconds(&loadStart, &loadEnd);
  ReadMemoryStatus(&postParseRssKiB, &postParsePeakRssKiB);
  memoryTrimmed = malloc_trim(0);
  ReadMemoryStatus(&loadedRssKiB, &loadedPeakRssKiB);

  printf("load total_ns=%" PRIu64 " seconds=%.3f\n", loadNanoseconds,
         (double)loadNanoseconds / 1000000000.0);
  printf("memory baseline_rss_kib=%zu post_parse_rss_kib=%zu "
         "trimmed_rss_kib=%zu trimmed_rss_delta_kib=%zu peak_rss_kib=%zu "
         "malloc_trim_released=%d\n",
         baselineRssKiB, postParseRssKiB, loadedRssKiB,
         loadedRssKiB > baselineRssKiB ? loadedRssKiB - baselineRssKiB : 0,
         loadedPeakRssKiB > postParsePeakRssKiB ? loadedPeakRssKiB
                                                : postParsePeakRssKiB,
         memoryTrimmed);

  for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++) {
    double loadFactor = 0.0;
    double averageNonemptyChain = 0.0;
    double averageSuccessfulProbes = 0.0;
    double averageValuesPerKey = 0.0;
    size_t keySamples = 0;
    size_t ruleSamples = 0;

    if (!GatherTableStats(tables[i], &stats[i])) {
      fprintf(stderr, "Cannot calculate statistics for the %s table.\n",
              tableNames[i]);
      goto cleanup;
    }
    loadFactor = (double)stats[i].keyCount / options.bucketCounts[i];
    if (stats[i].nonemptyBucketCount > 0)
      averageNonemptyChain =
          (double)stats[i].keyCount / stats[i].nonemptyBucketCount;
    if (stats[i].keyCount > 0)
      averageSuccessfulProbes =
          (double)(stats[i].successfulProbeTotal / stats[i].keyCount);
    if (stats[i].keyCount > 0)
      averageValuesPerKey =
          (double)stats[i].valueCount / stats[i].keyCount;
    printf("table name=%s buckets=%u keys=%zu values=%zu nonempty_buckets=%zu "
           "load_factor=%.6f average_nonempty_chain=%.6f max_chain=%zu "
           "average_successful_probes=%.6f average_unsuccessful_probes=%.6f "
           "average_values_per_key=%.6f max_values_per_key=%zu "
           "estimated_bytes=%zu\n",
           tableNames[i], options.bucketCounts[i], stats[i].keyCount,
           stats[i].valueCount, stats[i].nonemptyBucketCount, loadFactor,
           averageNonemptyChain, stats[i].maxChainLength,
           averageSuccessfulProbes, loadFactor, averageValuesPerKey,
           stats[i].maxValuesPerKey, stats[i].estimatedBytes);

    keySamples = stats[i].keyCount < options.sampleCount
                     ? stats[i].keyCount
                     : options.sampleCount;
    if (i == NETFILTER_TYPE_HTTP)
      ruleSamples = stats[i].valueCount < options.sampleCount
                        ? stats[i].valueCount
                        : options.sampleCount;
    if (!AllocateSamples(&samples[i], keySamples, ruleSamples)) {
      fprintf(stderr, "Cannot allocate samples for the %s table.\n",
              tableNames[i]);
      goto cleanup;
    }
    if (!CollectSamples(tables[i], &samples[i], stats[i].keyCount,
                        stats[i].valueCount,
                        options.randomSeed ^ ((uint64_t)i << 32))) {
      fprintf(stderr, "Cannot collect samples for the %s table.\n",
              tableNames[i]);
      goto cleanup;
    }
    if (samples[i].keyCount > 0) {
      missKeys[i] = CreateMissKeys(tableNames[i], samples[i].keyCount);
      if (missKeys[i] == NULL) {
        fprintf(stderr, "Cannot allocate miss keys for the %s table.\n",
                tableNames[i]);
        goto cleanup;
      }
    }
  }

  for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++) {
    uint64_t seed = options.randomSeed ^ ((uint64_t)i << 48);
    if (samples[i].keyCount == 0) {
      printf("query table=%s skipped=no_keys\n", tableNames[i]);
      continue;
    }
    WarmKeyLookups(tables[i], &samples[i], missKeys[i], options.queryCount,
                   seed);
    RunKeyLookup(tableNames[i], "key_hit", tables[i], &samples[i], missKeys[i],
                 options.queryCount, seed, true);
    RunKeyLookup(tableNames[i], "key_miss", tables[i], &samples[i], missKeys[i],
                 options.queryCount, seed, false);
    if (i == NETFILTER_TYPE_HTTP && samples[i].ruleCount > 0) {
      RunRuleLookup("rule_hit", tables[i], &samples[i], options.queryCount,
                    seed, true);
      RunRuleLookup("rule_miss_existing_host", tables[i], &samples[i],
                    options.queryCount, seed, false);
    }
  }

  exitCode = EXIT_SUCCESS;

cleanup:
  for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++) {
    free(missKeys[i]);
    DestroySamples(&samples[i]);
  }
  DestroyTables(tables);
  xmlCleanupParser();
  return exitCode;
}
