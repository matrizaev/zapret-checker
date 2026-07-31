#include "allheaders.h"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/ioctl.h>

#include "vendor/munit/munit.h"
#include "zapret-checker.h"

#define MOCK_CAPACITY 8
#define NFQ_BUFFER_SIZE 0xFFFF
#define REDIRECT_PAYLOAD1 "HTTP/1.1 301 Moved Permanently\r\nLocation: http://"
#define REDIRECT_PAYLOAD2 "/\r\nConnection: close\r\n\r\n"

typedef enum {
  MOCK_FAIL_NONE,
  MOCK_FAIL_SOCKET,
  MOCK_FAIL_IOCTL,
  MOCK_FAIL_SETSOCKOPT,
  MOCK_FAIL_NFQ_OPEN,
  MOCK_FAIL_NFQ_UNBIND,
  MOCK_FAIL_NFQ_BIND,
  MOCK_FAIL_NFQ_CREATE,
  MOCK_FAIL_NFQ_MODE,
  MOCK_FAIL_GETADDRINFO,
  MOCK_FAIL_EMPTY_ADDRINFO,
  MOCK_FAIL_INVALID_ADDRINFO,
  MOCK_FAIL_NFQ_FD,
  MOCK_FAIL_NFQ_HANDLE_PACKET,
  MOCK_FAIL_PTHREAD_CREATE,
  MOCK_FAIL_PTHREAD_JOIN,
} TMockFailure;

typedef enum {
  MOCK_RECV_PACKET,
  MOCK_RECV_ZERO,
  MOCK_RECV_ERROR,
  MOCK_RECV_EINTR_THEN_ERROR,
} TMockRecvMode;

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

static TMockFailure mockFailure = MOCK_FAIL_NONE;
static TMockRecvMode mockRecvMode = MOCK_RECV_PACKET;
static size_t socketCount = 0;
static size_t ioctlCount = 0;
static size_t setsockoptCount = 0;
static size_t closeCount = 0;
static size_t standardDescriptorCloseCount = 0;
static size_t nfqOpenCount = 0;
static size_t nfqCloseCount = 0;
static size_t nfqUnbindCount = 0;
static size_t nfqBindCount = 0;
static size_t nfqCreateCount = 0;
static size_t nfqDestroyCount = 0;
static size_t nfqSetModeCount = 0;
static size_t getaddrinfoCount = 0;
static size_t freeaddrinfoCount = 0;
static size_t recvCount = 0;
static size_t recvModeCount = 0;
static size_t handlePacketCount = 0;
static size_t verdictCount = 0;
static size_t parseCount = 0;
static size_t pthreadCreateCount = 0;
static size_t pthreadKillCount = 0;
static size_t pthreadCancelCount = 0;
static size_t pthreadJoinCount = 0;
static uint16_t queueNumbers[MOCK_CAPACITY] = {0};
static nfq_callback *queueCallbacks[MOCK_CAPACITY] = {0};
static void *queueCallbackData[MOCK_CAPACITY] = {0};
static void *(*threadRoutines[MOCK_CAPACITY])(void *) = {0};
static void *threadArguments[MOCK_CAPACITY] = {0};
static char capturedInterface[IFNAMSIZ] = {0};
static uint32_t lastVerdict = 0;
static uint32_t lastPacketId = 0;
static bool parseShouldDrop = false;
static bool providePayload = true;
static bool providePacketHeader = true;
static bool provideHardwareAddress = true;
static int payloadLength = 4;
static uint8_t packetPayload[4] = {0xde, 0xad, 0xbe, 0xef};
static struct nfqnl_msg_packet_hdr packetHeader;
static struct nfqnl_msg_packet_hw packetHardwareAddress;
static uint8_t handleTokens[MOCK_CAPACITY];
static uint8_t queueTokens[MOCK_CAPACITY];

static void ResetMocks(void) {
  mockFailure = MOCK_FAIL_NONE;
  mockRecvMode = MOCK_RECV_PACKET;
  socketCount = 0;
  ioctlCount = 0;
  setsockoptCount = 0;
  closeCount = 0;
  standardDescriptorCloseCount = 0;
  nfqOpenCount = 0;
  nfqCloseCount = 0;
  nfqUnbindCount = 0;
  nfqBindCount = 0;
  nfqCreateCount = 0;
  nfqDestroyCount = 0;
  nfqSetModeCount = 0;
  getaddrinfoCount = 0;
  freeaddrinfoCount = 0;
  recvCount = 0;
  recvModeCount = 0;
  handlePacketCount = 0;
  verdictCount = 0;
  parseCount = 0;
  pthreadCreateCount = 0;
  pthreadKillCount = 0;
  pthreadCancelCount = 0;
  pthreadJoinCount = 0;
  memset(queueNumbers, 0, sizeof(queueNumbers));
  memset(queueCallbacks, 0, sizeof(queueCallbacks));
  memset(queueCallbackData, 0, sizeof(queueCallbackData));
  memset(threadRoutines, 0, sizeof(threadRoutines));
  memset(threadArguments, 0, sizeof(threadArguments));
  memset(capturedInterface, 0, sizeof(capturedInterface));
  lastVerdict = 0;
  lastPacketId = 0;
  parseShouldDrop = false;
  providePayload = true;
  providePacketHeader = true;
  provideHardwareAddress = true;
  payloadLength = (int)sizeof(packetPayload);
  memset(&packetHeader, 0, sizeof(packetHeader));
  packetHeader.packet_id = htobe32(0x12345678);
  memset(&packetHardwareAddress, 0, sizeof(packetHardwareAddress));
  packetHardwareAddress.hw_addrlen = htobe16(ETH_ALEN);
  for (size_t i = 0; i < ETH_ALEN; i++)
    packetHardwareAddress.hw_addr[i] = (uint8_t)(i + 1);
  flagMatrixShutdown = 0;
  flagMatrixReconfigure = 0;
  flagMatrixReload = 0;
}

static bool MockPacketParser(uint8_t *packet, size_t packetSize,
                             TNetfilterContext *context,
                             uint8_t hardwareAddress[8]) {
  munit_assert_ptr_equal(packet, packetPayload);
  munit_assert_size(packetSize, ==, sizeof(packetPayload));
  munit_assert_not_null(context);
  munit_assert_memory_equal(ETH_ALEN, hardwareAddress,
                            packetHardwareAddress.hw_addr);
  parseCount++;
  return parseShouldDrop;
}

bool ProcessRawPacketHTTP(uint8_t *packet, size_t packetSize,
                          TNetfilterContext *context,
                          uint8_t hardwareAddress[8]) {
  return MockPacketParser(packet, packetSize, context, hardwareAddress);
}

bool ProcessRawPacketDNS(uint8_t *packet, size_t packetSize,
                         TNetfilterContext *context,
                         uint8_t hardwareAddress[8]) {
  return MockPacketParser(packet, packetSize, context, hardwareAddress);
}

int __wrap_socket(int domain, int type, int protocol) {
  munit_assert_int(domain, ==, PF_PACKET);
  munit_assert_int(type, ==, SOCK_DGRAM);
  munit_assert_int(protocol, ==, htons(ETH_P_IP));
  socketCount++;
  if (mockFailure == MOCK_FAIL_SOCKET) {
    errno = EPERM;
    return -1;
  }
  return 100 + (int)socketCount;
}

int __wrap_ioctl(int descriptor, unsigned long request, ...) {
  struct ifreq *interfaceRequest = NULL;
  va_list arguments;

  munit_assert_int(descriptor, >=, 100);
  munit_assert_ulong(request, ==, SIOCGIFINDEX);
  va_start(arguments, request);
  interfaceRequest = va_arg(arguments, struct ifreq *);
  va_end(arguments);
  munit_assert_not_null(interfaceRequest);
  memcpy(capturedInterface, interfaceRequest->ifr_name,
         sizeof(capturedInterface));
  ioctlCount++;
  if (mockFailure == MOCK_FAIL_IOCTL) {
    errno = ENODEV;
    return -1;
  }
  interfaceRequest->ifr_ifindex = 42;
  return 0;
}

int __wrap_setsockopt(int descriptor, int level, int option,
                      const void *value, socklen_t length) {
  const struct ifreq *interfaceRequest = value;

  munit_assert_int(descriptor, >=, 100);
  munit_assert_int(level, ==, SOL_SOCKET);
  munit_assert_int(option, ==, SO_BINDTODEVICE);
  munit_assert_size(length, ==, sizeof(struct ifreq));
  munit_assert_not_null(interfaceRequest);
  setsockoptCount++;
  if (mockFailure == MOCK_FAIL_SETSOCKOPT) {
    errno = EPERM;
    return -1;
  }
  return 0;
}

int __real_close(int descriptor);

int __wrap_close(int descriptor) {
  if (descriptor >= STDIN_FILENO && descriptor <= STDERR_FILENO) {
    standardDescriptorCloseCount++;
    return 0;
  }
  if (descriptor < 100)
    return __real_close(descriptor);
  closeCount++;
  return 0;
}

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **result) {
  struct addrinfo *entry = NULL;
  struct sockaddr_in *address = NULL;

  (void)service;
  munit_assert_string_equal(node, "redirect.example");
  munit_assert_not_null(hints);
  munit_assert_int(hints->ai_family, ==, AF_INET);
  munit_assert_not_null(result);
  *result = NULL;
  getaddrinfoCount++;
  if (mockFailure == MOCK_FAIL_GETADDRINFO)
    return EAI_NONAME;
  if (mockFailure == MOCK_FAIL_EMPTY_ADDRINFO)
    return 0;

  entry = calloc(1, sizeof(*entry));
  if (entry == NULL)
    return EAI_MEMORY;
  if (mockFailure == MOCK_FAIL_INVALID_ADDRINFO) {
    *result = entry;
    return 0;
  }
  address = calloc(1, sizeof(*address));
  if (address == NULL) {
    free(entry);
    return EAI_MEMORY;
  }
  address->sin_family = AF_INET;
  address->sin_addr.s_addr = inet_addr("203.0.113.45");
  entry->ai_family = AF_INET;
  entry->ai_addrlen = sizeof(*address);
  entry->ai_addr = (struct sockaddr *)address;
  *result = entry;
  return 0;
}

void __wrap_freeaddrinfo(struct addrinfo *result) {
  freeaddrinfoCount++;
  while (result != NULL) {
    struct addrinfo *next = result->ai_next;
    free(result->ai_addr);
    free(result);
    result = next;
  }
}

ssize_t __wrap_recv(int socket, void *buffer, size_t length, int flags) {
  (void)flags;
  munit_assert_int(socket, ==, 77);
  munit_assert_not_null(buffer);
  munit_assert_size(length, ==, NFQ_BUFFER_SIZE);
  recvCount++;
  recvModeCount++;
  if (mockRecvMode == MOCK_RECV_ZERO)
    return 0;
  if (mockRecvMode == MOCK_RECV_ERROR ||
      (mockRecvMode == MOCK_RECV_EINTR_THEN_ERROR && recvModeCount > 1)) {
    errno = EIO;
    return -1;
  }
  if (mockRecvMode == MOCK_RECV_EINTR_THEN_ERROR) {
    errno = EINTR;
    return -1;
  }
  memcpy(buffer, packetPayload, sizeof(packetPayload));
  flagMatrixReload = 1;
  return (ssize_t)sizeof(packetPayload);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                          void *(*routine)(void *), void *argument) {
  (void)attributes;
  munit_assert_not_null(thread);
  munit_assert_not_null(routine);
  if (mockFailure == MOCK_FAIL_PTHREAD_CREATE)
    return EAGAIN;
  munit_assert_size(pthreadCreateCount, <, MOCK_CAPACITY);
  *thread = (pthread_t)(1000 + pthreadCreateCount);
  threadRoutines[pthreadCreateCount] = routine;
  threadArguments[pthreadCreateCount] = argument;
  pthreadCreateCount++;
  return 0;
}

int __wrap_pthread_kill(pthread_t thread, int signalNumber) {
  munit_assert_uint64((uint64_t)thread, >=, 1000);
  munit_assert_int(signalNumber, ==, SIGINT);
  pthreadKillCount++;
  return 0;
}

int __wrap_pthread_cancel(pthread_t thread) {
  munit_assert_uint64((uint64_t)thread, >=, 1000);
  pthreadCancelCount++;
  return 0;
}

int __wrap_pthread_join(pthread_t thread, void **result) {
  (void)result;
  munit_assert_uint64((uint64_t)thread, >=, 1000);
  pthreadJoinCount++;
  return mockFailure == MOCK_FAIL_PTHREAD_JOIN ? EINVAL : 0;
}

struct nfq_handle *nfq_open(void) {
  nfqOpenCount++;
  if (mockFailure == MOCK_FAIL_NFQ_OPEN)
    return NULL;
  munit_assert_size(nfqOpenCount, <=, MOCK_CAPACITY);
  return (struct nfq_handle *)&handleTokens[nfqOpenCount - 1];
}

int nfq_close(struct nfq_handle *handle) {
  munit_assert_not_null(handle);
  nfqCloseCount++;
  return 0;
}

int nfq_unbind_pf(struct nfq_handle *handle, uint16_t protocolFamily) {
  munit_assert_not_null(handle);
  munit_assert_uint16(protocolFamily, ==, AF_INET);
  nfqUnbindCount++;
  return mockFailure == MOCK_FAIL_NFQ_UNBIND ? -1 : 0;
}

int nfq_bind_pf(struct nfq_handle *handle, uint16_t protocolFamily) {
  munit_assert_not_null(handle);
  munit_assert_uint16(protocolFamily, ==, AF_INET);
  nfqBindCount++;
  return mockFailure == MOCK_FAIL_NFQ_BIND ? -1 : 0;
}

struct nfq_q_handle *nfq_create_queue(struct nfq_handle *handle,
                                      uint16_t number, nfq_callback *callback,
                                      void *data) {
  size_t index = nfqCreateCount;

  munit_assert_not_null(handle);
  munit_assert_not_null(callback);
  munit_assert_not_null(data);
  nfqCreateCount++;
  if (mockFailure == MOCK_FAIL_NFQ_CREATE)
    return NULL;
  munit_assert_size(index, <, MOCK_CAPACITY);
  queueNumbers[index] = number;
  queueCallbacks[index] = callback;
  queueCallbackData[index] = data;
  return (struct nfq_q_handle *)&queueTokens[index];
}

int nfq_destroy_queue(struct nfq_q_handle *queue) {
  munit_assert_not_null(queue);
  nfqDestroyCount++;
  return 0;
}

int nfq_set_mode(struct nfq_q_handle *queue, uint8_t mode,
                 unsigned int length) {
  munit_assert_not_null(queue);
  munit_assert_uint8(mode, ==, NFQNL_COPY_PACKET);
  munit_assert_uint(length, ==, NFQ_BUFFER_SIZE);
  nfqSetModeCount++;
  return mockFailure == MOCK_FAIL_NFQ_MODE ? -1 : 0;
}

int nfq_fd(struct nfq_handle *handle) {
  munit_assert_not_null(handle);
  return mockFailure == MOCK_FAIL_NFQ_FD ? -1 : 77;
}

int nfq_handle_packet(struct nfq_handle *handle, char *buffer, int length) {
  munit_assert_not_null(handle);
  munit_assert_not_null(buffer);
  munit_assert_int(length, ==, (int)sizeof(packetPayload));
  munit_assert_memory_equal(sizeof(packetPayload), buffer, packetPayload);
  handlePacketCount++;
  return mockFailure == MOCK_FAIL_NFQ_HANDLE_PACKET ? -1 : 0;
}

int nfq_get_payload(struct nfq_data *data, unsigned char **payload) {
  munit_assert_not_null(data);
  munit_assert_not_null(payload);
  if (!providePayload) {
    *payload = NULL;
    return -1;
  }
  *payload = packetPayload;
  return payloadLength;
}

struct nfqnl_msg_packet_hdr *
nfq_get_msg_packet_hdr(struct nfq_data *data) {
  munit_assert_not_null(data);
  return providePacketHeader ? &packetHeader : NULL;
}

struct nfqnl_msg_packet_hw *nfq_get_packet_hw(struct nfq_data *data) {
  munit_assert_not_null(data);
  return provideHardwareAddress ? &packetHardwareAddress : NULL;
}

int nfq_set_verdict(struct nfq_q_handle *queue, uint32_t packetId,
                    uint32_t verdict, uint32_t dataLength,
                    const unsigned char *buffer) {
  munit_assert_not_null(queue);
  munit_assert_uint32(dataLength, ==, 0);
  munit_assert_null(buffer);
  verdictCount++;
  lastPacketId = packetId;
  lastVerdict = verdict;
  return 17;
}

void ClearNetfilterContext(TNetfilterContext **contexts, size_t count) {
  if (contexts == NULL || count == 0)
    return;
  StopNetfilterProcessing(contexts, count);
  for (size_t i = 0; i < count; i++) {
    if (contexts[i] == NULL)
      continue;
    if (contexts[i]->redirectSocket >= 0)
      close(contexts[i]->redirectSocket);
    free(contexts[i]->redirectNetworkPacket);
    if (contexts[i]->nfQueue != NULL)
      nfq_destroy_queue(contexts[i]->nfQueue);
    if (contexts[i]->nfqHandle != NULL)
      nfq_close(contexts[i]->nfqHandle);
    free(contexts[i]);
    contexts[i] = NULL;
  }
}

static void DestroyContexts(TNetfilterContext **contexts, size_t count) {
  ClearNetfilterContext(contexts, count);
  free(contexts);
}

static MunitResult TestHTTPConfiguration(
    const MunitParameter parameters[], void *fixture) {
  static char interfaceName[] = "eth-test";
  static char redirectHost[] = "redirect.example";
  static const char expectedPayload[] =
      REDIRECT_PAYLOAD1 "redirect.example" REDIRECT_PAYLOAD2;
  TNetfilterContext **contexts = NULL;
  size_t expectedLength = IP4_HDRLEN + sizeof(struct tcphdr) +
                          sizeof(expectedPayload) - 1;

  (void)parameters;
  (void)fixture;
  ResetMocks();
  contexts = InitNetfilterConfiguration(2, interfaceName, redirectHost, 120,
                                        NETFILTER_TYPE_HTTP);
  munit_assert_not_null(contexts);
  munit_assert_size(socketCount, ==, 2);
  munit_assert_size(ioctlCount, ==, 2);
  munit_assert_size(setsockoptCount, ==, 2);
  munit_assert_size(nfqOpenCount, ==, 2);
  munit_assert_size(nfqCreateCount, ==, 2);
  munit_assert_uint16(queueNumbers[0], ==, 120);
  munit_assert_uint16(queueNumbers[1], ==, 121);
  munit_assert_string_equal(capturedInterface, interfaceName);

  for (size_t i = 0; i < 2; i++) {
    munit_assert_not_null(contexts[i]);
    munit_assert_int(contexts[i]->redirectSocket, ==, 101 + (int)i);
    munit_assert_int(contexts[i]->ifIndex, ==, 42);
    munit_assert_ptr_equal(contexts[i]->nfqParseCallback,
                           ProcessRawPacketHTTP);
    munit_assert_size(contexts[i]->redirectDataLen, ==, expectedLength);
    munit_assert_memory_equal(
        sizeof(expectedPayload) - 1,
        contexts[i]->redirectNetworkPacket + IP4_HDRLEN +
            sizeof(struct tcphdr),
        expectedPayload);
    munit_assert_not_null(queueCallbacks[i]);
    munit_assert_ptr_equal(queueCallbackData[i], contexts[i]);
  }

  DestroyContexts(contexts, 2);
  munit_assert_size(closeCount, ==, 2);
  munit_assert_size(nfqDestroyCount, ==, 2);
  munit_assert_size(nfqCloseCount, ==, 2);
  return MUNIT_OK;
}

static MunitResult TestDNSConfiguration(
    const MunitParameter parameters[], void *fixture) {
  static char interfaceName[] = "dns-test";
  static char redirectHost[] = "redirect.example";
  TNetfilterContext **contexts = NULL;

  (void)parameters;
  (void)fixture;
  ResetMocks();
  contexts = InitNetfilterConfiguration(1, interfaceName, redirectHost, 530,
                                        NETFILTER_TYPE_DNS);
  munit_assert_not_null(contexts);
  munit_assert_size(getaddrinfoCount, ==, 1);
  munit_assert_size(freeaddrinfoCount, ==, 1);
  munit_assert_ptr_equal(contexts[0]->nfqParseCallback, ProcessRawPacketDNS);
  munit_assert_size(contexts[0]->redirectDataLen, ==, NFQ_BUFFER_SIZE);

  const struct udphdr *udpHeader =
      (const struct udphdr *)(contexts[0]->redirectNetworkPacket + IP4_HDRLEN);
  const TDNSHeader *dnsHeader =
      (const TDNSHeader *)(contexts[0]->redirectNetworkPacket + IP4_HDRLEN +
                           sizeof(struct udphdr));
  const TDNSAnswer *answer =
      (const TDNSAnswer *)(contexts[0]->redirectNetworkPacket + IP4_HDRLEN +
                           sizeof(struct udphdr) + sizeof(TDNSHeader));
  munit_assert_uint16(be16toh(udpHeader->source), ==, 53);
  munit_assert_true(dnsHeader->qr);
  munit_assert_true(dnsHeader->rd);
  munit_assert_true(dnsHeader->ra);
  munit_assert_uint16(be16toh(dnsHeader->questionCount), ==, 1);
  munit_assert_uint16(be16toh(dnsHeader->answerCount), ==, 1);
  munit_assert_uint16(be16toh(answer->name), ==, 0xc00c);
  munit_assert_uint16(be16toh(answer->type), ==, 1);
  munit_assert_uint16(be16toh(answer->addrClass), ==, 1);
  munit_assert_uint32(be32toh(answer->ttl), ==, 3568);
  munit_assert_uint16(be16toh(answer->rdlength), ==, 4);
  munit_assert_uint32(answer->rdata, ==, inet_addr("203.0.113.45"));

  DestroyContexts(contexts, 1);
  return MUNIT_OK;
}

static MunitResult TestQueueCallbackVerdicts(
    const MunitParameter parameters[], void *fixture) {
  static char interfaceName[] = "callback-test";
  static char redirectHost[] = "redirect.example";
  TNetfilterContext **contexts = NULL;
  nfq_callback *callback = NULL;
  struct nfgenmsg *message = (struct nfgenmsg *)(uintptr_t)1;
  struct nfq_data *data = (struct nfq_data *)(uintptr_t)1;
  int callbackResult = 0;

  (void)parameters;
  (void)fixture;
  ResetMocks();
  contexts = InitNetfilterConfiguration(1, interfaceName, redirectHost, 10,
                                        NETFILTER_TYPE_HTTP);
  munit_assert_not_null(contexts);
  callback = queueCallbacks[0];
  munit_assert_not_null(callback);

  parseShouldDrop = true;
  callbackResult = callback(contexts[0]->nfQueue, message, data, contexts[0]);
  munit_assert_int(callbackResult, ==, 17);
  munit_assert_size(parseCount, ==, 1);
  munit_assert_size(verdictCount, ==, 1);
  munit_assert_uint32(lastPacketId, ==, 0x12345678);
  munit_assert_uint32(lastVerdict, ==, NF_DROP);

  parseShouldDrop = false;
  callbackResult = callback(contexts[0]->nfQueue, message, data, contexts[0]);
  munit_assert_int(callbackResult, ==, 17);
  munit_assert_uint32(lastVerdict, ==, NF_ACCEPT);

  providePayload = false;
  callbackResult = callback(contexts[0]->nfQueue, message, data, contexts[0]);
  munit_assert_int(callbackResult, ==, 17);
  munit_assert_size(parseCount, ==, 2);
  munit_assert_uint32(lastVerdict, ==, NF_ACCEPT);
  providePayload = true;

  payloadLength = 0;
  callbackResult = callback(contexts[0]->nfQueue, message, data, contexts[0]);
  munit_assert_int(callbackResult, ==, 17);
  munit_assert_size(parseCount, ==, 2);
  payloadLength = (int)sizeof(packetPayload);

  packetHardwareAddress.hw_addrlen = htobe16(ETH_ALEN - 1);
  callbackResult = callback(contexts[0]->nfQueue, message, data, contexts[0]);
  munit_assert_int(callbackResult, ==, 17);
  munit_assert_size(parseCount, ==, 2);
  packetHardwareAddress.hw_addrlen = htobe16(ETH_ALEN);

  contexts[0]->nfqParseCallback = NULL;
  callbackResult = callback(contexts[0]->nfQueue, message, data, contexts[0]);
  munit_assert_int(callbackResult, ==, 17);
  munit_assert_size(parseCount, ==, 2);

  providePacketHeader = false;
  munit_assert_int(callback(contexts[0]->nfQueue, message, data, contexts[0]),
                   ==, -1);
  providePacketHeader = true;
  munit_assert_int(callback(NULL, message, data, contexts[0]), ==, -1);
  munit_assert_int(callback(contexts[0]->nfQueue, NULL, data, contexts[0]), ==,
                   -1);
  munit_assert_int(callback(contexts[0]->nfQueue, message, NULL, contexts[0]),
                   ==, -1);
  munit_assert_int(callback(contexts[0]->nfQueue, message, data, NULL), ==, -1);

  DestroyContexts(contexts, 1);
  return MUNIT_OK;
}

static MunitResult TestInitializationFailuresAreCleanedUp(
    const MunitParameter parameters[], void *fixture) {
  static const TMockFailure failures[] = {
      MOCK_FAIL_SOCKET,       MOCK_FAIL_IOCTL,
      MOCK_FAIL_SETSOCKOPT,   MOCK_FAIL_NFQ_OPEN,
      MOCK_FAIL_NFQ_UNBIND,   MOCK_FAIL_NFQ_BIND,
      MOCK_FAIL_NFQ_CREATE,   MOCK_FAIL_NFQ_MODE,
      MOCK_FAIL_GETADDRINFO,  MOCK_FAIL_EMPTY_ADDRINFO,
      MOCK_FAIL_INVALID_ADDRINFO,
  };
  static char interfaceName[] = "failure-test";
  static char redirectHost[] = "redirect.example";

  (void)parameters;
  (void)fixture;
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
    ResetMocks();
    mockFailure = failures[i];
    munit_assert_null(InitNetfilterConfiguration(
        1, interfaceName, redirectHost, 100, NETFILTER_TYPE_DNS));
    if (failures[i] == MOCK_FAIL_SOCKET)
      munit_assert_size(closeCount, ==, 0);
    else
      munit_assert_size(closeCount, ==, 1);
    munit_assert_size(standardDescriptorCloseCount, ==, 0);
    if (nfqCreateCount > 0 && failures[i] != MOCK_FAIL_NFQ_CREATE)
      munit_assert_size(nfqDestroyCount, ==, 1);
    if (nfqOpenCount > 0 && failures[i] != MOCK_FAIL_NFQ_OPEN)
      munit_assert_size(nfqCloseCount, ==, 1);
  }
  return MUNIT_OK;
}

static MunitResult TestInvalidInitializationArguments(
    const MunitParameter parameters[], void *fixture) {
  static char interfaceName[] = "argument-test";
  static char redirectHost[] = "redirect.example";
  char longInterface[IFNAMSIZ + 1];
  char *longHost = NULL;

  (void)parameters;
  (void)fixture;
  ResetMocks();
  memset(longInterface, 'x', sizeof(longInterface) - 1);
  longInterface[sizeof(longInterface) - 1] = '\0';
  longHost = munit_malloc(NFQ_BUFFER_SIZE + 1);
  memset(longHost, 'h', NFQ_BUFFER_SIZE);
  longHost[NFQ_BUFFER_SIZE] = '\0';

  munit_assert_null(InitNetfilterConfiguration(
      0, interfaceName, redirectHost, 1, NETFILTER_TYPE_HTTP));
  munit_assert_null(InitNetfilterConfiguration(
      1, NULL, redirectHost, 1, NETFILTER_TYPE_HTTP));
  munit_assert_null(InitNetfilterConfiguration(
      1, interfaceName, NULL, 1, NETFILTER_TYPE_HTTP));
  munit_assert_null(InitNetfilterConfiguration(
      1, interfaceName, redirectHost, 1, NETFILTER_TYPE_IP));
  munit_assert_null(InitNetfilterConfiguration(
      2, interfaceName, redirectHost, UINT16_MAX, NETFILTER_TYPE_HTTP));
  munit_assert_null(InitNetfilterConfiguration(
      1, longInterface, redirectHost, 1, NETFILTER_TYPE_HTTP));
  munit_assert_null(InitNetfilterConfiguration(
      1, interfaceName, longHost, 1, NETFILTER_TYPE_HTTP));
  munit_assert_size(socketCount, ==, 0);

  free(longHost);
  return MUNIT_OK;
}

static MunitResult TestThreadLifecycle(
    const MunitParameter parameters[], void *fixture) {
  static char interfaceName[] = "thread-test";
  static char redirectHost[] = "redirect.example";
  TNetfilterContext **contexts = NULL;
  pfHashMap *httpRules = NULL;

  (void)parameters;
  (void)fixture;
  ResetMocks();
  contexts = InitNetfilterConfiguration(2, interfaceName, redirectHost, 200,
                                        NETFILTER_TYPE_HTTP);
  munit_assert_not_null(contexts);
  httpRules = pfHashMapCreate(NULL, 31);
  munit_assert_not_null(httpRules);

  StartHTTPNetfilterProcessing(contexts, 2, httpRules);
  munit_assert_size(pthreadCreateCount, ==, 2);
  munit_assert_ptr_equal(contexts[0]->httpRules, httpRules);
  munit_assert_ptr_equal(contexts[1]->httpRules, httpRules);
  munit_assert_not_null(threadRoutines[0]);
  munit_assert_null(threadRoutines[0](threadArguments[0]));
  munit_assert_size(recvCount, ==, 1);
  munit_assert_size(handlePacketCount, ==, 1);

  flagMatrixReload = 0;
  mockRecvMode = MOCK_RECV_EINTR_THEN_ERROR;
  recvModeCount = 0;
  munit_assert_null(threadRoutines[1](threadArguments[1]));
  munit_assert_size(recvCount, ==, 3);

  flagMatrixReload = 0;
  mockRecvMode = MOCK_RECV_PACKET;
  recvModeCount = 0;
  mockFailure = MOCK_FAIL_NFQ_HANDLE_PACKET;
  munit_assert_null(threadRoutines[1](threadArguments[1]));
  munit_assert_size(recvCount, ==, 4);
  munit_assert_size(handlePacketCount, ==, 2);
  mockFailure = MOCK_FAIL_NONE;

  StopNetfilterProcessing(contexts, 2);
  munit_assert_size(pthreadKillCount, ==, 2);
  munit_assert_size(pthreadCancelCount, ==, 2);
  munit_assert_size(pthreadJoinCount, ==, 2);
  munit_assert_uint64((uint64_t)contexts[0]->threadId, ==, 0);
  munit_assert_uint64((uint64_t)contexts[1]->threadId, ==, 0);

  DestroyContexts(contexts, 2);
  pfHashMapDestroy(httpRules);
  return MUNIT_OK;
}

static MunitResult TestThreadLifecycleFailures(
    const MunitParameter parameters[], void *fixture) {
  static char interfaceName[] = "thread-failure";
  static char redirectHost[] = "redirect.example";
  TNetfilterContext **contexts = NULL;
  pfHashMap *httpRules = NULL;

  (void)parameters;
  (void)fixture;
  ResetMocks();
  contexts = InitNetfilterConfiguration(1, interfaceName, redirectHost, 300,
                                        NETFILTER_TYPE_HTTP);
  munit_assert_not_null(contexts);
  httpRules = pfHashMapCreate(NULL, 31);
  munit_assert_not_null(httpRules);

  StartHTTPNetfilterProcessing(NULL, 0, NULL);
  StartHTTPNetfilterProcessing(NULL, 1, httpRules);
  StartHTTPNetfilterProcessing(contexts, 1, NULL);
  flagMatrixShutdown = 1;
  StartHTTPNetfilterProcessing(contexts, 1, httpRules);
  flagMatrixShutdown = 0;
  flagMatrixReconfigure = 1;
  StartHTTPNetfilterProcessing(contexts, 1, httpRules);
  flagMatrixReconfigure = 0;
  munit_assert_size(pthreadCreateCount, ==, 0);

  mockFailure = MOCK_FAIL_PTHREAD_CREATE;
  StartHTTPNetfilterProcessing(contexts, 1, httpRules);
  munit_assert_size(pthreadCreateCount, ==, 0);
  mockFailure = MOCK_FAIL_NONE;
  StartHTTPNetfilterProcessing(contexts, 1, httpRules);
  munit_assert_size(pthreadCreateCount, ==, 1);

  mockFailure = MOCK_FAIL_NFQ_FD;
  munit_assert_null(threadRoutines[0](threadArguments[0]));
  munit_assert_size(recvCount, ==, 0);

  mockFailure = MOCK_FAIL_PTHREAD_JOIN;
  StopNetfilterProcessing(contexts, 1);
  munit_assert_uint64((uint64_t)contexts[0]->threadId, ==, 0);
  StopNetfilterProcessing(NULL, 1);
  StopNetfilterProcessing(contexts, 0);

  mockFailure = MOCK_FAIL_NONE;
  DestroyContexts(contexts, 1);
  pfHashMapDestroy(httpRules);
  return MUNIT_OK;
}

static MunitTest netfilterTests[] = {
    {"/http-configuration", TestHTTPConfiguration, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/dns-configuration", TestDNSConfiguration, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/queue-callback-verdicts", TestQueueCallbackVerdicts, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/initialization-failure-cleanup",
     TestInitializationFailuresAreCleanedUp, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-initialization-arguments", TestInvalidInitializationArguments,
     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/thread-lifecycle", TestThreadLifecycle, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/thread-lifecycle-failures", TestThreadLifecycleFailures, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite netfilterSuite = {
    "/netfilter", netfilterTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  return munit_suite_main(&netfilterSuite, NULL, argc, argv);
}
