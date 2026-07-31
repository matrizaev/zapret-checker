#include "allheaders.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

#include "vendor/munit/munit.h"
#include "zapret-checker.h"

#define TEST_PACKET_CAPACITY 2048
#define CAPTURED_PACKET_COUNT 2
#define REDIRECT_HOST "redirect.example"
#define REDIRECT_PAYLOAD1 "HTTP/1.1 301 Moved Permanently\r\nLocation: http://"
#define REDIRECT_PAYLOAD2 "/\r\nConnection: close\r\n\r\n"

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

typedef struct {
  uint8_t data[TEST_PACKET_CAPACITY];
  size_t length;
  struct sockaddr_ll address;
} TCapturedPacket;

typedef struct {
  pfHashTable *hashTable;
  TNetfilterContext context;
} TRawHTTPFixture;

static TCapturedPacket capturedPackets[CAPTURED_PACKET_COUNT];
static size_t capturedPacketCount = 0;

ssize_t __wrap_sendto(int socket, const void *buffer, size_t length, int flags,
                      const struct sockaddr *destination,
                      socklen_t destinationLength) {
  TCapturedPacket *captured = NULL;

  (void)socket;
  (void)flags;
  if (buffer == NULL || destination == NULL ||
      destinationLength < sizeof(struct sockaddr_ll) ||
      capturedPacketCount >= CAPTURED_PACKET_COUNT ||
      length > TEST_PACKET_CAPACITY) {
    errno = EINVAL;
    return -1;
  }

  captured = &capturedPackets[capturedPacketCount++];
  memcpy(captured->data, buffer, length);
  captured->length = length;
  memcpy(&captured->address, destination, sizeof(captured->address));
  return (ssize_t)length;
}

static void ResetCapturedPackets(void) {
  memset(capturedPackets, 0, sizeof(capturedPackets));
  capturedPacketCount = 0;
}

static size_t BuildRequestPacket(uint8_t *packet, size_t capacity,
                                 const char *request) {
  struct iphdr *ipHeader = NULL;
  struct tcphdr *tcpHeader = NULL;
  size_t requestLength = 0;
  size_t packetLength = 0;

  if (packet == NULL || request == NULL)
    return 0;
  requestLength = strlen(request);
  if (requestLength > UINT16_MAX - IP4_HDRLEN - sizeof(struct tcphdr))
    return 0;
  packetLength = IP4_HDRLEN + sizeof(struct tcphdr) + requestLength;
  if (packetLength > capacity)
    return 0;

  memset(packet, 0, capacity);
  ipHeader = (struct iphdr *)packet;
  ipHeader->version = 4;
  ipHeader->ihl = IP4_HDRLEN / 4;
  ipHeader->protocol = IPPROTO_TCP;
  ipHeader->tot_len = htobe16((uint16_t)packetLength);
  ipHeader->saddr = inet_addr("192.0.2.10");
  ipHeader->daddr = inet_addr("198.51.100.20");

  tcpHeader = (struct tcphdr *)(packet + IP4_HDRLEN);
  tcpHeader->doff = sizeof(struct tcphdr) / 4;
  tcpHeader->source = htobe16(43210);
  tcpHeader->dest = htobe16(80);
  tcpHeader->seq = htobe32(1000);
  tcpHeader->ack_seq = htobe32(2000);

  memcpy(packet + IP4_HDRLEN + sizeof(struct tcphdr), request, requestLength);
  return packetLength;
}

static uint16_t CalculateTCPChecksum(const uint8_t *packet,
                                     size_t packetLength) {
  const struct iphdr *ipHeader = NULL;
  TPseudoHeader *pseudoHeader = NULL;
  struct tcphdr *copiedTCPHeader = NULL;
  uint8_t *checksumData = NULL;
  size_t tcpLength = 0;
  uint16_t result = 0;

  if (packet == NULL || packetLength < IP4_HDRLEN + sizeof(struct tcphdr))
    return 0;
  ipHeader = (const struct iphdr *)packet;
  tcpLength = packetLength - IP4_HDRLEN;
  checksumData = calloc(sizeof(TPseudoHeader) + tcpLength, 1);
  if (checksumData == NULL)
    return 0;

  pseudoHeader = (TPseudoHeader *)checksumData;
  pseudoHeader->srcAddr = ipHeader->saddr;
  pseudoHeader->dstAddr = ipHeader->daddr;
  pseudoHeader->proto = IPPROTO_TCP;
  pseudoHeader->length = htobe16((uint16_t)tcpLength);
  memcpy(checksumData + sizeof(TPseudoHeader), packet + IP4_HDRLEN, tcpLength);
  copiedTCPHeader =
      (struct tcphdr *)(checksumData + sizeof(TPseudoHeader));
  copiedTCPHeader->check = 0;
  result = checksum((uint16_t *)checksumData,
                    sizeof(TPseudoHeader) + tcpLength);
  free(checksumData);
  return result;
}

static void AssertValidIPHeader(const TCapturedPacket *captured,
                                size_t expectedLength) {
  struct iphdr copiedHeader;
  const struct iphdr *header = NULL;
  uint16_t expectedChecksum = 0;

  munit_assert_not_null(captured);
  munit_assert_size(captured->length, ==, expectedLength);
  header = (const struct iphdr *)captured->data;
  munit_assert_uint8(header->version, ==, 4);
  munit_assert_uint8(header->ihl, ==, IP4_HDRLEN / 4);
  munit_assert_uint8(header->protocol, ==, IPPROTO_TCP);
  munit_assert_uint8(header->ttl, ==, 64);
  munit_assert_uint16(be16toh(header->tot_len), ==, expectedLength);
  munit_assert_uint32(header->saddr, ==, inet_addr("198.51.100.20"));
  munit_assert_uint32(header->daddr, ==, inet_addr("192.0.2.10"));

  memcpy(&copiedHeader, header, sizeof(copiedHeader));
  expectedChecksum = copiedHeader.check;
  copiedHeader.check = 0;
  munit_assert_uint16(checksum((uint16_t *)&copiedHeader,
                              sizeof(copiedHeader)),
                      ==, expectedChecksum);
}

static void AssertCapturedRedirect(size_t requestLength,
                                   const uint8_t hardwareAddress[8],
                                   size_t redirectLength) {
  const TCapturedPacket *ackPacket = &capturedPackets[0];
  const TCapturedPacket *redirectPacket = &capturedPackets[1];
  const struct tcphdr *ackTCP = NULL;
  const struct tcphdr *redirectTCP = NULL;
  const char expectedPayload[] =
      REDIRECT_PAYLOAD1 REDIRECT_HOST REDIRECT_PAYLOAD2;

  munit_assert_size(capturedPacketCount, ==, CAPTURED_PACKET_COUNT);
  AssertValidIPHeader(ackPacket, IP4_HDRLEN + sizeof(struct tcphdr));
  AssertValidIPHeader(redirectPacket, redirectLength);

  munit_assert_int(ackPacket->address.sll_family, ==, AF_PACKET);
  munit_assert_uint16(ackPacket->address.sll_protocol, ==, htons(ETH_P_IP));
  munit_assert_int(ackPacket->address.sll_ifindex, ==, 7);
  munit_assert_uint8(ackPacket->address.sll_halen, ==, ETH_ALEN);
  munit_assert_memory_equal(ETH_ALEN, ackPacket->address.sll_addr,
                            hardwareAddress);
  munit_assert_memory_equal(sizeof(ackPacket->address),
                            &ackPacket->address, &redirectPacket->address);

  ackTCP = (const struct tcphdr *)(ackPacket->data + IP4_HDRLEN);
  munit_assert_uint16(be16toh(ackTCP->source), ==, 80);
  munit_assert_uint16(be16toh(ackTCP->dest), ==, 43210);
  munit_assert_uint32(be32toh(ackTCP->seq), ==, 2000);
  munit_assert_uint32(be32toh(ackTCP->ack_seq), ==, 1000 + requestLength);
  munit_assert_true(ackTCP->ack);
  munit_assert_false(ackTCP->psh);
  munit_assert_false(ackTCP->fin);
  munit_assert_uint16(ackTCP->check, ==,
                      CalculateTCPChecksum(ackPacket->data, ackPacket->length));

  redirectTCP =
      (const struct tcphdr *)(redirectPacket->data + IP4_HDRLEN);
  munit_assert_true(redirectTCP->ack);
  munit_assert_true(redirectTCP->psh);
  munit_assert_true(redirectTCP->fin);
  munit_assert_uint16(
      redirectTCP->check, ==,
      CalculateTCPChecksum(redirectPacket->data, redirectPacket->length));
  munit_assert_memory_equal(
      sizeof(expectedPayload) - 1,
      redirectPacket->data + IP4_HDRLEN + sizeof(struct tcphdr),
      expectedPayload);
}

static void *RawHTTPSetup(const MunitParameter parameters[], void *userData) {
  TRawHTTPFixture *fixture = munit_malloc(sizeof(*fixture));
  const size_t redirectLength =
      IP4_HDRLEN + sizeof(struct tcphdr) + strlen(REDIRECT_PAYLOAD1) +
      strlen(REDIRECT_HOST) + strlen(REDIRECT_PAYLOAD2);
  uint8_t *payload = NULL;

  (void)parameters;
  (void)userData;
  memset(fixture, 0, sizeof(*fixture));
  fixture->hashTable = pfHashCreate(NULL, 31);
  if (fixture->hashTable == NULL)
    munit_error("cannot allocate HTTP hash table");
  if (!pfHashSet(fixture->hashTable, "example.com", "/") ||
      !pfHashSet(fixture->hashTable, "example.com", "/blocked path"))
    munit_error("cannot populate HTTP hash table");

  fixture->context.hashTable = fixture->hashTable;
  fixture->context.ifIndex = 7;
  fixture->context.redirectSocket = 42;
  fixture->context.redirectDataLen = redirectLength;
  fixture->context.redirectNetworkPacket = munit_malloc(redirectLength);
  memset(fixture->context.redirectNetworkPacket, 0, redirectLength);
  payload = fixture->context.redirectNetworkPacket + IP4_HDRLEN +
            sizeof(struct tcphdr);
  memcpy(payload, REDIRECT_PAYLOAD1, strlen(REDIRECT_PAYLOAD1));
  payload += strlen(REDIRECT_PAYLOAD1);
  memcpy(payload, REDIRECT_HOST, strlen(REDIRECT_HOST));
  payload += strlen(REDIRECT_HOST);
  memcpy(payload, REDIRECT_PAYLOAD2, strlen(REDIRECT_PAYLOAD2));
  ResetCapturedPackets();
  return fixture;
}

static void RawHTTPTearDown(void *fixtureData) {
  TRawHTTPFixture *fixture = fixtureData;

  if (fixture == NULL)
    return;
  pfHashDestroy(fixture->hashTable);
  free(fixture->context.redirectNetworkPacket);
  free(fixture);
}

static MunitResult TestRelativeRequestProducesRedirect(
    const MunitParameter parameters[], void *fixtureData) {
  static const char request[] =
      "GET /blocked%20path HTTP/1.1\r\n"
      "User-Agent: raw-http-test\r\n"
      "hOsT: ExAmPlE.CoM\r\n\r\n";
  static const uint8_t hardwareAddress[8] = {0x00, 0x11, 0x22, 0x33,
                                             0x44, 0x55, 0x66, 0x77};
  TRawHTTPFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));
  size_t packetLength = 0;

  (void)parameters;
  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  munit_assert_size(packetLength, >, 0);
  munit_assert_true(ProcessRawPacketHTTP(
      packet, packetLength, &fixture->context, (uint8_t *)hardwareAddress));
  AssertCapturedRedirect(strlen(request), hardwareAddress,
                         fixture->context.redirectDataLen);
  return MUNIT_OK;
}

static MunitResult TestAbsoluteRequestTargets(
    const MunitParameter parameters[], void *fixtureData) {
  static const char *requests[] = {
      "GET http://EXAMPLE.COM HTTP/1.0\r\n\r\n",
      "GET http://Example.Com/blocked%20path HTTP/1.1\r\n"
      "Host: ignored.example\r\n\r\n",
      "GET     /blocked%20path HTTP/1.1\r\nHost: example.com\r\n\r\n",
  };
  static const uint8_t hardwareAddress[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  TRawHTTPFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));

  (void)parameters;
  for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
    size_t packetLength =
        BuildRequestPacket(packet, sizeof(packet), requests[i]);
    ResetCapturedPackets();
    munit_assert_true(ProcessRawPacketHTTP(
        packet, packetLength, &fixture->context, (uint8_t *)hardwareAddress));
    AssertCapturedRedirect(strlen(requests[i]), hardwareAddress,
                           fixture->context.redirectDataLen);
  }
  return MUNIT_OK;
}

static MunitResult TestRequestsThatMustNotBeRedirected(
    const MunitParameter parameters[], void *fixtureData) {
  static const char *requests[] = {
      "",
      "POST /blocked%20path HTTP/1.1\r\nHost: example.com\r\n\r\n",
      "GET /blocked%20path HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
      "GET /allowed HTTP/1.1\r\nHost: example.com\r\n\r\n",
      "GET /blocked%20path HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
      "GET /blocked%20path HTTP/1.1\r\nHost: example.com\r\n",
      "GET https://example.com/blocked%20path HTTP/1.1\r\n\r\n",
      "GET http://missing.example/ HTTP/1.1\r\n\r\n",
      "GET http://missing.example HTTP/1.1\r\n\r\n",
      "GET http://example.com/allowed HTTP/1.1\r\n\r\n",
      "GET http://example.com/no-request-line-terminator\r\n\r\n",
      "GET /blocked\r\nHost:example.com\r\n\r\n",
      "GET http://example.com\r\n\r\n",
      "GET http://example.com\nHeader: value\r\n\r\n",
  };
  static uint8_t hardwareAddress[8] = {0};
  TRawHTTPFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));

  (void)parameters;
  for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
    size_t packetLength =
        BuildRequestPacket(packet, sizeof(packet), requests[i]);
    ResetCapturedPackets();
    munit_assert_false(ProcessRawPacketHTTP(
        packet, packetLength, &fixture->context, hardwareAddress));
    munit_assert_size(capturedPacketCount, ==, 0);
  }
  return MUNIT_OK;
}

static MunitResult TestMalformedPacketLengths(
    const MunitParameter parameters[], void *fixtureData) {
  static const char request[] =
      "GET /blocked%20path HTTP/1.1\r\nHost: example.com\r\n\r\n";
  static uint8_t hardwareAddress[8] = {0};
  TRawHTTPFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));
  struct iphdr *ipHeader = NULL;
  struct tcphdr *tcpHeader = NULL;
  size_t packetLength = 0;

  (void)parameters;
  munit_assert_false(ProcessRawPacketHTTP(NULL, 0, &fixture->context,
                                          hardwareAddress));
  munit_assert_false(ProcessRawPacketHTTP(packet, 0, &fixture->context,
                                          hardwareAddress));

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  ipHeader = (struct iphdr *)packet;
  ipHeader->version = 6;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  ipHeader = (struct iphdr *)packet;
  ipHeader->protocol = IPPROTO_UDP;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  ipHeader = (struct iphdr *)packet;
  ipHeader->tot_len = htobe16((uint16_t)(packetLength + 1));
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  ipHeader = (struct iphdr *)packet;
  ipHeader->ihl = 4;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  ipHeader = (struct iphdr *)packet;
  ipHeader->ihl = 15;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  ipHeader = (struct iphdr *)packet;
  ipHeader->tot_len = htobe16(IP4_HDRLEN);
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  tcpHeader = (struct tcphdr *)(packet + IP4_HDRLEN);
  tcpHeader->doff = 4;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  tcpHeader = (struct tcphdr *)(packet + IP4_HDRLEN);
  tcpHeader->doff = 15;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));

  munit_assert_size(capturedPacketCount, ==, 0);
  return MUNIT_OK;
}

static MunitResult TestInvalidContextIsRejected(
    const MunitParameter parameters[], void *fixtureData) {
  static const char request[] =
      "GET /blocked%20path HTTP/1.1\r\nHost: example.com\r\n\r\n";
  static uint8_t hardwareAddress[8] = {0};
  TRawHTTPFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));
  uint8_t *redirectPacket = fixture->context.redirectNetworkPacket;
  pfHashTable *hashTable = fixture->context.hashTable;
  size_t redirectLength = fixture->context.redirectDataLen;
  size_t packetLength = BuildRequestPacket(packet, sizeof(packet), request);

  (void)parameters;
  munit_assert_false(
      ProcessRawPacketHTTP(packet, packetLength, NULL, hardwareAddress));
  munit_assert_false(
      ProcessRawPacketHTTP(packet, packetLength, &fixture->context, NULL));

  fixture->context.hashTable = NULL;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));
  fixture->context.hashTable = hashTable;

  fixture->context.redirectNetworkPacket = NULL;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));
  fixture->context.redirectNetworkPacket = redirectPacket;

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  fixture->context.redirectDataLen =
      IP4_HDRLEN + sizeof(struct tcphdr) - 1;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));

  packetLength = BuildRequestPacket(packet, sizeof(packet), request);
  fixture->context.redirectDataLen = (size_t)UINT16_MAX + 1;
  munit_assert_false(ProcessRawPacketHTTP(packet, packetLength,
                                          &fixture->context, hardwareAddress));
  fixture->context.redirectDataLen = redirectLength;

  munit_assert_size(capturedPacketCount, ==, 0);
  return MUNIT_OK;
}

static MunitTest rawHTTPTests[] = {
    {"/relative-request-redirect", TestRelativeRequestProducesRedirect,
     RawHTTPSetup, RawHTTPTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/absolute-request-targets", TestAbsoluteRequestTargets, RawHTTPSetup,
     RawHTTPTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/requests-not-redirected", TestRequestsThatMustNotBeRedirected,
     RawHTTPSetup, RawHTTPTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/malformed-packet-lengths", TestMalformedPacketLengths, RawHTTPSetup,
     RawHTTPTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-context", TestInvalidContextIsRejected, RawHTTPSetup,
     RawHTTPTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite rawHTTPSuite = {
    "/raw-http", rawHTTPTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  return munit_suite_main(&rawHTTPSuite, NULL, argc, argv);
}
