#include "allheaders.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

#include "vendor/munit/munit.h"
#include "zapret-checker.h"

#define TEST_PACKET_CAPACITY 2048
#define DNS_QUESTION_OFFSET                                                    \
  (IP4_HDRLEN + sizeof(struct udphdr) + sizeof(TDNSHeader))
#define DNS_PACKET_SIZE                                                        \
  (IP4_HDRLEN + sizeof(struct udphdr) + sizeof(TDNSHeader) +                  \
   sizeof(TDNSAnswer))
#define REDIRECT_ADDRESS "203.0.113.45"

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

typedef struct {
  uint8_t data[TEST_PACKET_CAPACITY];
  size_t length;
  struct sockaddr_ll address;
} TCapturedPacket;

typedef struct {
  pfHashSet *blockedKeys;
  TNetfilterContext context;
  TDNSAnswer answerTemplate;
} TRawDNSFixture;

static TCapturedPacket capturedPacket;
static size_t capturedPacketCount = 0;

ssize_t __wrap_sendto(int socket, const void *buffer, size_t length, int flags,
                      const struct sockaddr *destination,
                      socklen_t destinationLength) {
  (void)socket;
  (void)flags;
  if (buffer == NULL || destination == NULL ||
      destinationLength < sizeof(struct sockaddr_ll) ||
      capturedPacketCount != 0 || length > sizeof(capturedPacket.data)) {
    errno = EINVAL;
    return -1;
  }

  memcpy(capturedPacket.data, buffer, length);
  capturedPacket.length = length;
  memcpy(&capturedPacket.address, destination,
         sizeof(capturedPacket.address));
  capturedPacketCount++;
  return (ssize_t)length;
}

static void ResetCapturedPacket(void) {
  memset(&capturedPacket, 0, sizeof(capturedPacket));
  capturedPacketCount = 0;
}

static size_t EncodeQuestion(uint8_t *output, size_t capacity,
                             const char *domain, uint16_t questionType,
                             uint16_t questionClass) {
  const char *label = domain;
  uint8_t *cursor = output;
  uint16_t networkValue = 0;

  if (output == NULL || domain == NULL || *domain == '\0')
    return 0;
  if (*label == '.')
    label++;
  while (*label != '\0') {
    const char *separator = strchr(label, '.');
    size_t labelLength =
        separator == NULL ? strlen(label) : (size_t)(separator - label);
    size_t used = (size_t)(cursor - output);
    if (labelLength == 0 || labelLength > 63 || used > capacity ||
        labelLength + 1 > capacity - used)
      return 0;
    *cursor++ = (uint8_t)labelLength;
    memcpy(cursor, label, labelLength);
    cursor += labelLength;
    if (separator == NULL)
      break;
    label = separator + 1;
  }
  size_t used = (size_t)(cursor - output);
  if (used > capacity || 5 > capacity - used)
    return 0;
  *cursor++ = 0;
  networkValue = htobe16(questionType);
  memcpy(cursor, &networkValue, sizeof(networkValue));
  cursor += sizeof(networkValue);
  networkValue = htobe16(questionClass);
  memcpy(cursor, &networkValue, sizeof(networkValue));
  cursor += sizeof(networkValue);
  return (size_t)(cursor - output);
}

static size_t BuildDNSQuery(uint8_t *packet, size_t capacity,
                            const char *domain, uint16_t questionType,
                            uint16_t questionClass, size_t *questionSize) {
  struct iphdr *ipHeader = NULL;
  struct udphdr *udpHeader = NULL;
  TDNSHeader *dnsHeader = NULL;
  size_t encodedQuestionSize = 0;
  size_t packetLength = 0;

  if (packet == NULL || domain == NULL || questionSize == NULL ||
      capacity < DNS_QUESTION_OFFSET)
    return 0;
  memset(packet, 0, capacity);
  encodedQuestionSize =
      EncodeQuestion(packet + DNS_QUESTION_OFFSET,
                     capacity - DNS_QUESTION_OFFSET, domain, questionType,
                     questionClass);
  if (encodedQuestionSize == 0)
    return 0;
  packetLength = DNS_QUESTION_OFFSET + encodedQuestionSize;
  if (packetLength > UINT16_MAX)
    return 0;

  ipHeader = (struct iphdr *)packet;
  ipHeader->version = 4;
  ipHeader->ihl = IP4_HDRLEN / 4;
  ipHeader->protocol = IPPROTO_UDP;
  ipHeader->tot_len = htobe16((uint16_t)packetLength);
  ipHeader->saddr = inet_addr("192.0.2.10");
  ipHeader->daddr = inet_addr("198.51.100.53");

  udpHeader = (struct udphdr *)(packet + IP4_HDRLEN);
  udpHeader->source = htobe16(53000);
  udpHeader->dest = htobe16(53);
  udpHeader->len =
      htobe16((uint16_t)(packetLength - IP4_HDRLEN));

  dnsHeader =
      (TDNSHeader *)(packet + IP4_HDRLEN + sizeof(struct udphdr));
  dnsHeader->id = htobe16(0x1234);
  dnsHeader->rd = 1;
  dnsHeader->questionCount = htobe16(1);
  *questionSize = encodedQuestionSize;
  return packetLength;
}

static uint16_t CalculateUDPChecksum(const uint8_t *packet,
                                     size_t packetLength) {
  const struct iphdr *ipHeader = NULL;
  TPseudoHeader *pseudoHeader = NULL;
  struct udphdr *copiedUDPHeader = NULL;
  uint8_t *checksumData = NULL;
  size_t udpLength = 0;
  uint16_t result = 0;

  if (packet == NULL || packetLength < IP4_HDRLEN + sizeof(struct udphdr))
    return 0;
  ipHeader = (const struct iphdr *)packet;
  udpLength = packetLength - IP4_HDRLEN;
  checksumData = calloc(sizeof(TPseudoHeader) + udpLength, 1);
  if (checksumData == NULL)
    return 0;

  pseudoHeader = (TPseudoHeader *)checksumData;
  pseudoHeader->srcAddr = ipHeader->saddr;
  pseudoHeader->dstAddr = ipHeader->daddr;
  pseudoHeader->proto = IPPROTO_UDP;
  pseudoHeader->length = htobe16((uint16_t)udpLength);
  memcpy(checksumData + sizeof(TPseudoHeader), packet + IP4_HDRLEN, udpLength);
  copiedUDPHeader =
      (struct udphdr *)(checksumData + sizeof(TPseudoHeader));
  copiedUDPHeader->check = 0;
  result = checksum((uint16_t *)checksumData,
                    sizeof(TPseudoHeader) + udpLength);
  free(checksumData);
  return result;
}

static void AssertIPHeader(size_t expectedLength) {
  struct iphdr copiedHeader;
  const struct iphdr *header = (const struct iphdr *)capturedPacket.data;
  uint16_t expectedChecksum = 0;

  munit_assert_uint8(header->version, ==, 4);
  munit_assert_uint8(header->ihl, ==, IP4_HDRLEN / 4);
  munit_assert_uint8(header->protocol, ==, IPPROTO_UDP);
  munit_assert_uint8(header->ttl, ==, 64);
  munit_assert_uint16(be16toh(header->tot_len), ==, expectedLength);
  munit_assert_uint32(header->saddr, ==, inet_addr("198.51.100.53"));
  munit_assert_uint32(header->daddr, ==, inet_addr("192.0.2.10"));

  memcpy(&copiedHeader, header, sizeof(copiedHeader));
  expectedChecksum = copiedHeader.check;
  copiedHeader.check = 0;
  munit_assert_uint16(checksum((uint16_t *)&copiedHeader,
                              sizeof(copiedHeader)),
                      ==, expectedChecksum);
}

static void AssertCapturedDNSResponse(const TRawDNSFixture *fixture,
                                      const char *expectedDomain,
                                      size_t expectedQuestionSize,
                                      const uint8_t hardwareAddress[8]) {
  const struct udphdr *udpHeader = NULL;
  const TDNSHeader *dnsHeader = NULL;
  const TDNSAnswer *answer = NULL;
  uint8_t expectedQuestion[256] = {0};
  size_t responseLength = DNS_PACKET_SIZE + expectedQuestionSize;

  munit_assert_size(capturedPacketCount, ==, 1);
  munit_assert_size(capturedPacket.length, ==, responseLength);
  AssertIPHeader(responseLength);

  munit_assert_int(capturedPacket.address.sll_family, ==, AF_PACKET);
  munit_assert_uint16(capturedPacket.address.sll_protocol, ==,
                      htons(ETH_P_IP));
  munit_assert_int(capturedPacket.address.sll_ifindex, ==, 9);
  munit_assert_uint8(capturedPacket.address.sll_halen, ==, ETH_ALEN);
  munit_assert_memory_equal(ETH_ALEN, capturedPacket.address.sll_addr,
                            hardwareAddress);

  udpHeader =
      (const struct udphdr *)(capturedPacket.data + IP4_HDRLEN);
  munit_assert_uint16(be16toh(udpHeader->source), ==, 53);
  munit_assert_uint16(be16toh(udpHeader->dest), ==, 53000);
  munit_assert_uint16(be16toh(udpHeader->len), ==,
                      responseLength - IP4_HDRLEN);
  munit_assert_uint16(udpHeader->check, ==,
                      CalculateUDPChecksum(capturedPacket.data,
                                           capturedPacket.length));

  dnsHeader = (const TDNSHeader *)(capturedPacket.data + IP4_HDRLEN +
                                  sizeof(struct udphdr));
  munit_assert_uint16(be16toh(dnsHeader->id), ==, 0x1234);
  munit_assert_true(dnsHeader->qr);
  munit_assert_true(dnsHeader->rd);
  munit_assert_true(dnsHeader->ra);
  munit_assert_uint16(be16toh(dnsHeader->questionCount), ==, 1);
  munit_assert_uint16(be16toh(dnsHeader->answerCount), ==, 1);

  munit_assert_size(EncodeQuestion(expectedQuestion, sizeof(expectedQuestion),
                                   expectedDomain, 1, 1),
                    ==, expectedQuestionSize);
  munit_assert_memory_equal(expectedQuestionSize,
                            capturedPacket.data + DNS_QUESTION_OFFSET,
                            expectedQuestion);

  answer = (const TDNSAnswer *)(capturedPacket.data + DNS_QUESTION_OFFSET +
                               expectedQuestionSize);
  munit_assert_uint16(be16toh(answer->name), ==, 0xc00c);
  munit_assert_uint16(be16toh(answer->type), ==, 1);
  munit_assert_uint16(be16toh(answer->addrClass), ==, 1);
  munit_assert_uint32(be32toh(answer->ttl), ==, 3568);
  munit_assert_uint16(be16toh(answer->rdlength), ==, 4);
  munit_assert_uint32(answer->rdata, ==, inet_addr(REDIRECT_ADDRESS));

  munit_assert_memory_equal(
      sizeof(fixture->answerTemplate),
      fixture->context.redirectNetworkPacket + DNS_QUESTION_OFFSET,
      &fixture->answerTemplate);
}

static bool AddBlockedDomain(pfHashSet *set, const char *domain) {
  char domainBuffer[256];
  uint8_t *dnsName = NULL;
  bool result = false;
  int written = 0;

  written = snprintf(domainBuffer, sizeof(domainBuffer), ".%s", domain);
  if (set == NULL || domain == NULL || written <= 0 ||
      (size_t)written >= sizeof(domainBuffer))
    return false;
  dnsName = String2DNSNotation(domainBuffer);
  if (dnsName == NULL)
    return false;
  result = pfHashSetAdd(set, (char *)dnsName);
  free(dnsName);
  return result;
}

static void *RawDNSSetup(const MunitParameter parameters[], void *userData) {
  TRawDNSFixture *fixture = munit_malloc(sizeof(*fixture));
  struct udphdr *udpHeader = NULL;
  TDNSHeader *dnsHeader = NULL;
  TDNSAnswer *answer = NULL;

  (void)parameters;
  (void)userData;
  memset(fixture, 0, sizeof(*fixture));
  fixture->blockedKeys = pfHashSetCreate(NULL, 31);
  if (fixture->blockedKeys == NULL ||
      !AddBlockedDomain(fixture->blockedKeys, "example.com") ||
      !AddBlockedDomain(fixture->blockedKeys, "blocked.test"))
    munit_error("cannot populate DNS hash table");

  fixture->context.blockedKeys = fixture->blockedKeys;
  fixture->context.ifIndex = 9;
  fixture->context.redirectSocket = 43;
  fixture->context.redirectDataLen = TEST_PACKET_CAPACITY;
  fixture->context.redirectNetworkPacket =
      munit_malloc(fixture->context.redirectDataLen);
  memset(fixture->context.redirectNetworkPacket, 0,
         fixture->context.redirectDataLen);

  udpHeader = (struct udphdr *)(fixture->context.redirectNetworkPacket +
                                IP4_HDRLEN);
  udpHeader->source = htobe16(53);
  dnsHeader = (TDNSHeader *)(fixture->context.redirectNetworkPacket +
                             IP4_HDRLEN + sizeof(struct udphdr));
  dnsHeader->qr = 1;
  dnsHeader->rd = 1;
  dnsHeader->ra = 1;
  dnsHeader->questionCount = htobe16(1);
  dnsHeader->answerCount = htobe16(1);
  answer = (TDNSAnswer *)(fixture->context.redirectNetworkPacket +
                          DNS_QUESTION_OFFSET);
  answer->name = htobe16(0xc00c);
  answer->type = htobe16(1);
  answer->addrClass = htobe16(1);
  answer->ttl = htobe32(3568);
  answer->rdlength = htobe16(4);
  answer->rdata = inet_addr(REDIRECT_ADDRESS);
  memcpy(&fixture->answerTemplate, answer, sizeof(fixture->answerTemplate));
  ResetCapturedPacket();
  return fixture;
}

static void RawDNSTearDown(void *fixtureData) {
  TRawDNSFixture *fixture = fixtureData;

  if (fixture == NULL)
    return;
  pfHashSetDestroy(fixture->blockedKeys);
  free(fixture->context.redirectNetworkPacket);
  free(fixture);
}

static MunitResult TestParentDomainProducesResponse(
    const MunitParameter parameters[], void *fixtureData) {
  static const uint8_t hardwareAddress[8] = {0x00, 0x11, 0x22, 0x33,
                                             0x44, 0x55, 0x66, 0x77};
  TRawDNSFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));
  size_t packetLength = 0;
  size_t questionSize = 0;

  (void)parameters;
  packetLength = BuildDNSQuery(packet, sizeof(packet), "WWW.Example.COM", 1,
                               1, &questionSize);
  munit_assert_size(packetLength, >, 0);
  munit_assert_true(ProcessRawPacketDNS(
      packet, packetLength, &fixture->context, (uint8_t *)hardwareAddress));
  AssertCapturedDNSResponse(fixture, "www.example.com", questionSize,
                            hardwareAddress);
  return MUNIT_OK;
}

static MunitResult TestExactAndAllowedDomains(
    const MunitParameter parameters[], void *fixtureData) {
  static uint8_t hardwareAddress[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  TRawDNSFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));
  size_t questionSize = 0;
  size_t packetLength = 0;

  (void)parameters;
  packetLength = BuildDNSQuery(packet, sizeof(packet), "blocked.test", 1, 1,
                               &questionSize);
  munit_assert_true(ProcessRawPacketDNS(packet, packetLength,
                                        &fixture->context, hardwareAddress));
  munit_assert_size(capturedPacketCount, ==, 1);

  ResetCapturedPacket();
  packetLength = BuildDNSQuery(packet, sizeof(packet), "allowed.test", 1, 1,
                               &questionSize);
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));
  munit_assert_size(capturedPacketCount, ==, 0);
  return MUNIT_OK;
}

static MunitResult TestUnsupportedQuestionsAndFlags(
    const MunitParameter parameters[], void *fixtureData) {
  static uint8_t hardwareAddress[8] = {0};
  TRawDNSFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));
  size_t questionSize = 0;
  size_t packetLength = 0;
  TDNSHeader *dnsHeader = NULL;
  struct iphdr *ipHeader = NULL;

  (void)parameters;
  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 28, 1,
                               &questionSize);
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 3,
                               &questionSize);
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  dnsHeader = (TDNSHeader *)(packet + IP4_HDRLEN + sizeof(struct udphdr));
  dnsHeader->questionCount = 0;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  dnsHeader = (TDNSHeader *)(packet + IP4_HDRLEN + sizeof(struct udphdr));
  dnsHeader->questionCount = htobe16(2);
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  dnsHeader = (TDNSHeader *)(packet + IP4_HDRLEN + sizeof(struct udphdr));
  dnsHeader->qr = 1;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  dnsHeader = (TDNSHeader *)(packet + IP4_HDRLEN + sizeof(struct udphdr));
  dnsHeader->opcode = 1;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  dnsHeader = (TDNSHeader *)(packet + IP4_HDRLEN + sizeof(struct udphdr));
  dnsHeader->tc = 1;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  ipHeader = (struct iphdr *)packet;
  ipHeader->frag_off = htobe16(1);
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));
  munit_assert_size(capturedPacketCount, ==, 0);
  return MUNIT_OK;
}

static MunitResult TestMalformedPacketLengthsAndNames(
    const MunitParameter parameters[], void *fixtureData) {
  static uint8_t hardwareAddress[8] = {0};
  TRawDNSFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));
  size_t questionSize = 0;
  size_t packetLength = 0;
  struct iphdr *ipHeader = NULL;
  struct udphdr *udpHeader = NULL;

  (void)parameters;
  munit_assert_false(ProcessRawPacketDNS(NULL, 0, &fixture->context,
                                         hardwareAddress));
  munit_assert_false(ProcessRawPacketDNS(packet, 0, &fixture->context,
                                         hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  ipHeader = (struct iphdr *)packet;
  ipHeader->version = 6;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  ipHeader = (struct iphdr *)packet;
  ipHeader->protocol = IPPROTO_TCP;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  ipHeader = (struct iphdr *)packet;
  ipHeader->ihl = 4;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  ipHeader = (struct iphdr *)packet;
  ipHeader->ihl = 15;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  ipHeader = (struct iphdr *)packet;
  ipHeader->tot_len = htobe16((uint16_t)(packetLength + 1));
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  ipHeader = (struct iphdr *)packet;
  ipHeader->tot_len = htobe16(IP4_HDRLEN + sizeof(struct udphdr) +
                              sizeof(TDNSHeader) - 1);
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  udpHeader = (struct udphdr *)(packet + IP4_HDRLEN);
  udpHeader->len = htobe16(sizeof(struct udphdr) + sizeof(TDNSHeader) - 1);
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  udpHeader = (struct udphdr *)(packet + IP4_HDRLEN);
  udpHeader->len =
      htobe16((uint16_t)(packetLength - IP4_HDRLEN + 1));
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  udpHeader = (struct udphdr *)(packet + IP4_HDRLEN);
  udpHeader->len = htobe16(sizeof(struct udphdr) + sizeof(TDNSHeader));
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  packet[DNS_QUESTION_OFFSET] = 64;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  packet[DNS_QUESTION_OFFSET] = 0xc0;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  udpHeader = (struct udphdr *)(packet + IP4_HDRLEN);
  udpHeader->len = htobe16(sizeof(struct udphdr) + sizeof(TDNSHeader) + 2);
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  packet[DNS_QUESTION_OFFSET] = 0;
  udpHeader = (struct udphdr *)(packet + IP4_HDRLEN);
  udpHeader->len = htobe16(sizeof(struct udphdr) + sizeof(TDNSHeader) + 1);
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));
  munit_assert_size(capturedPacketCount, ==, 0);
  return MUNIT_OK;
}

static MunitResult TestInvalidContextIsRejected(
    const MunitParameter parameters[], void *fixtureData) {
  static uint8_t hardwareAddress[8] = {0};
  TRawDNSFixture *fixture = fixtureData;
  uint8_t packet[TEST_PACKET_CAPACITY] __attribute__((aligned(4)));
  const pfHashSet *blockedKeys = fixture->context.blockedKeys;
  uint8_t *redirectPacket = fixture->context.redirectNetworkPacket;
  size_t redirectLength = fixture->context.redirectDataLen;
  size_t questionSize = 0;
  size_t packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com",
                                      1, 1, &questionSize);

  (void)parameters;
  munit_assert_false(
      ProcessRawPacketDNS(packet, packetLength, NULL, hardwareAddress));
  munit_assert_false(
      ProcessRawPacketDNS(packet, packetLength, &fixture->context, NULL));

  fixture->context.blockedKeys = NULL;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));
  fixture->context.blockedKeys = blockedKeys;

  fixture->context.redirectNetworkPacket = NULL;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));
  fixture->context.redirectNetworkPacket = redirectPacket;

  packetLength = BuildDNSQuery(packet, sizeof(packet), "example.com", 1, 1,
                               &questionSize);
  fixture->context.redirectDataLen = DNS_PACKET_SIZE + questionSize - 1;
  munit_assert_false(ProcessRawPacketDNS(packet, packetLength,
                                         &fixture->context, hardwareAddress));
  fixture->context.redirectDataLen = redirectLength;

  munit_assert_size(capturedPacketCount, ==, 0);
  return MUNIT_OK;
}

static MunitTest rawDNSTests[] = {
    {"/parent-domain-response", TestParentDomainProducesResponse, RawDNSSetup,
     RawDNSTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/exact-and-allowed-domains", TestExactAndAllowedDomains, RawDNSSetup,
     RawDNSTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/unsupported-questions-and-flags", TestUnsupportedQuestionsAndFlags,
     RawDNSSetup, RawDNSTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/malformed-packets-and-names", TestMalformedPacketLengthsAndNames,
     RawDNSSetup, RawDNSTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-context", TestInvalidContextIsRejected, RawDNSSetup,
     RawDNSTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite rawDNSSuite = {
    "/raw-dns", rawDNSTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  return munit_suite_main(&rawDNSSuite, NULL, argc, argv);
}
