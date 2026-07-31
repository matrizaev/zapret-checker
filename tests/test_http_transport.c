#include "allheaders.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>

#include "util.h"
#include "vendor/munit/munit.h"

typedef struct {
  pid_t pid;
  uint16_t port;
} TLoopbackServer;

static bool WriteAll(int file, const void *buffer, size_t length) {
  const unsigned char *bytes = buffer;
  size_t offset = 0;

  while (offset < length) {
    ssize_t written = write(file, bytes + offset, length - offset);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return false;
    offset += (size_t)written;
  }
  return true;
}

static size_t FindHeaderEnd(const unsigned char *request,
                            size_t requestLength) {
  static const unsigned char separator[] = "\r\n\r\n";

  if (request == NULL || requestLength < sizeof(separator) - 1)
    return SIZE_MAX;
  for (size_t i = 0; i <= requestLength - (sizeof(separator) - 1); i++) {
    if (!memcmp(request + i, separator, sizeof(separator) - 1))
      return i + sizeof(separator) - 1;
  }
  return SIZE_MAX;
}

static bool ParseContentLength(const unsigned char *request,
                               size_t headerLength, size_t *contentLength) {
  char *headers = NULL;
  char *value = NULL;
  char *end = NULL;
  uintmax_t parsed = 0;
  bool result = false;

  if (request == NULL || contentLength == NULL ||
      headerLength == SIZE_MAX || headerLength > SIZE_MAX - 1)
    return false;
  headers = malloc(headerLength + 1);
  if (headers == NULL)
    return false;
  memcpy(headers, request, headerLength);
  headers[headerLength] = '\0';
  value = strcasestr(headers, "\r\nContent-Length:");
  if (value == NULL)
    goto cleanup;
  value += strlen("\r\nContent-Length:");
  while (*value == ' ' || *value == '\t')
    value++;
  errno = 0;
  parsed = strtoumax(value, &end, 10);
  if (errno == ERANGE || end == value || parsed > SIZE_MAX ||
      (*end != '\r' && *end != '\n'))
    goto cleanup;
  *contentLength = (size_t)parsed;
  result = true;

cleanup:
  free(headers);
  return result;
}

static bool ServeRequest(int listener, unsigned int statusCode,
                         const void *expectedPayload,
                         size_t expectedPayloadLength, const void *response,
                         size_t responseLength) {
  unsigned char request[8192];
  struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
  size_t requestLength = 0;
  size_t headerEnd = SIZE_MAX;
  size_t contentLength = 0;
  int client = -1;
  char responseHeaders[256];
  int responseHeadersLength = 0;
  bool requestValid = false;
  bool result = false;

  client = accept(listener, NULL, NULL);
  if (client == -1)
    return false;
  if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                 sizeof(timeout)) != 0)
    goto cleanup;

  while (requestLength < sizeof(request)) {
    ssize_t received =
        recv(client, request + requestLength,
             sizeof(request) - requestLength, 0);
    if (received < 0 && errno == EINTR)
      continue;
    if (received <= 0)
      goto cleanup;
    requestLength += (size_t)received;
    headerEnd = FindHeaderEnd(request, requestLength);
    if (headerEnd == SIZE_MAX)
      continue;
    if (!ParseContentLength(request, headerEnd, &contentLength) ||
        contentLength > sizeof(request) - headerEnd)
      goto cleanup;
    if (requestLength >= headerEnd + contentLength)
      break;
  }
  if (headerEnd == SIZE_MAX || contentLength != expectedPayloadLength ||
      requestLength < headerEnd + contentLength)
    goto cleanup;

  requestValid =
      requestLength >= strlen("POST /soap HTTP/1.1\r\n") &&
      !memcmp(request, "POST /soap HTTP/1.1\r\n",
              strlen("POST /soap HTTP/1.1\r\n")) &&
      memmem(request, headerEnd, "\r\nX-Test-Header: transport\r\n",
             strlen("\r\nX-Test-Header: transport\r\n")) != NULL &&
      !memcmp(request + headerEnd, expectedPayload, expectedPayloadLength);

  responseHeadersLength = snprintf(
      responseHeaders, sizeof(responseHeaders),
      "HTTP/1.1 %u %s\r\nContent-Length: %zu\r\n"
      "Content-Type: text/plain\r\nConnection: close\r\n\r\n",
      statusCode, statusCode == 200 ? "OK" : "Service Unavailable",
      responseLength);
  if (responseHeadersLength <= 0 ||
      (size_t)responseHeadersLength >= sizeof(responseHeaders))
    goto cleanup;
  if (!WriteAll(client, responseHeaders, (size_t)responseHeadersLength) ||
      !WriteAll(client, response, responseLength))
    goto cleanup;
  result = requestValid;

cleanup:
  close(client);
  return result;
}

static TLoopbackServer StartLoopbackServer(
    unsigned int statusCode, const void *expectedPayload,
    size_t expectedPayloadLength, const void *response,
    size_t responseLength) {
  TLoopbackServer server = {.pid = -1, .port = 0};
  struct sockaddr_in address = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = htobe32(INADDR_LOOPBACK),
      .sin_port = 0,
  };
  socklen_t addressLength = sizeof(address);
  int listener = -1;
  int reuseAddress = 1;

  listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener == -1)
    return server;
  if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuseAddress,
                 sizeof(reuseAddress)) != 0 ||
      bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      getsockname(listener, (struct sockaddr *)&address, &addressLength) != 0 ||
      listen(listener, 1) != 0)
    goto error;
  server.port = be16toh(address.sin_port);
  server.pid = fork();
  if (server.pid == 0) {
    bool served = ServeRequest(listener, statusCode, expectedPayload,
                               expectedPayloadLength, response,
                               responseLength);
    close(listener);
    _exit(served ? EXIT_SUCCESS : EXIT_FAILURE);
  }
  if (server.pid < 0)
    goto error;
  close(listener);
  return server;

error:
  close(listener);
  server.pid = -1;
  server.port = 0;
  return server;
}

static bool WaitForLoopbackServer(TLoopbackServer server) {
  int status = 0;

  if (server.pid <= 0)
    return false;
  while (waitpid(server.pid, &status, 0) < 0) {
    if (errno != EINTR)
      return false;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;
}

static MunitResult TestRealHttpPostRoundTrip(
    const MunitParameter parameters[], void *fixture) {
  static const char payload[] = "<request>loopback</request>";
  static const char expectedResponse[] = "synthetic-http-response";
  char *headers[] = {
      "Content-Type: text/xml; charset=utf-8",
      "X-Test-Header: transport",
  };
  TLoopbackServer server =
      StartLoopbackServer(200, payload, sizeof(payload) - 1,
                          expectedResponse, sizeof(expectedResponse) - 1);
  char url[128];
  void *response = NULL;
  size_t responseLength = 0;
  int written = 0;
  bool serverSucceeded = false;

  (void)parameters;
  (void)fixture;

  munit_assert_int(server.pid, >, 0);
  written = snprintf(url, sizeof(url), "http://127.0.0.1:%u/soap",
                     server.port);
  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, sizeof(url));
  response = SendHTTPPost(url, payload, headers,
                          sizeof(headers) / sizeof(headers[0]),
                          sizeof(payload) - 1, &responseLength);
  serverSucceeded = WaitForLoopbackServer(server);

  munit_assert_true(serverSucceeded);
  munit_assert_not_null(response);
  munit_assert_size(responseLength, ==, sizeof(expectedResponse) - 1);
  munit_assert_memory_equal(responseLength, response, expectedResponse);
  free(response);
  return MUNIT_OK;
}

static MunitResult TestHttpErrorIsRejected(
    const MunitParameter parameters[], void *fixture) {
  static const char payload[] = "request";
  static const char errorResponse[] = "temporarily unavailable";
  char *headers[] = {"X-Test-Header: transport"};
  TLoopbackServer server =
      StartLoopbackServer(503, payload, sizeof(payload) - 1,
                          errorResponse, sizeof(errorResponse) - 1);
  char url[128];
  void *response = NULL;
  size_t responseLength = 123;
  int written = 0;
  bool serverSucceeded = false;

  (void)parameters;
  (void)fixture;

  munit_assert_int(server.pid, >, 0);
  written = snprintf(url, sizeof(url), "http://127.0.0.1:%u/soap",
                     server.port);
  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, sizeof(url));
  response = SendHTTPPost(url, payload, headers,
                          sizeof(headers) / sizeof(headers[0]),
                          sizeof(payload) - 1, &responseLength);
  serverSucceeded = WaitForLoopbackServer(server);

  munit_assert_true(serverSucceeded);
  munit_assert_null(response);
  munit_assert_size(responseLength, ==, 0);
  return MUNIT_OK;
}

static MunitResult TestInvalidHttpArguments(
    const MunitParameter parameters[], void *fixture) {
  static const char payload[] = "request";
  size_t responseLength = 123;

  (void)parameters;
  (void)fixture;

  munit_assert_null(
      SendHTTPPost(NULL, payload, NULL, 0, sizeof(payload) - 1,
                   &responseLength));
  munit_assert_size(responseLength, ==, 0);
  responseLength = 123;
  munit_assert_null(
      SendHTTPPost("http://127.0.0.1/", NULL, NULL, 0, 1,
                   &responseLength));
  munit_assert_size(responseLength, ==, 0);
  return MUNIT_OK;
}

static MunitTest httpTransportTests[] = {
    {"/round-trip", TestRealHttpPostRoundTrip, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/http-error", TestHttpErrorIsRejected, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-arguments", TestInvalidHttpArguments, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite httpTransportSuite = {
    "/http-transport", httpTransportTests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  int result = 0;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK)
    return EXIT_FAILURE;
  result = munit_suite_main(&httpTransportSuite, NULL, argc, argv);
  curl_global_cleanup();
  return result;
}
