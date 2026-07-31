TARGET = zapret-checker
DOWNLOAD_TARGET = zapret-download
SIGN_TARGET = rutoken-sign
HASH_BENCHMARK_TARGET = zapret-hash-benchmark
TEST_TARGET = tests/test_core
SOAP_TEST_TARGET = tests/test_soap
SOAP_INTERACTION_TEST_TARGET = tests/test_soap_interaction
SOAP_SCENARIO_TEST_TARGET = tests/test_soap_scenarios
REGISTER_TEST_TARGET = tests/test_register
CONFIGURATION_TEST_TARGET = tests/test_configuration
HTTP_TRANSPORT_TEST_TARGET = tests/test_http_transport
RAW_HTTP_TEST_TARGET = tests/test_raw_http
RAW_DNS_TEST_TARGET = tests/test_raw_dns
NETFILTER_TEST_TARGET = tests/test_netfilter
CLEANING_TEST_TARGET = tests/test_cleaning
SMTP_TEST_TARGET = tests/test_smtp
CHECKER_TEST_TARGET = tests/test_checker
TEST_SANITIZER_TARGET = tests/test_core-sanitize
SOAP_TEST_SANITIZER_TARGET = tests/test_soap-sanitize
SOAP_INTERACTION_TEST_SANITIZER_TARGET = tests/test_soap_interaction-sanitize
SOAP_SCENARIO_TEST_SANITIZER_TARGET = tests/test_soap_scenarios-sanitize
REGISTER_TEST_SANITIZER_TARGET = tests/test_register-sanitize
CONFIGURATION_TEST_SANITIZER_TARGET = tests/test_configuration-sanitize
HTTP_TRANSPORT_TEST_SANITIZER_TARGET = tests/test_http_transport-sanitize
RAW_HTTP_TEST_SANITIZER_TARGET = tests/test_raw_http-sanitize
RAW_DNS_TEST_SANITIZER_TARGET = tests/test_raw_dns-sanitize
NETFILTER_TEST_SANITIZER_TARGET = tests/test_netfilter-sanitize
CLEANING_TEST_SANITIZER_TARGET = tests/test_cleaning-sanitize
SMTP_TEST_SANITIZER_TARGET = tests/test_smtp-sanitize
CHECKER_TEST_SANITIZER_TARGET = tests/test_checker-sanitize
SOAP_TEST_FIXTURES = tests/fixtures/soap/README.md $(wildcard tests/fixtures/soap/*.xml)
REGISTER_TEST_FIXTURES = tests/fixtures/register/README.md $(wildcard tests/fixtures/register/*.xml) tests/fixtures/register/blacklist.zip.base64
CONFIGURATION_TEST_FIXTURES = tests/fixtures/configuration/README.md $(wildcard tests/fixtures/configuration/*.xml)
PREFIX ?=
SRCS = zapret-checker.c zapret-soap.c zapret-smtp.c zapret-configuration.c zapret-process.c zapret-netfilter.c zapret-rawHTTP.c zapret-rawDNS.c zapret-cleaning.c util.c sign.c pfhash.c
CFG = zapret-checker.xml custom.xml
OBJS = $(SRCS:.c=.o)
DOWNLOAD_OBJS = zapret-download.o zapret-soap.o zapret-smtp.o util.o sign.o
CFLAGS_LOCAL = -g -O3 -Wall -Wextra -std=gnu99 `xml2-config --cflags` `curl-config --cflags` `pkg-config --cflags libzip`
LDFLAGS_LOCAL = -g -lnetfilter_queue `xml2-config --libs` `curl-config --libs` `pkg-config --libs libzip` -ldl -lpthread -lidn2 -lm
DOWNLOAD_LDFLAGS = `xml2-config --libs` `curl-config --libs` `pkg-config --libs libzip` -ldl -lidn2
TEST_CFLAGS = -g -O0 -Wall -Wextra -std=gnu99 -I. `xml2-config --cflags` `curl-config --cflags`
TEST_LDFLAGS = `xml2-config --libs` `curl-config --libs`
SANITIZER_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer
NETFILTER_WRAP_FLAGS = -Wl,--wrap=socket -Wl,--wrap=ioctl -Wl,--wrap=setsockopt -Wl,--wrap=close -Wl,--wrap=getaddrinfo -Wl,--wrap=freeaddrinfo -Wl,--wrap=recv -Wl,--wrap=pthread_create -Wl,--wrap=pthread_kill -Wl,--wrap=pthread_cancel -Wl,--wrap=pthread_join
CHECKER_WRAP_FLAGS = -Wl,--wrap=sigemptyset -Wl,--wrap=sigaction -Wl,--wrap=sleep -Wl,--wrap=pause -Wl,--wrap=time -Wl,--wrap=pipe -Wl,--wrap=fork -Wl,--wrap=fdopen -Wl,--wrap=close -Wl,--wrap=waitpid
CC = gcc

.PHONY: all benchmark test test-sanitize clean install uninstall

all: $(TARGET) $(DOWNLOAD_TARGET) $(SIGN_TARGET)

benchmark: $(HASH_BENCHMARK_TARGET)

$(TARGET): zapret-configuration.h $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS_LOCAL) -o $(TARGET)

$(DOWNLOAD_TARGET): $(DOWNLOAD_OBJS)
	$(CC) $(DOWNLOAD_OBJS) $(DOWNLOAD_LDFLAGS) -o $(DOWNLOAD_TARGET)

$(HASH_BENCHMARK_TARGET): zapret-hash-benchmark.c zapret-process.c zapret-checker.h zapret-structures.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(CFLAGS_LOCAL) zapret-hash-benchmark.c zapret-process.c util.c pfhash.c $(DOWNLOAD_LDFLAGS) -o $(HASH_BENCHMARK_TARGET)

zapret-configuration.h: zapret-configuration.h.include

zapret-configuration.h.include: zapret-checker.xsd
	cat zapret-checker.xsd | tr -d '\t\r\n' | xxd -i > zapret-configuration.h.include

%.o: %.c
	$(CC) -c $(CFLAGS_LOCAL) $< -o $@

zapret-checker.o zapret-process.o: zapret-structures.h

test: $(TEST_TARGET) $(SOAP_TEST_TARGET) $(SOAP_INTERACTION_TEST_TARGET) $(SOAP_SCENARIO_TEST_TARGET) $(REGISTER_TEST_TARGET) $(CONFIGURATION_TEST_TARGET) $(HTTP_TRANSPORT_TEST_TARGET) $(RAW_HTTP_TEST_TARGET) $(RAW_DNS_TEST_TARGET) $(NETFILTER_TEST_TARGET) $(CLEANING_TEST_TARGET) $(SMTP_TEST_TARGET) $(CHECKER_TEST_TARGET)
	./$(TEST_TARGET)
	./$(SOAP_TEST_TARGET)
	./$(SOAP_INTERACTION_TEST_TARGET)
	./$(SOAP_SCENARIO_TEST_TARGET)
	./$(REGISTER_TEST_TARGET)
	./$(CONFIGURATION_TEST_TARGET)
	./$(HTTP_TRANSPORT_TEST_TARGET)
	./$(RAW_HTTP_TEST_TARGET)
	./$(RAW_DNS_TEST_TARGET)
	./$(NETFILTER_TEST_TARGET)
	./$(CLEANING_TEST_TARGET)
	./$(SMTP_TEST_TARGET)
	./$(CHECKER_TEST_TARGET)

$(TEST_TARGET): tests/test_core.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_core.c tests/vendor/munit/munit.c util.c pfhash.c $(TEST_LDFLAGS) -o $(TEST_TARGET)

$(SOAP_TEST_TARGET): tests/test_soap.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_soap.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl -o $(SOAP_TEST_TARGET)

$(SOAP_INTERACTION_TEST_TARGET): tests/test_soap_interaction.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_soap_interaction.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl -Wl,--wrap=SendHTTPPost -Wl,--wrap=sleep -o $(SOAP_INTERACTION_TEST_TARGET)

$(SOAP_SCENARIO_TEST_TARGET): tests/test_soap_scenarios.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_soap_scenarios.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl -Wl,--wrap=SendHTTPPost -Wl,--wrap=sleep -o $(SOAP_SCENARIO_TEST_TARGET)

$(REGISTER_TEST_TARGET): tests/test_register.c $(REGISTER_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-process.c zapret-checker.h zapret-structures.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) `pkg-config --cflags libzip` tests/test_register.c tests/vendor/munit/munit.c zapret-process.c util.c pfhash.c $(TEST_LDFLAGS) `pkg-config --libs libzip` -lidn2 -Wl,--wrap=getaddrinfo -Wl,--wrap=freeaddrinfo -o $(REGISTER_TEST_TARGET)

$(CONFIGURATION_TEST_TARGET): tests/test_configuration.c $(CONFIGURATION_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-configuration.c zapret-configuration.h zapret-configuration.h.include zapret-checker.h zapret-structures.h util.c util.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_configuration.c tests/vendor/munit/munit.c zapret-configuration.c util.c $(TEST_LDFLAGS) -o $(CONFIGURATION_TEST_TARGET)

$(HTTP_TRANSPORT_TEST_TARGET): tests/test_http_transport.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h util.c util.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_http_transport.c tests/vendor/munit/munit.c util.c $(TEST_LDFLAGS) -o $(HTTP_TRANSPORT_TEST_TARGET)

$(RAW_HTTP_TEST_TARGET): tests/test_raw_http.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-rawHTTP.c zapret-checker.h zapret-structures.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_raw_http.c tests/vendor/munit/munit.c zapret-rawHTTP.c util.c pfhash.c $(TEST_LDFLAGS) -Wl,--wrap=sendto -o $(RAW_HTTP_TEST_TARGET)

$(RAW_DNS_TEST_TARGET): tests/test_raw_dns.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-rawDNS.c zapret-checker.h zapret-structures.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_raw_dns.c tests/vendor/munit/munit.c zapret-rawDNS.c util.c pfhash.c $(TEST_LDFLAGS) -Wl,--wrap=sendto -o $(RAW_DNS_TEST_TARGET)

$(NETFILTER_TEST_TARGET): tests/test_netfilter.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-netfilter.c zapret-checker.h zapret-structures.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_netfilter.c tests/vendor/munit/munit.c zapret-netfilter.c pfhash.c $(TEST_LDFLAGS) -lpthread $(NETFILTER_WRAP_FLAGS) -o $(NETFILTER_TEST_TARGET)

$(CLEANING_TEST_TARGET): tests/test_cleaning.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-cleaning.c zapret-checker.h zapret-structures.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_cleaning.c tests/vendor/munit/munit.c zapret-cleaning.c pfhash.c $(TEST_LDFLAGS) -o $(CLEANING_TEST_TARGET)

$(SMTP_TEST_TARGET): tests/test_smtp.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-smtp.c zapret-checker.h zapret-structures.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_smtp.c tests/vendor/munit/munit.c zapret-smtp.c -o $(SMTP_TEST_TARGET)

$(CHECKER_TEST_TARGET): tests/test_checker.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-checker.c zapret-checker.h zapret-structures.h pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_checker.c tests/vendor/munit/munit.c `xml2-config --libs` $(CHECKER_WRAP_FLAGS) -o $(CHECKER_TEST_TARGET)

test-sanitize: $(TEST_SANITIZER_TARGET) $(SOAP_TEST_SANITIZER_TARGET) $(SOAP_INTERACTION_TEST_SANITIZER_TARGET) $(SOAP_SCENARIO_TEST_SANITIZER_TARGET) $(REGISTER_TEST_SANITIZER_TARGET) $(CONFIGURATION_TEST_SANITIZER_TARGET) $(HTTP_TRANSPORT_TEST_SANITIZER_TARGET) $(RAW_HTTP_TEST_SANITIZER_TARGET) $(RAW_DNS_TEST_SANITIZER_TARGET) $(NETFILTER_TEST_SANITIZER_TARGET) $(CLEANING_TEST_SANITIZER_TARGET) $(SMTP_TEST_SANITIZER_TARGET) $(CHECKER_TEST_SANITIZER_TARGET)
	./$(TEST_SANITIZER_TARGET)
	./$(SOAP_TEST_SANITIZER_TARGET)
	./$(SOAP_INTERACTION_TEST_SANITIZER_TARGET)
	./$(SOAP_SCENARIO_TEST_SANITIZER_TARGET)
	./$(REGISTER_TEST_SANITIZER_TARGET)
	./$(CONFIGURATION_TEST_SANITIZER_TARGET)
	./$(HTTP_TRANSPORT_TEST_SANITIZER_TARGET)
	./$(RAW_HTTP_TEST_SANITIZER_TARGET)
	./$(RAW_DNS_TEST_SANITIZER_TARGET)
	./$(NETFILTER_TEST_SANITIZER_TARGET)
	./$(CLEANING_TEST_SANITIZER_TARGET)
	./$(SMTP_TEST_SANITIZER_TARGET)
	./$(CHECKER_TEST_SANITIZER_TARGET)

$(TEST_SANITIZER_TARGET): tests/test_core.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_core.c tests/vendor/munit/munit.c util.c pfhash.c $(TEST_LDFLAGS) $(SANITIZER_FLAGS) -o $(TEST_SANITIZER_TARGET)

$(SOAP_TEST_SANITIZER_TARGET): tests/test_soap.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_soap.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl $(SANITIZER_FLAGS) -o $(SOAP_TEST_SANITIZER_TARGET)

$(SOAP_INTERACTION_TEST_SANITIZER_TARGET): tests/test_soap_interaction.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_soap_interaction.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl -Wl,--wrap=SendHTTPPost -Wl,--wrap=sleep $(SANITIZER_FLAGS) -o $(SOAP_INTERACTION_TEST_SANITIZER_TARGET)

$(SOAP_SCENARIO_TEST_SANITIZER_TARGET): tests/test_soap_scenarios.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_soap_scenarios.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl -Wl,--wrap=SendHTTPPost -Wl,--wrap=sleep $(SANITIZER_FLAGS) -o $(SOAP_SCENARIO_TEST_SANITIZER_TARGET)

$(REGISTER_TEST_SANITIZER_TARGET): tests/test_register.c $(REGISTER_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-process.c zapret-checker.h zapret-structures.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) `pkg-config --cflags libzip` tests/test_register.c tests/vendor/munit/munit.c zapret-process.c util.c pfhash.c $(TEST_LDFLAGS) `pkg-config --libs libzip` -lidn2 -Wl,--wrap=getaddrinfo -Wl,--wrap=freeaddrinfo $(SANITIZER_FLAGS) -o $(REGISTER_TEST_SANITIZER_TARGET)

$(CONFIGURATION_TEST_SANITIZER_TARGET): tests/test_configuration.c $(CONFIGURATION_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-configuration.c zapret-configuration.h zapret-configuration.h.include zapret-checker.h zapret-structures.h util.c util.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_configuration.c tests/vendor/munit/munit.c zapret-configuration.c util.c $(TEST_LDFLAGS) $(SANITIZER_FLAGS) -o $(CONFIGURATION_TEST_SANITIZER_TARGET)

$(HTTP_TRANSPORT_TEST_SANITIZER_TARGET): tests/test_http_transport.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h util.c util.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_http_transport.c tests/vendor/munit/munit.c util.c $(TEST_LDFLAGS) $(SANITIZER_FLAGS) -o $(HTTP_TRANSPORT_TEST_SANITIZER_TARGET)

$(RAW_HTTP_TEST_SANITIZER_TARGET): tests/test_raw_http.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-rawHTTP.c zapret-checker.h zapret-structures.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_raw_http.c tests/vendor/munit/munit.c zapret-rawHTTP.c util.c pfhash.c $(TEST_LDFLAGS) -Wl,--wrap=sendto $(SANITIZER_FLAGS) -o $(RAW_HTTP_TEST_SANITIZER_TARGET)

$(RAW_DNS_TEST_SANITIZER_TARGET): tests/test_raw_dns.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-rawDNS.c zapret-checker.h zapret-structures.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_raw_dns.c tests/vendor/munit/munit.c zapret-rawDNS.c util.c pfhash.c $(TEST_LDFLAGS) -Wl,--wrap=sendto $(SANITIZER_FLAGS) -o $(RAW_DNS_TEST_SANITIZER_TARGET)

$(NETFILTER_TEST_SANITIZER_TARGET): tests/test_netfilter.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-netfilter.c zapret-checker.h zapret-structures.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_netfilter.c tests/vendor/munit/munit.c zapret-netfilter.c pfhash.c $(TEST_LDFLAGS) -lpthread $(NETFILTER_WRAP_FLAGS) $(SANITIZER_FLAGS) -o $(NETFILTER_TEST_SANITIZER_TARGET)

$(CLEANING_TEST_SANITIZER_TARGET): tests/test_cleaning.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-cleaning.c zapret-checker.h zapret-structures.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_cleaning.c tests/vendor/munit/munit.c zapret-cleaning.c pfhash.c $(TEST_LDFLAGS) $(SANITIZER_FLAGS) -o $(CLEANING_TEST_SANITIZER_TARGET)

$(SMTP_TEST_SANITIZER_TARGET): tests/test_smtp.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-smtp.c zapret-checker.h zapret-structures.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_smtp.c tests/vendor/munit/munit.c zapret-smtp.c $(SANITIZER_FLAGS) -o $(SMTP_TEST_SANITIZER_TARGET)

$(CHECKER_TEST_SANITIZER_TARGET): tests/test_checker.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-checker.c zapret-checker.h zapret-structures.h pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_checker.c tests/vendor/munit/munit.c `xml2-config --libs` $(CHECKER_WRAP_FLAGS) $(SANITIZER_FLAGS) -o $(CHECKER_TEST_SANITIZER_TARGET)

clean:
	rm -rf $(TARGET) $(DOWNLOAD_TARGET) $(SIGN_TARGET) $(HASH_BENCHMARK_TARGET) $(TEST_TARGET) $(SOAP_TEST_TARGET) $(SOAP_INTERACTION_TEST_TARGET) $(SOAP_SCENARIO_TEST_TARGET) $(REGISTER_TEST_TARGET) $(CONFIGURATION_TEST_TARGET) $(HTTP_TRANSPORT_TEST_TARGET) $(RAW_HTTP_TEST_TARGET) $(RAW_DNS_TEST_TARGET) $(NETFILTER_TEST_TARGET) $(CLEANING_TEST_TARGET) $(SMTP_TEST_TARGET) $(CHECKER_TEST_TARGET) $(TEST_SANITIZER_TARGET) $(SOAP_TEST_SANITIZER_TARGET) $(SOAP_INTERACTION_TEST_SANITIZER_TARGET) $(SOAP_SCENARIO_TEST_SANITIZER_TARGET) $(REGISTER_TEST_SANITIZER_TARGET) $(CONFIGURATION_TEST_SANITIZER_TARGET) $(HTTP_TRANSPORT_TEST_SANITIZER_TARGET) $(RAW_HTTP_TEST_SANITIZER_TARGET) $(RAW_DNS_TEST_SANITIZER_TARGET) $(NETFILTER_TEST_SANITIZER_TARGET) $(CLEANING_TEST_SANITIZER_TARGET) $(SMTP_TEST_SANITIZER_TARGET) $(CHECKER_TEST_SANITIZER_TARGET) $(OBJS) zapret-download.o zapret-configuration.h.include

install:
	install $(TARGET) $(DOWNLOAD_TARGET) $(SIGN_TARGET) $(PREFIX)/bin
#	mkdir -pv $(PREFIX)/bin/ $(PREFIX)/etc/$(TARGET)/
#	cp -vf $(CFG) $(PREFIX)/etc/$(TARGET)/
#	cp -vf ./$(TARGET).service /etc/systemd/system

uninstall:
	rm -rf $(PREFIX)/bin/$(TARGET)
	rm -rf $(PREFIX)/bin/$(DOWNLOAD_TARGET)
	rm -rf $(PREFIX)/bin/$(SIGN_TARGET)
	rm -rf /etc/systemd/system/$(TARGET).service
	rm -rf /etc/$(TARGET)/

$(SIGN_TARGET): rutoken-sign.c sign.c sign.h
	$(CC) rutoken-sign.c sign.c -ldl -o $(SIGN_TARGET)
