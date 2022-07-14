/*************************************************************************
* Модуль фильтрации трафика.                                             *
*************************************************************************/

#include "allheaders.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <linux/netfilter.h>
#include "zapret-checker.h"


#define NFQ_BUFFER_SIZE 0xFFFF

#define REDIRECT_PAYLOAD1 "HTTP/1.1 301 Moved Permanently\r\nLocation: http://"
#define REDIRECT_PAYLOAD2 "/\r\nConnection: close\r\n\r\n"


/*************************************************************************
* Колбэк выборки пакетов из очереди NFQUEUE	                             *
*************************************************************************/
static int NetfilterCallback (struct nfq_q_handle *qh,
                              struct nfgenmsg     *nfmsg,
                              struct nfq_data     *nfad, void *data)
{
	int result = -1;


	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	if (qh != NULL && nfmsg != NULL && nfad != NULL && data != NULL)
	{
		/*************************************************************************
		* Получаем содержимое канального уровня.                                 *
		*************************************************************************/
		uint8_t *payload = NULL;
		int payloadCount = nfq_get_payload(nfad, (unsigned char **)&payload);
		struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
		struct nfqnl_msg_packet_hw* hwAddr = nfq_get_packet_hw (nfad);
		bool dropPacket = false;
		/*************************************************************************
		* Обрабатываем пакет и выносим вердикт.                          *
		*************************************************************************/
		if (payload != NULL && ph!= NULL && payloadCount > 0 && hwAddr != NULL)
		{
			TNetfilterContext *threadData = (TNetfilterContext *)data;
			dropPacket = threadData->nfqParseCallback(payload, payloadCount, threadData, hwAddr->hw_addr);
		}
		if (ph != NULL)
		{
			result = nfq_set_verdict(qh, be32toh(ph->packet_id), dropPacket ? NF_DROP : NF_ACCEPT, 0, NULL);
		}
	}
	return result;
}

/*************************************************************************
* Экземпляр потока фильтрации.                                           *
*************************************************************************/
static void *NetfilterThread (void *data)
{
	char buf[NFQ_BUFFER_SIZE] __attribute__ ((aligned)) = {0};
	int nfqFD = 0;
	ssize_t bytesRcvd = 0;
	TNetfilterContext *threadData = data;

	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	check (threadData != NULL, ERROR_STR_INVALIDINPUT);
	check (threadData->nfQueue != NULL && threadData->nfqHandle != NULL && threadData->redirectNetworkPacket != NULL && threadData->hashTable != NULL, ERROR_STR_INVALIDINPUT);	
	
	/*************************************************************************
	* Получаем дескриптор для чтения пакетов.                                *
	*************************************************************************/
	nfqFD = nfq_fd(threadData->nfqHandle);
	while ((flagMatrixShutdown == 0) && (flagMatrixReconfigure == 0) && (flagMatrixReload == 0))
	{
		/*************************************************************************
		* Читаем и отправляем пакеты на обработку.                               *
		*************************************************************************/
		bytesRcvd = recv (nfqFD, buf, NFQ_BUFFER_SIZE, 0);
		if (bytesRcvd >= 0)
			nfq_handle_packet(threadData->nfqHandle, buf, bytesRcvd);
	}
error:
	return NULL;	
}

/*************************************************************************
* Иницилизруем структуры данных потоков фильтрации.                      *
*************************************************************************/
TNetfilterContext **InitNetfilterConfiguration(size_t count, char *redirectIface, char *redirectHost, size_t netfilterQueue, TNetfilterType threadType)
{
	struct addrinfo *aiResult = NULL;
	struct ifreq ifr;
	TNetfilterContext **result = NULL;
	
	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	check(count > 0 && redirectIface != NULL && redirectHost != NULL, ERROR_STR_INVALIDINPUT);
	
	
	/*************************************************************************
	* Выделяем память под массив структур данных потоков фильтации.          *
	*************************************************************************/
	result = calloc (count, sizeof(TNetfilterContext *));
	check_mem (result);
	
	/*************************************************************************
	* Инициализируем структуру привязки к интерфейсу.                        *
	*************************************************************************/
	memset (&ifr, 0, sizeof (ifr));
	check (snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", redirectIface) > 0, ERROR_STR_INVALIDSTRING);
	
	for (size_t i = 0; i < count; i++)
	{
		result[i] = calloc (1, sizeof (TNetfilterContext));
		check_mem(result[i]);

		result[i]->redirectSocket = socket (PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
		check(result[i]->redirectSocket > 0, ERROR_STR_SOCKETERROR);
		
		check(ioctl (result[i]->redirectSocket, SIOCGIFINDEX, &ifr) >= 0, ERROR_STR_SOCKETERROR);
		check(setsockopt (result[i]->redirectSocket, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) == 0, ERROR_STR_SOCKETERROR);
		result[i]->ifIndex = ifr.ifr_ifindex;
		
		result[i]->nfqHandle = nfq_open ();
		check (result[i]->nfqHandle != NULL, ERROR_STR_PTHREAD);
		check (nfq_unbind_pf (result[i]->nfqHandle, AF_INET) == 0 && nfq_bind_pf (result[i]->nfqHandle, AF_INET) == 0, ERROR_STR_PTHREAD);
		result[i]->nfQueue = nfq_create_queue (result[i]->nfqHandle, netfilterQueue + i, NetfilterCallback, result[i]);
		check (result[i]->nfQueue != NULL, ERROR_STR_PTHREAD);
		check (nfq_set_mode (result[i]->nfQueue, NFQNL_COPY_PACKET, NFQ_BUFFER_SIZE) == 0, ERROR_STR_PTHREAD);
		
		result[i]->redirectNetworkPacket = calloc(NFQ_BUFFER_SIZE, 1);
		check_mem(result[i]->redirectNetworkPacket);
		if (threadType == NETFILTER_TYPE_DNS)
		{
			result[i]->nfqParseCallback = ProcessRawPacketDNS;
			result[i]->redirectDataLen = NFQ_BUFFER_SIZE;
			//result[i]->redirectNetworkPacket = calloc(result[i]->redirectDataLen, 1);

			struct udphdr *udpHdr = (struct udphdr *)(result[i]->redirectNetworkPacket + IP4_HDRLEN);
			udpHdr->source = htobe16(53);
			
			TDNSHeader *dnsHdr = (TDNSHeader *)(result[i]->redirectNetworkPacket + IP4_HDRLEN + sizeof (struct udphdr));
			
			dnsHdr->qr = 1;
			dnsHdr->rd = 1;
			dnsHdr->ra = 1;
			
			//dnsHdr->flags[0] = 0x81;
			//dnsHdr->flags[1] = 0x80;
			dnsHdr->questionCount = htobe16(1);
			dnsHdr->answerCount = htobe16(1);
			
			struct addrinfo aiHints;
			memset(&aiHints, 0, sizeof(struct addrinfo));
			aiHints.ai_family = AF_INET;
			aiHints.ai_socktype = SOCK_STREAM;
			aiHints.ai_flags = AI_PASSIVE;
			aiHints.ai_protocol = 0;
			aiHints.ai_canonname = NULL;
			aiHints.ai_addr = NULL;
			aiHints.ai_next = NULL;
			check (getaddrinfo(redirectHost, NULL, &aiHints, &aiResult) == 0, ERROR_STR_NSERROR);
			struct sockaddr_in* saddr = (struct sockaddr_in*)aiResult->ai_addr;
			
			TDNSAnswer *dnsAns = (TDNSAnswer *)(result[i]->redirectNetworkPacket + IP4_HDRLEN + sizeof (struct udphdr) + sizeof (TDNSHeader));
			dnsAns->rdata = saddr->sin_addr.s_addr;
			dnsAns->name = 0x0cc0;
			dnsAns->type = 0x0100;
			dnsAns->addrClass = 0x0100;
			dnsAns->ttl = htobe32(3568);
			dnsAns->rdlength = htobe16(4);
			
			freeaddrinfo(aiResult);
			aiResult = NULL;
		}
		else if (threadType == NETFILTER_TYPE_HTTP)
		{
			result[i]->nfqParseCallback = ProcessRawPacketHTTP;
			result[i]->redirectDataLen = strlen(redirectHost) + sizeof (struct tcphdr) + IP4_HDRLEN + strlen (REDIRECT_PAYLOAD1) + strlen (REDIRECT_PAYLOAD2);
			memcpy(result[i]->redirectNetworkPacket + sizeof (struct tcphdr) + IP4_HDRLEN, REDIRECT_PAYLOAD1, strlen (REDIRECT_PAYLOAD1));
			memcpy(result[i]->redirectNetworkPacket + sizeof (struct tcphdr) + IP4_HDRLEN + strlen (REDIRECT_PAYLOAD1), redirectHost, strlen (redirectHost));
			memcpy(result[i]->redirectNetworkPacket + sizeof (struct tcphdr) + IP4_HDRLEN + strlen (REDIRECT_PAYLOAD1) + strlen(redirectHost), REDIRECT_PAYLOAD2, strlen (REDIRECT_PAYLOAD2));
		}

	}
	return result;
error:
	ClearNetfilterContext(result, count);
	if (result != NULL)
		free (result);
	if (aiResult != NULL)
		freeaddrinfo(aiResult);
	return NULL;
}


/*************************************************************************
* Останавливаем потоки фильтрации.                                       *
*************************************************************************/
void StopNetfilterProcessing(TNetfilterContext **context, size_t contextCount)
{
	if (context == NULL || contextCount == 0)
		return;
	flagMatrixReload = 1;
	for (size_t i = 0; i < contextCount; i++)
	{
		if (context[i]->threadId != 0)
		{
			pthread_kill (context[i]->threadId, SIGINT);
			pthread_cancel (context[i]->threadId);
			if (pthread_join (context[i]->threadId, NULL) != 0)
				log_err(ERROR_STR_PTHREAD);
			context[i]->threadId = 0;
		}
	}
}


/*************************************************************************
* Запускаем обработку трафика.                                           *
*************************************************************************/
void StartNetfilterProcessing (TNetfilterContext **context, size_t contextCount, pfHashTable *hashTable)
{
	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	if (contextCount == 0)
		return;
	
	check (context != NULL && hashTable != NULL && flagMatrixShutdown != 1 && flagMatrixReconfigure != 1, ERROR_STR_INVALIDINPUT);
	
	flagMatrixReload = 0;
	/*************************************************************************
	* Запускаем потоки обработки трафика.                                    *
	*************************************************************************/
	for (size_t i = 0; i < contextCount; i++)
	{
		check (context[i] != NULL, ERROR_STR_INVALIDINPUT);
		context[i]->hashTable = hashTable;
		if (context[i]->threadId == 0)
		{
			check (pthread_create (&(context[i]->threadId), NULL, NetfilterThread, context[i]) == 0, ERROR_STR_PTHREAD);
		}
	}
error:
	return;
}