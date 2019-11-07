/*************************************************************************
* Модуль обработки DNS пакетов.                                          *
*************************************************************************/


#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include "zapret-checker.h"

#define DNS_QUESTION_OFFSET (IP4_HDRLEN + sizeof (struct udphdr) + sizeof (TDNSHeader))
#define DNS_PACKET_SIZE (IP4_HDRLEN + sizeof (struct udphdr) + sizeof (TDNSHeader) + sizeof (TDNSAnswer))


/*************************************************************************
* Подготавливаем поддельный пакет.                                       *
*************************************************************************/
static void PrepareDNSAnsPacket (uint8_t *redirectNetworkPacket, uint32_t clientIP, uint16_t clientPort, uint32_t serverIP, uint16_t dnsId, uint8_t *questionData, size_t questionDataSize)
{
	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	if (redirectNetworkPacket == NULL || questionData == NULL)
		return;
	
	/*************************************************************************
	* Заполняем псевдо IPv4 заголовок для рассчета контрольной суммы.        *
	*************************************************************************/
	TPseudoHeader *psHdr = (TPseudoHeader *)(redirectNetworkPacket + PSEUDO_HDR_OFFSET);
	psHdr->srcAddr = serverIP;
	psHdr->dstAddr = clientIP;
	psHdr->length = htobe16(sizeof (struct udphdr) + sizeof (TDNSHeader) + questionDataSize + sizeof (TDNSAnswer));
	psHdr->proto = IPPROTO_UDP;
	psHdr->zero = 0;
	
	/*************************************************************************
	* Заполняем DNS заголовок.                                               *
	*************************************************************************/
	TDNSHeader *dnsHdr = (TDNSHeader *)(redirectNetworkPacket + IP4_HDRLEN + sizeof (struct udphdr));
	dnsHdr->id = dnsId;

	/*************************************************************************
	* Заполняем UDP заголовок.                                               *
	*************************************************************************/	
	struct udphdr *udpHdr = (struct udphdr *)(redirectNetworkPacket + IP4_HDRLEN);
	udpHdr->dest = clientPort;
	udpHdr->len = psHdr->length;
	udpHdr->check = 0;
	
	/*************************************************************************
	* Заполняем копируем блоки запроса и ответа в соответствующую позицию.   *
	*************************************************************************/
	memcpy(redirectNetworkPacket + DNS_QUESTION_OFFSET + questionDataSize, redirectNetworkPacket + DNS_QUESTION_OFFSET, sizeof (TDNSAnswer));
	memcpy(redirectNetworkPacket + DNS_QUESTION_OFFSET, questionData, questionDataSize);
	
	/*************************************************************************
	* Рассчитываем контрольную сумму UDP.                                    *
	*************************************************************************/
	uint16_t networkChecksum = checksum ((uint16_t *)(redirectNetworkPacket + PSEUDO_HDR_OFFSET), sizeof(TPseudoHeader) + sizeof (struct udphdr) + sizeof (TDNSHeader) + questionDataSize + sizeof (TDNSAnswer));
	udpHdr->check = networkChecksum;

	/*************************************************************************
	* Заполняем заголовок IPv4.                                              *
	*************************************************************************/	
	FillIPHeader ((struct iphdr *)(redirectNetworkPacket), clientIP, serverIP, IP4_HDRLEN + sizeof (struct udphdr) + sizeof (TDNSHeader) + questionDataSize + sizeof (TDNSAnswer), IPPROTO_UDP);
	
	return;
}


/*************************************************************************
* Сверяем запрос с реестром запрещённых сайтов.                          *
* Пример блока с DNS запросом:                                           *
* [3] w w w [7] e x a m p l e [3] c o m [0] [0x00] [0x01] [0x00] [0x01]  *
*                                            Запрос A     Класс IN       *
* Результат: размер блока блока с DNS запросом.                          *
*************************************************************************/
static bool CheckDomain(const pfHashTable *domainTable, uint8_t *questionData, uint16_t dataLen, size_t *questionDataSize)
{
	bool result = false;

	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	if (questionData == NULL || domainTable == NULL || dataLen == 0)
		return false;
	
	/*************************************************************************
	* Преобразуем DNS имя в нижний регистр.                                  *
	* questionDataSize инициализируем размером последних 5 байт запроса.     *
	*************************************************************************/
	*questionDataSize = 5;
	uint8_t len = *questionData;
	uint8_t *partDomain = questionData;
	while (len != 0)
	{
		if (len > 63)
			return false;
		*questionDataSize += len + 1;
		if (*questionDataSize > dataLen)
			return false;
		for (uint16_t i = 1; i <= len; i++)
			partDomain[i] = tolower (partDomain[i]);
		partDomain += len + 1;
		len = *partDomain;
	}
	partDomain++;
	uint16_t questionType = *((uint16_t *)partDomain);
	partDomain += 2;
	uint16_t questionClass = *((uint16_t *)partDomain);
	if (questionType != 0x0100 || questionClass != 0x0100)
		return false;
	
	/*************************************************************************
	* Проверяем не заблокировано ли доменное имя и вышестоящие домены.       *
	*************************************************************************/
	len = *questionData;
	partDomain = questionData;
	while (len != 0 && result == false)
	{
		result = pfHashCheckKey (domainTable, (char *)partDomain);
		partDomain += len + 1;
		len = *partDomain;
	}
	return result;
}

/*************************************************************************
* Обрабатываем IPV4 (UDP ( DNS )) пакет.                                 *
*************************************************************************/
bool ProcessRawPacketDNS (uint8_t *packet, size_t packetSize, TNetfilterContext *threadData,  uint8_t hwAddr[8])
{

	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	
	if (packet == NULL || threadData == NULL || threadData->redirectNetworkPacket == NULL || packetSize < IP4_HDRLEN)
		return false;
	
	struct iphdr *ipHdr = (struct iphdr *)(packet);

	/*************************************************************************
	* Поддерживается только IPV4.                                            *
	*************************************************************************/	
	if (ipHdr->version != 4)
		return false;

	/*************************************************************************
	* Поддерживается только UDP, пакет должен был цельным.                   *
	*************************************************************************/	
	uint16_t totalLen = be16toh(ipHdr->tot_len);
	if (ipHdr->protocol != IPPROTO_UDP || packetSize < totalLen || totalLen < sizeof (struct udphdr))
		return false;

	/*************************************************************************
	* Находим начало UDP.                                                    *
	*************************************************************************/	
	uint16_t iphLen = (ipHdr->ihl << 2);
	packet += iphLen;
	
	struct udphdr *udpHdr = (struct udphdr *)(packet);
	
	/*************************************************************************
	* Находим начало DNS.                                                    *
	*************************************************************************/		
	packet += sizeof (struct udphdr);
	
	/*************************************************************************
	* Если длина данных меньше чем заголовок DNS, выходим.                   *
	*************************************************************************/	
	uint16_t dataLen = be16toh(udpHdr->len);
	if (dataLen <= sizeof (TDNSHeader))
		return false;

	dataLen -= sizeof (TDNSHeader);
	TDNSHeader *dnsHdr = (TDNSHeader *)(packet);
	
	uint16_t questionCount = be16toh(dnsHdr->questionCount);
	
	/*************************************************************************
	* Если DNS пакет не содержит простой запрос без фрагментации, выходим.   *
	*************************************************************************/	
	if (questionCount == 0 || dnsHdr->qr != 0 || dnsHdr->opcode != 0 || dnsHdr->tc != 0)
		return false;

	packet += sizeof (TDNSHeader);
	
	bool result = false;
	size_t questionDataSize = 0;
		
	/*************************************************************************
	* Если запрос запрещён, подделываем ответ.                               *
	*************************************************************************/	
	if (CheckDomain (threadData->hashTable, packet, dataLen, &questionDataSize))
	{
		struct sockaddr_ll sin;
		memset (&sin, 0, sizeof (struct sockaddr_ll));
		sin.sll_family = AF_PACKET;
		sin.sll_protocol = htons(ETH_P_IP);
		sin.sll_ifindex = threadData->ifIndex;
		sin.sll_pkttype = PACKET_OUTGOING;
		sin.sll_halen = ETH_ALEN;
		memcpy(&sin.sll_addr, hwAddr, ETH_ALEN);
		
		PrepareDNSAnsPacket (threadData->redirectNetworkPacket, ipHdr->saddr, udpHdr->source, ipHdr->daddr, dnsHdr->id, packet, questionDataSize);
		sendto (threadData->redirectSocket, threadData->redirectNetworkPacket, DNS_PACKET_SIZE + questionDataSize, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr_ll));
		memcpy(threadData->redirectNetworkPacket + DNS_QUESTION_OFFSET, threadData->redirectNetworkPacket + DNS_QUESTION_OFFSET + questionDataSize, sizeof (TDNSAnswer));
		result = true;
	}

	return result;
}