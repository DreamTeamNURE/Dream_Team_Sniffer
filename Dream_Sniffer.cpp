#pragma comment(lib, "ws2_32.lib")

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS


#include <conio.h>
#include <stdlib.h>
#include <iostream>
#include <stdio.h>
#include <winsock2.h>

#define MAX_PACKET_SIZE    0x10000
#define SIO_RCVALL         0x98000001
// Буфер для приёма данных
BYTE Buffer[MAX_PACKET_SIZE]; // 64 Kb

using namespace std;

//Структура заголовка IP-пакета

typedef struct IPHeader {
	UCHAR   iph_verlen;   // версия и длина заголовка
	UCHAR   iph_tos;      // тип сервиса
	USHORT  iph_length;   // длина всего пакета
	USHORT  iph_id;       // Идентификация
	USHORT  iph_offset;   // флаги и смещения
	UCHAR   iph_ttl;      // время жизни пакета
	UCHAR   iph_protocol; // протокол
	USHORT  iph_xsum;     // контрольная сумма
	ULONG   iph_src;      // IP-адрес отправителя
	ULONG   iph_dest;     // IP-адрес назначения

	//------------------------------------------------------------
	unsigned short* params;	    // параметры (до 320 бит)
	unsigned char* data;	    // данные (до 65535 - длина заголовка)
} IPHeader;

typedef IPHeader FAR* LPIPHeader;


char src[10];
char dest[10];
char ds[15];
char dso[5];
unsigned short lowbyte;
unsigned short hibyte;

int main()
{
	WSADATA     wsadata;   // Инициализация WinSock.
	SOCKET      s;         // Cлущающий сокет.
	char        name[128]; // Имя хоста (компьютера).
	HOSTENT* h;       // Информация о хосте.
	SOCKADDR_IN sa;        // Адрес хоста
	IN_ADDR sa1;        //
	unsigned long        flag = 1;  // Флаг PROMISC Вкл/выкл.

	// инициализация

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
		printf("WSAStartup failed\n");

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET)
		printf("unable to open raw socket\nRUN THIS PROGRAM WITH ADMINISTRATIVE PRIVILEGES!!!\n");

	// use default interface
	if ((gethostname(name, 1024)) == SOCKET_ERROR)
		printf("unable to gethostname\n");

	if ((h = gethostbyname(name)) == NULL)
		printf("unable to gethostbyname\n");

	sa.sin_family = AF_INET;
	sa.sin_port = htons(6000);
	memcpy(&sa.sin_addr.S_un.S_addr, h->h_addr_list[2], h->h_length);

	if ((bind(s, (SOCKADDR*)&sa, sizeof(SOCKADDR))) == SOCKET_ERROR)
		printf("unable to bind() socket\n");
	
	
	

	// Включение promiscuous mode.
	ioctlsocket(s, SIO_RCVALL, &flag);
	// Бесконечный цикл приёма IP-пакетов.
	while (1)
	{
		int count;
		count = recv(s, (char*)&Buffer[0], sizeof(Buffer), 0);;
		// обработка IP-пакета
		

		if (count >= sizeof(IPHeader))
		{
			IPHeader* hdr = (LPIPHeader)malloc(MAX_PACKET_SIZE);
			memcpy(hdr, Buffer, MAX_PACKET_SIZE);
			//Начинаем разбор пакета...
			printf("Packet: ");
			// Преобразуем в понятный вид адрес отправителя.
			printf("From ");
			sa1.s_addr = hdr->iph_src;
			printf(inet_ntoa(sa1));

			// Преобразуем в понятный вид адрес получателя.
			printf(" To ");
			sa1.s_addr = hdr->iph_dest;
			printf(inet_ntoa(sa1));

			// Вычисляем протокол. Полный список этих констант
			// содержится в файле winsock2.h
			printf(" Prot: ");
			
			if (hdr->iph_protocol == IPPROTO_TCP) printf("TCP "); else
				if (hdr->iph_protocol == IPPROTO_UDP) printf("UDP "); else {
					printf("UNKNOWN ");
					cout << int(hdr->iph_protocol) << " ";
				}
					


			// Вычисляем размер. Так как в сети принят прямой порядок
			// байтов, а не обратный, то прийдётся поменять байты местами.
			printf("Size: ");
			lowbyte = hdr->iph_length >> 8;
			hibyte = hdr->iph_length << 8;
			hibyte = hibyte + lowbyte;
			printf("%s", _itoa(hibyte, ds, 10));

			// Вычисляем время жизни пакета.
			printf("%s", _itoa(hibyte, ds, 10));
			printf(" TTL:%s", _itoa(hdr->iph_ttl, ds, 10));

			cout << " " << hdr->iph_offset << " " << hdr->iph_id;
			cout << " " << hdr->params << " " << hdr->data;

			cout << endl;
		}
	}

	closesocket(s);
	WSACleanup();
}