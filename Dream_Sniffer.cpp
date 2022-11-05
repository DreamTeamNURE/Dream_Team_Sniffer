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
unsigned char Buffer[MAX_PACKET_SIZE]; // 64 Kb

using namespace std;

//Структура заголовка IP-пакета

typedef struct IPHeader {
	UCHAR   verlen;   // версия(4) и длина заголовка(4)
	UCHAR   tos;      // тип сервиса(DSCP(6), ECN(2)) 
	USHORT  length;   // длина всего пакета(16)
	USHORT  id;       // Идентификация(16)
	USHORT  offset;   // флаги(3) и смещения(13)
	UCHAR   ttl;      // время жизни пакета(8)
	UCHAR   protocol; // протокол(8)
	USHORT  xsum;     // контрольная сумма(16)
	ULONG   src;      // IP-адрес отправителя(32)
	ULONG   dest;     // IP-адрес назначения(32)

	//------------------------------------------------------------
	unsigned short* params;	    // параметры (до 320 бит)
	unsigned char* data;	    // данные (до 65535 - длина заголовка)
} IPHeader;

typedef struct IPPacket {
	unsigned char version;
	unsigned char IHL;
	unsigned char DSCP;
	unsigned char ECN;
	unsigned short Total_Length;
	unsigned short Data_Length;
	unsigned short Id;
	unsigned char Flags;
	unsigned char Fragment_offset;
	unsigned char TTL;
	unsigned char Protocol;
	unsigned short Hchecksum;
	unsigned int Src_IP;
	unsigned int Dest_IP;
	unsigned short* Options;
	unsigned char* Data;
	

} IPPakcet;

typedef struct TCPPacket {
	unsigned short Src_port;
	unsigned short Dest_port;
	unsigned int Sequence_number;
	unsigned int Acknowledgment_number;
	unsigned char* Options;

} TCPPacket;

typedef IPHeader FAR* LPIPHeader;
typedef IPPacket FAR* LPIPPacket;
typedef TCPPacket FAR* LPTCPPacket;

typedef struct Packet {
	char protocol;
	char src_ip;
	char src_port;
	char dest_ip;
	char dest_port;
};


SOCKET Create_Socket(int host_interface) {
	WSADATA     wsadata;   // Инициализация WinSock.
	SOCKET      s;         // Cлущающий сокет.
	char        name[128]; // Имя хоста (компьютера).
	HOSTENT*	h;       // Информация о хосте.
	SOCKADDR_IN sa;        // Адрес хоста
	unsigned long	flag = 1;  // Флаг PROMISC Вкл/выкл.

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
	memcpy(&sa.sin_addr.S_un.S_addr, h->h_addr_list[host_interface], h->h_length); // Выберите свой интерфейс

	if ((bind(s, (SOCKADDR*)&sa, sizeof(SOCKADDR))) == SOCKET_ERROR)
		printf("unable to bind() socket\n");

	// Включение promiscuous mode.
	ioctlsocket(s, SIO_RCVALL, &flag);

	return s;
}

void Stop_Socket(SOCKET s) {
	closesocket(s);
	WSACleanup();
}

IPPacket* Get_IP_packet(SOCKET s){
	IPHeader* hdr;
	IPPacket* ipp;
	int count = 0;
	count = recv(s, (char*)&Buffer, sizeof(Buffer), 0);
	if (count >= sizeof(IPHeader))
	{
		hdr = (LPIPHeader)malloc(MAX_PACKET_SIZE);
		ipp = (LPIPPacket)malloc(MAX_PACKET_SIZE);
		memcpy(hdr, &Buffer, MAX_PACKET_SIZE);

		char c;

		
		c = hdr->verlen << 4;
		ipp->IHL = int(c >> 4);
		ipp->version = int(hdr->verlen >> 4);

		c = hdr->tos << 6;
		ipp->ECN = c >> 6;
		ipp->DSCP = hdr->tos >> 2;
	
		ipp->Total_Length = hdr->length >> 8 + hdr->length << 8;
		int len = ipp->IHL - 5;

		ipp->Data_Length = ipp->Total_Length - 20 - len * 4;
		ipp->Id = hdr->id;

		ipp->Flags = hdr->offset >> 13;
		c = hdr->offset << 3;
		ipp->Fragment_offset = c >> 3;

		ipp->TTL = hdr->ttl;
		ipp->Protocol = int(hdr->protocol);
		ipp->Hchecksum = hdr->xsum;

		ipp->Src_IP = hdr->src;

		ipp->Dest_IP = hdr->dest;

		//memmove(ipp->Options, hdr->params, len * 4);
		memmove(ipp->Data, hdr->params + len * 4, ipp->Data_Length);
		
		
		return ipp;
	}
	else
		return 0;

}

TCPPacket* Get_TCP_packet(IPPacket* ipp) {
	TCPPacket* tcpp;
	tcpp = (LPTCPPacket)malloc(MAX_PACKET_SIZE);
	memcpy(tcpp, &ipp->Data, MAX_PACKET_SIZE);
	unsigned char lowbyte, hibyte;
	lowbyte = tcpp->Dest_port >> 8;
	hibyte = tcpp->Dest_port << 8;
	//tcpp->Dest_port = hibyte + lowbyte;
	//tcpp->Dest_port = tcpp->Dest_port >> 8 + tcpp->Dest_port << 8;
	return tcpp;
}

int main1()
{
	
	SOCKET      s;         // Cлущающий сокет.
	IN_ADDR		sa1;        //
	

	s = Create_Socket(2);

	if (s != SOCKET_ERROR) {
		// Бесконечный цикл приёма IP-пакетов.
		while (1) {
			IPPacket* ipp = Get_IP_packet(s);
			if (ipp != 0) {
				TCPPacket* tcpp = Get_TCP_packet(ipp);
				//cout << "Version " << int(ipp->version) << endl;
				//cout << "IHL " << int(ipp->IHL) << endl;
				//cout << "DSCP " << int(ipp->DSCP) << endl;
				//cout << "ECN " << int(ipp->ECN) << endl;
				//cout << "Total_Length " << ipp->Total_Length << endl;
				//cout << "Data_Length " << ipp->Data_Length << endl;
				//cout << "Id " << int(ipp->Id) << endl;
				//cout << "Flags " << int(ipp->Flags) << endl;
				//cout << "Fragment_offset " << int(ipp->Fragment_offset) << endl;
				//cout << "TTL " << int(ipp->TTL) << endl;
				sa1.s_addr = ipp->Src_IP;
				if (strcmp(inet_ntoa(sa1), "192.168.2.34") == 0) {
					cout << "Protocol " << int(ipp->Protocol) << " ";
					
					cout << "Src_IP " << inet_ntoa(sa1) << " ";

					cout << tcpp->Src_port << " ";

					sa1.s_addr = ipp->Dest_IP;
					cout << "Dest_IP " << inet_ntoa(sa1) << " ";

					cout << tcpp->Dest_port << " ";
					cout << endl;
				}
				//cout << "Hchecksum " << int(ipp->Hchecksum) << endl;
				
			}
		}
	}
	Stop_Socket(s);
	return 0;
}
}