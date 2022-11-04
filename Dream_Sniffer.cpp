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
// ����� ��� ����� ������
BYTE Buffer[MAX_PACKET_SIZE]; // 64 Kb

using namespace std;

//��������� ��������� IP-������

typedef struct IPHeader {
	UCHAR   iph_verlen;   // ������ � ����� ���������
	UCHAR   iph_tos;      // ��� �������
	USHORT  iph_length;   // ����� ����� ������
	USHORT  iph_id;       // �������������
	USHORT  iph_offset;   // ����� � ��������
	UCHAR   iph_ttl;      // ����� ����� ������
	UCHAR   iph_protocol; // ��������
	USHORT  iph_xsum;     // ����������� �����
	ULONG   iph_src;      // IP-����� �����������
	ULONG   iph_dest;     // IP-����� ����������

	//------------------------------------------------------------
	unsigned short* params;	    // ��������� (�� 320 ���)
	unsigned char* data;	    // ������ (�� 65535 - ����� ���������)
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
	WSADATA     wsadata;   // ������������� WinSock.
	SOCKET      s;         // C�������� �����.
	char        name[128]; // ��� ����� (����������).
	HOSTENT* h;       // ���������� � �����.
	SOCKADDR_IN sa;        // ����� �����
	IN_ADDR sa1;        //
	unsigned long        flag = 1;  // ���� PROMISC ���/����.

	// �������������

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
	
	
	

	// ��������� promiscuous mode.
	ioctlsocket(s, SIO_RCVALL, &flag);
	// ����������� ���� ����� IP-�������.
	while (1)
	{
		int count;
		count = recv(s, (char*)&Buffer[0], sizeof(Buffer), 0);;
		// ��������� IP-������
		

		if (count >= sizeof(IPHeader))
		{
			IPHeader* hdr = (LPIPHeader)malloc(MAX_PACKET_SIZE);
			memcpy(hdr, Buffer, MAX_PACKET_SIZE);
			//�������� ������ ������...
			printf("Packet: ");
			// ����������� � �������� ��� ����� �����������.
			printf("From ");
			sa1.s_addr = hdr->iph_src;
			printf(inet_ntoa(sa1));

			// ����������� � �������� ��� ����� ����������.
			printf(" To ");
			sa1.s_addr = hdr->iph_dest;
			printf(inet_ntoa(sa1));

			// ��������� ��������. ������ ������ ���� ��������
			// ���������� � ����� winsock2.h
			printf(" Prot: ");
			
			if (hdr->iph_protocol == IPPROTO_TCP) printf("TCP "); else
				if (hdr->iph_protocol == IPPROTO_UDP) printf("UDP "); else {
					printf("UNKNOWN ");
					cout << int(hdr->iph_protocol) << " ";
				}
					


			// ��������� ������. ��� ��� � ���� ������ ������ �������
			// ������, � �� ��������, �� �������� �������� ����� �������.
			printf("Size: ");
			lowbyte = hdr->iph_length >> 8;
			hibyte = hdr->iph_length << 8;
			hibyte = hibyte + lowbyte;
			printf("%s", _itoa(hibyte, ds, 10));

			// ��������� ����� ����� ������.
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