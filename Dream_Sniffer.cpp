#pragma comment(lib, "ws2_32.lib")
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS


#include <iostream>
#include <winsock2.h>


#define MAX_PACKET_SIZE    0x10000
#define SIO_RCVALL         0x98000001

using namespace std;


// Headers

struct IPv4Header {
	unsigned char IHL : 4;				// Internet Header Length (4 bits)
	unsigned char version : 4;			// IP protocol (4 bits)
	unsigned char ECN : 2;				// Explicit Congestion Notification (2 bits)
	unsigned char DSCP : 6;				// Differentiated Services Code Point (6 bits)
	unsigned short total_length;		// Total Length (16 bits)
	unsigned short id;					// Identification (16 bits)
	unsigned char fragment_offset1 : 5; // Fragment offset (5 bits)
	unsigned char more_fragment : 1;	// Flags (More Fragments) (1 bit)
	unsigned char dont_fragment : 1;	// Flags (Don't Fragment) (1 bit)
	unsigned char reserved_zero : 1;	// Flags (Reserved) (1 bit)
	unsigned char fragment_offset2;		// Fragment offset (8 bits)
	unsigned char TTL;					// Time to live (8 bits)
	unsigned char protocol;				// Protocol (8 bits)
	unsigned short Hchecksum;			// Header checksum (16 bits)
	unsigned int src_IP;				// Source address (32 bits)
	unsigned int dest_IP;				// Destination address (32 bits)
	//unsigned short* Options;			// Options
};

struct TCPHeader {
	unsigned short src_port;			// Source port (16 bits)
	unsigned short dest_port;			// Destination port (16 bits)
	unsigned int sequence;				// Sequence number (32 bits)
	unsigned int acknowledge;			// Acknowledgement number (32 bits)

	unsigned char ns : 1;				// Nonce Sum Flag Added in RFC 3540. (1 bit)
	unsigned char reserved_part : 3;	// according to rfc (3 bits)
	unsigned char data_offset : 4;		// The number of 32-bit words in the TCP header (4 bits)
	unsigned char fin : 1;				// Finish Flag (1 bit)
	unsigned char syn : 1;				// Synchronise Flag (1 bit)
	unsigned char rst : 1;				// Reset Flag (1 bit)
	unsigned char psh : 1;				// Push Flag (1 bit)
	unsigned char ack : 1;				// Acknowledgement Flag (1 bit)
	unsigned char urg : 1;				// Urgent Flag (1 bit)

	unsigned char ecn : 1;				// ECN-Echo Flag (1 bit)
	unsigned char cwr : 1;				// Congestion Window Reduced Flag (1 bit)
	unsigned short window;				// Window (16 bits)
	unsigned short checksum;			// Checksum (16 bits)
	unsigned short urgent_pointer;		// Urgent pointer (16 bits)
	//unsigned short* Options;			// Options
};

struct UDPHeader {
	unsigned short src_port;			// Source port (16 bits)
	unsigned short dest_port;			// Destination port (16 bits)
	unsigned short length;				// Udp packet length (16 bits)
	unsigned short checksum;			// Udp checksum (optional) (16 bits)
};

// Socket


void PrintInterfaceList() {

	SOCKET_ADDRESS_LIST* slist = NULL;
	SOCKET s;
	char buf[2048];
	DWORD dwBytesRet;
	int ret, i;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

	if (s == SOCKET_ERROR) {
		printf("socket() failed with error code %d\n", WSAGetLastError());
		return;
	}

	ret = WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, buf, 2048, &dwBytesRet, NULL, NULL);
	if (ret == SOCKET_ERROR) {
		printf("WSAIoctl(SIO_ADDRESS_LIST_QUERY) failed with error code %d\n", WSAGetLastError());
		return;
	}

	slist = (SOCKET_ADDRESS_LIST*)buf;

	for (i = 0; i < slist->iAddressCount; i++) {
		printf("          %d) %s\n", i + 1, inet_ntoa(((SOCKADDR_IN*)slist->Address[i].lpSockaddr)->sin_addr));
	}

	if (closesocket(s) != 0)
		printf("closesocket() failed with error code %d\n", WSAGetLastError());

	return;

}

int GetInterface(SOCKET s, SOCKADDR_IN* ifx, int num)

{
	SOCKET_ADDRESS_LIST* slist = NULL;
	char                 buf[2048];
	DWORD                dwBytesRet;
	int                  ret;

	ret = WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, buf, 2048, &dwBytesRet, NULL, NULL);
	if (ret == SOCKET_ERROR) {
		printf("WSAIoctl(SIO_ADDRESS_LIST_QUERY) failed with error code %d\n", WSAGetLastError());
		return -1;
	}

	slist = (SOCKET_ADDRESS_LIST*)buf;
	if (num >= slist->iAddressCount)
		return -1;
	ifx->sin_addr.s_addr = ((SOCKADDR_IN*)slist->Address[num].lpSockaddr)->sin_addr.s_addr;
	return 0;
}

SOCKET CreateSocket() {
	WSADATA     wsadata;		// init WinSock.
	SOCKET      s;				// listening socket.
	int host_interface;			// Host interface ID
	SOCKADDR_IN if0;			// Host IP address (Host interface).
	unsigned long	flag = 1;	// Flag PROMISC ON/OFF.

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
		printf("WSAStartup() failed with error % d\n", WSAGetLastError());


	if ((s = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET) {
		printf("WSASocket() for raw socket failed with error code %d\n", WSAGetLastError());
		printf("RUN THIS PROGRAM WITH ADMINISTRATIVE PRIVILEGES!!!\n");
	}
	printf("Interface list:\n");
	PrintInterfaceList();

	printf("Enter host interface index: ");
	cin >> host_interface;

	if (GetInterface(s, &if0, host_interface - 1) != 0)
		printf("Unable to obtain an interface!\n");

	printf("Binding to if: %s\n", inet_ntoa(if0.sin_addr));


	if0.sin_family = AF_INET;
	if0.sin_port = htons(0);

	if ((bind(s, (SOCKADDR*)&if0, sizeof(if0))) == SOCKET_ERROR)
		printf("bind() failed with error code %d\n", WSAGetLastError());

	// Turn ON promiscuous mode.
	if (ioctlsocket(s, SIO_RCVALL, &flag) == SOCKET_ERROR)
		printf("WSAIotcl(%ul) failed with error code %d\n", SIO_RCVALL, WSAGetLastError());

	if (s != SOCKET_ERROR)
		printf("Socket has created successfuly\n");
	else
		s = NULL;

	return s;
}

void DelSocket(SOCKET s) {
	if (closesocket(s) != 0)
		printf("closesocket() failed with error code %d\n", WSAGetLastError());

	if (WSACleanup() != 0)
		printf("WSACleanup() failed with error code %d\n", WSAGetLastError());
}

unsigned char* Get_Buffer(SOCKET s) {
	unsigned char Buffer[MAX_PACKET_SIZE]; // Buffer for income data (64 Kb)
	int count = recv(s, (char*)&Buffer, sizeof(Buffer), 0);
	if (count < sizeof(IPv4Header))
		Buffer[0] = NULL;

	return Buffer;
}

// Process headers

TCPHeader* Get_TCP_header(unsigned char* Buffer) {
	IPv4Header* iphdr = (IPv4Header*)Buffer;
	TCPHeader* tcphdr = (TCPHeader*)(Buffer + iphdr->IHL * 4);
	return tcphdr;
}

UDPHeader* Get_UDP_header(unsigned char* Buffer) {
	IPv4Header* iphdr = (IPv4Header*)Buffer;
	UDPHeader* udphdr = (UDPHeader*)(Buffer + iphdr->IHL * 4);
	return udphdr;
}

IPv4Header* Get_IPv4_header(unsigned char* Buffer) {
	IPv4Header* iphdr = (IPv4Header*)Buffer;
	return iphdr;
}

//

struct Packet {
	unsigned int src_IP;
	unsigned short src_port;
	unsigned int dest_IP;
	unsigned short dest_port;
	unsigned char protocol_int;
	char protocol_str[6];
	unsigned short total_length;
	unsigned char TTL;
};

char* getStrIP(unsigned int ip) {
	IN_ADDR	s;
	s.s_addr = ip;
	return inet_ntoa(s);

}

void printPacket(Packet* pack) {
	cout << "Packet: " << getStrIP(pack->src_IP);
	if(pack->src_port)
		cout << ": " << htons(pack->src_port);
	cout << "\t->\t" << getStrIP(pack->dest_IP);
	if (pack->dest_port)
		cout << ": " << htons(pack->dest_port);
	if (strcmp(pack->protocol_str, "Other") !=0)
		cout << ",\t" << pack->protocol_str;
	else
		cout << ",\tprotocol(" << int(pack->protocol_int) << ")";
	cout << ",\tlength(" << pack->total_length;
	cout << "),\tTTL(" << int(pack->TTL) << ");\n";
}

Packet* getPacket(unsigned char* Buffer) {
	Packet* pack = new Packet;

	IPv4Header* iphdr = Get_IPv4_header(Buffer);
	TCPHeader* tcphdr;
	UDPHeader* udphdr;

	pack->src_IP = iphdr->src_IP;
	pack->dest_IP = iphdr->dest_IP;
	pack->protocol_int = iphdr->protocol;
	pack->total_length = (iphdr->total_length << 8) + (iphdr->total_length >> 8);
	pack->TTL = iphdr->TTL;

	switch (iphdr->protocol)
	{
	case IPPROTO_TCP: //TCP protocol (6)
		tcphdr = Get_TCP_header(Buffer);
		strcpy(pack->protocol_str, "TCP");
		pack->src_port = tcphdr->src_port;
		pack->dest_port = tcphdr->dest_port;
		break;

	case IPPROTO_UDP: //UDP protocol (17)
		udphdr = Get_UDP_header(Buffer);
		strcpy(pack->protocol_str, "UDP");
		pack->src_port = udphdr->src_port;
		pack->dest_port = udphdr->dest_port;
		break;

	default:
		strcpy(pack->protocol_str, "Other");
		pack->src_port = NULL;
		pack->dest_port = NULL;
		break;
	}

	return pack;
}

char Src_IP[16], Dest_IP[16], Proto[5];


bool show_packet(Packet* pack) {
	if (strcmp(Src_IP, getStrIP(pack->src_IP)) != 0 && strcmp(Src_IP, "-") != 0)
		return false;
	if (strcmp(Dest_IP, getStrIP(pack->dest_IP)) != 0 && strcmp(Dest_IP, "-") != 0)
		return false;
	if (strcmp(Proto, pack->protocol_str) != 0 && strcmp(Proto, "-") != 0)
		return false;
	return true;
}

//Packet* get

int main() {
	SOCKET s;
	unsigned char* Buffer;
	
	s = CreateSocket();

	cout << "Enter filter:\n";
	cout << "Enter Source IP or - : ";
	cin >> Src_IP;
	cout << "Enter Destination IP or - : ";
	cin >> Dest_IP;
	cout << "Enter Protocol (TCP/UDP/Other) or - : ";
	cin >> Proto;

	if (s)
		while (true) {
			Buffer = Get_Buffer(s);
			if (Buffer[0]) {
				Packet* pack = getPacket(Buffer);
				if (show_packet(pack))
					printPacket(pack);
			}

		}

	DelSocket(s);
	return 0;
}
