#pragma comment(lib, "ws2_32.lib")
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <winsock2.h>


#define MAX_PACKET_SIZE    0x10000
#define SIO_RCVALL         0x98000001

using namespace std;

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

struct UDPHeader{
	unsigned short src_port;			// Source port (16 bits)
	unsigned short dest_port;			// Destination port (16 bits)
	unsigned short length;				// Udp packet length (16 bits)
	unsigned short checksum;			// Udp checksum (optional) (16 bits)
};

struct Packet {
	char* src_IP;
	int src_port;
	char* dest_IP;
	int dest_port;
	string protocol;
	int total_length;
	int TTL;
};

char* getStrIP(unsigned int ip) {
	IN_ADDR	s;
	s.s_addr = ip;
	return inet_ntoa(s);

}

void print_Packet(Packet* pack) {
	if (!pack->src_IP) {
		cout << "Proto: " << pack->protocol << endl;
		return;
	}
	cout << "Src_IP: " << pack->src_IP << " ";
	cout << ": " << pack->src_port << " ";
	cout << "Dest_IP: " << pack->dest_IP << " ";
	cout << ": " << pack->dest_port << " ";
	cout << "Proto: " << pack->protocol << " ";
	cout << "Total length: " << pack->total_length << " ";
	cout << "TTL: " << pack->TTL << endl;
}

SOCKET CreateSocket(int host_interface) {
	WSADATA     wsadata;	// init WinSock.
	SOCKET      s;			// listening socket.
	char        h_name[128];	// Host name (Computer name).
	HOSTENT* h_info;				// Host information.
	SOCKADDR_IN sa;			// Host IP address.
	unsigned long	flag = 1;	// Flag PROMISC ON/OFF.

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		printf("WSAStartup failed with error % d\n", WSAGetLastError());
	}
	
	if ((gethostname(h_name, 1024)) == SOCKET_ERROR)
		printf("unable to gethostname\n");

	if ((h_info = gethostbyname(h_name)) == NULL)
		printf("unable to gethostbyname\n");
	
	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET)
		printf("unable to open raw socket\nRUN THIS PROGRAM WITH ADMINISTRATIVE PRIVILEGES!!!\n");
	
	sa.sin_family = AF_INET;
	//sa.sin_addr.S_un.S_addr = INADDR_ANY;
	memcpy(&sa.sin_addr.S_un.S_addr, h_info->h_addr_list[host_interface], h_info->h_length); // Choose your interface

	if ((bind(s, (SOCKADDR*)&sa, sizeof(SOCKADDR))) == SOCKET_ERROR)
		printf("unable to bind() socket\n");

	// Turn ON promiscuous mode.
	ioctlsocket(s, SIO_RCVALL, &flag);	
	printf("Socket has created successfuly\n");
	return s;
}

void DelSocket(SOCKET s) {
	closesocket(s);
	WSACleanup();
}

unsigned char* Get_Buffer(SOCKET s) {
	unsigned char Buffer[MAX_PACKET_SIZE]; // Buffer for income data (64 Kb)
	int count = recv(s, (char*)&Buffer, sizeof(Buffer), 0);
	if (count <= 0)
		Buffer[0] = NULL;
		
	return Buffer;

}

Packet* Get_TCP_header(unsigned char* Buffer) {
	IPv4Header* iphdr = (IPv4Header*)(Buffer);
	TCPHeader* tcphdr = (TCPHeader*)(Buffer + iphdr->IHL * 4);

	Packet* pack = new Packet;
	pack->src_IP = getStrIP(iphdr->src_IP);
	pack->src_port = (tcphdr->src_port);
	pack->dest_IP = getStrIP(iphdr->dest_IP);
	pack->dest_port = ntohs(tcphdr->dest_port);
	pack->protocol = "TCP";
	pack->total_length = int(iphdr->total_length);
	pack->TTL = int(iphdr->TTL);
	return pack;
}

Packet* Get_UDP_header(unsigned char* Buffer) {
	IPv4Header* iphdr = (IPv4Header*)(Buffer);
	UDPHeader* udphdr = (UDPHeader*)(Buffer + iphdr->IHL * 4);

	Packet* pack = new Packet;
	pack->src_IP = getStrIP(iphdr->src_IP);
	pack->src_port = ntohs(udphdr->src_port);
	pack->dest_IP = getStrIP(iphdr->dest_IP);
	pack->dest_port = ntohs(udphdr->dest_port);
	pack->protocol = "UDP";
	pack->total_length = int(iphdr->total_length);
	pack->TTL = int(iphdr->TTL);
	return pack;
}

Packet* Get_IPv4_header(unsigned char* Buffer) {
	IPv4Header* iphdr = (IPv4Header*)(Buffer);
	/*Packet* pack = new Packet;
	pack->src_IP = getstrIP(iphdr->src_IP);
	pack->dest_IP = getstrIP(iphdr->dest_IP);
	pack->protocol = int(iphdr->protocol);
	pack->total_length = int(iphdr->total_length);
	pack->TTL = int(iphdr->TTL);
	print_Packet(pack);*/
	Packet* pack;

	switch (iphdr->protocol)
	{
	case 6: //TCP Protocol
		pack = Get_TCP_header(Buffer);
		break;

	case 17: //UDP Protocol
		pack = Get_UDP_header(Buffer);
		break;
	default:
		pack = new Packet();
		pack->protocol = iphdr->protocol;
		pack->src_IP = NULL;
		break;
	}
	return pack;
}

int main() {
	SOCKET s;
	unsigned char* Buffer;
	s = CreateSocket(2);
	while (true) {
		Buffer = Get_Buffer(s);
		if (Buffer[0]) {
			Packet* pack = Get_IPv4_header(Buffer);
			//if (strcmp(pack->src_IP, "192.168.2.34") == 0)
				print_Packet(pack);
		}
			
	}
	
	DelSocket(s);
	return 0;
}