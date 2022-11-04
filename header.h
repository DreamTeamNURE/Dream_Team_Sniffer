#pragma comment(lib, "ws2_32.lib")

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <time.h>


/* packet header structures */
#pragma pack(push, 1)
struct iphdr {
	unsigned char ihl : 4;
	unsigned char ver : 4;

	unsigned char tos;
	unsigned short totlen;
	unsigned short id;
	unsigned short frag_and_flags;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int src;
	unsigned int dst;
};

struct tcphdr {
	unsigned short sport;
	unsigned short dport;
	unsigned int   seq;
	unsigned int   acknum;
	unsigned char  unused : 4;
	unsigned char  tcphl : 4;
	unsigned char  Flags;
	unsigned short Windows;
	unsigned short cksum;
	unsigned short UrgPointer;
};

#pragma pack(pop)

#define HOSTNAME_LEN 1024
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define PAKSIZE 65536

void init_net(void);
void die(const char*);
void process_pak(char*, int);
void bind_to_interface(int);
void WriteData(const char*);

/* G L O B A L S */
SOCKET s0k;
short promiscuous = 1;