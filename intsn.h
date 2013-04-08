/* 04/08/2013.
 * GNU LICENSE etc. etc.
 *
 * intsn_C - raw packet capture tool which can handle multiple interfaces & filters, plus a interactive interface
 *
 * ./intsn eth0,"icmp" tun0,"udp and port 1194" tun1,udp any,"host 1.1.1.1" eth1 eth2
 *
 * etc. For a hep menu, type 'h' once it starts
 *
 * This was a 3 day project which lasted 4 days. If someones likes this tool, I can contrib more to it.
 *
 * -- adarqui (adarq.org / github.com/adarqui)
 */

#ifndef INTSN_H
#define INTSN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <event.h>
#include <pcap.h>
#include <asm/byteorder.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>

#define BUFSZ		65535
#define MAX_LAYERS	6
#define MAX_PATH_SZ	255
#define MAX_BUF_SZ	255
#define MAX_VIEWS	5

#include "intsn_parse.h"
#include "intsn_misc.h"
#include "intsn_net.h"
#include "intsn_services.h"

enum {
	VIEW_0 = 0,
	VIEW_1,
	VIEW_2,
};

typedef struct service {
	char * name;
} service_t;

typedef struct view {
	void (*fn)(void *);
} view_t;

typedef struct options {
	unsigned char d; /* debug */
	unsigned char t; /* timestamp */
	unsigned char c; /* count */
	unsigned char e; /* ethernet frame */
	unsigned char p; /* path */
	unsigned char s; /* service translation */
	unsigned char i; /* interface verbosity */
	unsigned char E; /* toggles everything */

	/* terminal options */
	unsigned char pause;
	unsigned char view;
	view_t views[MAX_VIEWS+1];
} options_t;

typedef struct route {
	char * intf;
	struct in_addr addr_dest;
	struct in_addr addr_gw;
	struct in_addr addr_mask;
	struct in_addr addr_end;
	char * str_dest;
	char * str_gw;
	char * str_mask;
	char * str_end;
	struct route * next;
} route_t;

typedef struct datalink {
	int val;
	const char * name;
	const char * desc;
	plink_t plink;
} datalink_t;

typedef struct interface {
	char * name;
	char * filter;
	int fd;
	datalink_t datalink;
	int promisc;
	int to_ms;
	int count;
	unsigned char vlan;

	bpf_u_int32 net;
	bpf_u_int32 mask;

	struct bpf_program fp;

	struct event ev;

} interface_t;

typedef struct pkt {
	const unsigned char * raw;
	unsigned int off;
	struct pcap_pkthdr * phdr;
} pkt_t;


enum {
	INFO_PREFIX = 0,
	INFO_PATH,
	INFO_SRC,
	INFO_DST,
	INFO_DATA,
	INFO_DESC,
	INFO_INTF,
};

typedef struct info_layer {
	char data[MAX_PATH_SZ+1];
} info_layer_t;

typedef struct info {
	info_layer_t prefix;
	info_layer_t intf;
	info_layer_t path;
	int src_idx;
	info_layer_t src[MAX_LAYERS+1];
	int dst_idx;
	info_layer_t dst[MAX_LAYERS+1];
	int data_idx;
	info_layer_t data[MAX_LAYERS+1];
	int desc_idx;
	info_layer_t desc[MAX_LAYERS+1];
} info_t;

typedef struct pcap_obj {
	pcap_t * pcap;
	struct pcap_obj * next;
	interface_t intf;
	pkt_t pkt;
	info_t info;
} pobj_t;

typedef struct term {
	struct termios o; /* orig */
	struct termios n; /* new  */
	struct event ev;
} term_t;

typedef struct base {
	options_t opts;
	struct event_base * evb;
	pobj_t * head;
	route_t * routes;
	term_t term;
	service_t * services;
	int services_cnt;
} base_t;

base_t base;


/* intsn_net.c */
in_addr_t net_netmask(int);
in_addr_t net_network(in_addr_t, int);


/* intsn.c */
void stdin_handler(int, short, void *);
void stdin_handle_char(int);

void pobj_datalink(pobj_t *);
void pobj_handler(int, short, void *);
pobj_t * pobj_create(char *, char *, int, int, int);
pobj_t * pobj_create_exact(char *, char *, int, int, int);
void pobj_list(void);
void pobj_stats(void);

void pobj_layers_add(pobj_t *, int, char *, ...);
void pobj_layers_print_fill(void);
void pobj_layers_print(pobj_t *);
void pobj_layers_print_pre(pobj_t *);
void pobj_layers_print_0(pobj_t *);
void pobj_layers_print_1(pobj_t *);
void pobj_layers_print_null(pobj_t *);
void pobj_layers_zro(pobj_t *);

void routes_parse(void);
route_t * routes_insert(char *, char *, char *, char *);

void help(char * str);
void error(char * str);
void noncrit(char * str);

int parse_argv(int argc, char ** argv);
void init(void);
void fini_sighandler(int);
void fini(void);
void init_term(void);
void fini_term(void);
int main(int argc, char ** argv, char ** envp);

/* function ptr's */
int (*debug)(const char *format, ...);
int printf_null(const char *format, ...);

#endif
