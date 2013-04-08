/* 04/08/2013
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

#include "intsn.h"


void help(char * str) {
	if(!str) {
		str = "FAIL!";
	}

	printf(
		"intsn failed: %s\n"
		"\tUsage: ./intsn eth0,\"filter_string\" tun0,\"filter_string\" any,\"filter_string\" etc.\n\n"
		, str
	);

	printf(
		"Options: Command line \"-options\" or interctive commands when the sniffer is running.\n"
	);

	stdin_handle_char('h');

	exit(0);	
}

void error(char * str) {
	puts(str);
	exit(1);
}

void noncrit(char * str) {
	printf("# NONCRITICAL_ERROR: %s\n", str);
	return;
}

void pobj_layers_add(pobj_t *pobj, int type, char * fmt, ...) {
    va_list ap;
    int n;
    char tmp_buf[MAX_BUF_SZ];

	char * buf_ptr;
	int buf_size;

	if(!pobj || !fmt) return;

	switch(type) {
		case INFO_PREFIX: {
			buf_ptr		= pobj->info.prefix.data;
			buf_size	= sizeof(pobj->info.prefix.data)-1;
			break;
		}
		case INFO_PATH: {
			if(!base.opts.p) return;
			buf_ptr		= pobj->info.path.data;
			buf_size	= sizeof(pobj->info.path.data)-1;
			break;
		}
		case INFO_SRC: {
			if(pobj->info.src_idx + 1 > MAX_LAYERS) return;
			buf_ptr		= pobj->info.src[pobj->info.src_idx].data;
			buf_size	= sizeof(pobj->info.src[pobj->info.src_idx].data)-1;
			pobj->info.src_idx++;
			break;
		}
		case INFO_DST: {
			if(pobj->info.dst_idx + 1 > MAX_LAYERS) return;
			buf_ptr		= pobj->info.dst[pobj->info.dst_idx].data;
			buf_size	= sizeof(pobj->info.dst[pobj->info.dst_idx].data)-1;
			pobj->info.dst_idx++;
			break;
		}
		case INFO_DATA: {
			if(pobj->info.data_idx + 1 > MAX_LAYERS) return;
			buf_ptr		= pobj->info.data[pobj->info.data_idx].data;
			buf_size	= sizeof(pobj->info.data[pobj->info.data_idx].data)-1;
			pobj->info.data_idx++;
			break;
		}
		case INFO_DESC: {
			if(pobj->info.src_idx + 1 > MAX_LAYERS) return;
			buf_ptr		= pobj->info.desc[pobj->info.src_idx].data;
			buf_size	= sizeof(pobj->info.desc[pobj->info.src_idx].data)-1;
			break;
		}
		case INFO_INTF: {
			if(!base.opts.i) 
				return;

			buf_ptr		= pobj->info.intf.data;
			buf_size	= sizeof(pobj->info.intf.data)-1;
			break;
		}
		default: {
			return;
		}
	}

    va_start(ap, fmt);
    n = vsnprintf(tmp_buf, buf_size, fmt, ap);
    if (n > buf_size)
        n = buf_size;
    else
        n = n;

    va_end(ap);

    n = strlcat(buf_ptr, tmp_buf, buf_size);
    return ;
}


void pobj_layers_print_fill(void) {
	int i;

	base.opts.views[0].fn = (void *)pobj_layers_print_0;
	base.opts.views[1].fn = (void *)pobj_layers_print_0;
	base.opts.views[2].fn = (void *)pobj_layers_print_1;

	for(i=0;i < sizeof(base.opts.views)/sizeof(view_t);i++) {
		if(base.opts.views[i].fn == NULL) { 
			base.opts.views[i].fn = (void *)pobj_layers_print_null;
		}

	} 
}


void pobj_layers_print(pobj_t *pobj) {

	if(!pobj) return;

	base.opts.views[base.opts.view].fn(pobj);

	return;
}

void pobj_layers_print_null(pobj_t *pobj) {
	return;
}


void pobj_layers_print_pre(pobj_t *pobj) {
	if(pobj->info.prefix.data[0] > 0) {
		printf("%s ", pobj->info.prefix.data);
	}
	if(base.opts.i > 0 && pobj->info.intf.data[0] != '\0') {
		if(pobj->info.path.data[0] == '\0') {
			printf("%s ", pobj->info.intf.data);
		} else {
			printf("%s", pobj->info.intf.data);
		}
	}
	if(pobj->info.path.data[0] > 0) {
		printf("%s ", pobj->info.path.data);
	}
	return;
}

void pobj_layers_print_0(pobj_t *pobj) {
	int i, p=0;

	pobj_layers_print_pre(pobj);

	for(i = 0; i < MAX_LAYERS; i++) {
		if(pobj->info.src[i].data[0] == '\0')
			break;

		if(pobj->info.desc[i].data[0]!='\0') {
			printf("%s ", pobj->info.desc[i].data);
		}
		printf("%s > %s ", pobj->info.src[i].data, pobj->info.dst[i].data);
		p++;
	}

	for(i = 0; i < MAX_LAYERS; i++) {
		if(pobj->info.data[i].data[0] == '\0')
			break;

		printf("%s ", pobj->info.data[i].data);
		p++;
	}

	if(p>0) {
		puts("");
	}

	return;
}




void pobj_layers_print_1(pobj_t *pobj) {
	int i, p=0;

	pobj_layers_print_pre(pobj);

	for(i = 0; i < MAX_LAYERS; i++) {

		if(pobj->info.desc[i].data[0]!='\0') {
			printf("%s ", pobj->info.desc[i].data);
		}

		if(pobj->info.src[i].data[0] == '\0')
			break;
		printf("%s ", pobj->info.src[i].data);
		p++;
	}
	if(i>0) {
		printf("> ");
	}
	for(i = 0; i < MAX_LAYERS; i++) {
		if(pobj->info.src[i].data[0] == '\0')
			break;

		printf("%s ", pobj->info.dst[i].data);
		p++;
	}

	for(i = 0; i < MAX_LAYERS; i++) {
		if(pobj->info.data[i].data[0] == '\0')
			break;
		printf("%s ", pobj->info.data[i].data);
		p++;
	}

	if(p>0) {
		puts("");
	}
	return;
}




void pobj_layers_zro(pobj_t *pobj) {
	int i;

	if(!pobj) return;

	pobj->info.prefix.data[0] 	= '\0';
	pobj->info.path.data[0]		= '\0';

	for(i = 0; i < MAX_LAYERS; i++) {
		pobj->info.src[i].data[0]	= '\0';
		pobj->info.dst[i].data[0]	= '\0';
		pobj->info.data[i].data[0]	= '\0';
		pobj->info.desc[i].data[0]	= '\0';
	}

	pobj->info.src_idx	= 0;
	pobj->info.dst_idx	= 0;
	pobj->info.data_idx	= 0;
	pobj->info.desc_idx	= 0;

	pobj->info.intf.data[0]		= '\0';

	return;
}


route_t * routes_insert(char * intf, char * dest, char * gw, char * mask) {
	route_t * r, *r_tmp;

	if(!intf || !dest || !gw || !mask) return NULL;

	r = (route_t *)calloc(1,sizeof(route_t));
	if(!r) { error("routes_insert: calloc"); }

	if(!base.routes) {
		base.routes = r;
	} else {
		r_tmp = base.routes;
		base.routes = r;
		r->next = r_tmp;
	}

	r->intf = strdup(intf);
	r->addr_dest.s_addr = strtoul(dest, NULL, 16);
	r->addr_gw.s_addr = strtoul(gw, NULL, 16);
	r->addr_mask.s_addr = strtoul(mask, NULL, 16);
	r->addr_end.s_addr = (0xFFFFFFFF - r->addr_mask.s_addr) + r->addr_dest.s_addr;
	
	r->str_dest	= strdup(inet_ntoa(r->addr_dest));
	r->str_gw	= strdup(inet_ntoa(r->addr_gw));
	r->str_mask	= strdup(inet_ntoa(r->addr_mask));
	r->str_end	= strdup(inet_ntoa(r->addr_end));

	debug("# ROUTE_INSERT: %s %s %s %s ::: dest=%s gw=%s mask=%s end=%s  \n", 
		intf, dest, gw, mask, r->str_dest, r->str_gw, r->str_mask, r->str_end);

	return r;
}
void routes_parse(void) {
	FILE * fp;
	route_t *r;
	char buf[1024], *s_intf, *s_dest, *s_gw, *s_mask;
	int n=0,i;

	fp = fopen("/proc/net/route", "r");
	if(!fp) {
		error("Cannot open /proc/net/route");
	}

	while(1) {
		memset(buf,0,sizeof(buf));
		if(fgets(buf,sizeof(buf)-1,fp)==NULL) break;
		if(!n) {n++; continue;}
		n++;

		s_intf = strtok(buf, "\t");
		if(!s_intf) continue;

		s_dest = strtok(NULL, "\t");
		if(!s_dest) continue;

		s_gw = strtok(NULL, "\t");
		if(!s_gw) continue;

		for(i=0;i<4;i++) { strtok(NULL, "\t"); }
		s_mask = strtok(NULL, "\t");
		if(!s_mask) continue;

		r = routes_insert(s_intf, s_dest, s_gw, s_mask);
	}
	return;
}


pobj_t * pobj_create(char * intf, char * filter, int promisc, int to_ms, int count) {
	pcap_if_t * ifs = NULL, *ifp;
	char errbuf [ PCAP_ERRBUF_SIZE + 1 ];
	int ret;

	if(!intf) {
		error("pobj_create");
	}

	if(!strncasecmp(intf, "any", 3) || !strncasecmp(intf, "all", 3)) {
		ret = pcap_findalldevs(&ifs, errbuf);
		if(ret < 0) {
			error("pcap_findalldevs");
		}

		for(ifp = ifs; ifp != NULL; ifp = ifp->next) {
			if(!strncasecmp(ifp->name, "any", 3)) continue;
			pobj_create_exact(ifp->name, filter, promisc, to_ms, count);
		}
	}
	else {

		return pobj_create_exact(intf, filter, promisc, to_ms, count);
	}

	return NULL;
}


void pobj_datalink(pobj_t * pobj) {
	datalink_t * dl;

	if(!pobj) return;

	dl = &pobj->intf.datalink;

	dl->val = pcap_datalink(pobj->pcap);
	dl->name = pcap_datalink_val_to_name(dl->val);
	if(dl->name) dl->name = strdup(dl->name);
	dl->desc = pcap_datalink_val_to_description(dl->val);
	if(dl->desc) dl->desc = strdup(dl->desc);

	dl->plink.fn = p_datalinks[dl->val].fn;

	return;
}


pobj_t * pobj_create_exact(char * intf, char * filter, int promisc, int to_ms, int count) {
	pobj_t * pobj;
	char errbuf [ PCAP_ERRBUF_SIZE + 1 ];
	int ret;

	if(!intf || !filter) {
		error("pobj_create: intf || filter == NULL");
	}

	pobj = (pobj_t *) calloc(1,sizeof(pobj_t));
	if(!pobj) {
		error("pobj_create: calloc");
	}
    
	if(!base.head) {
		base.head = pobj;
	}
	else {
		pobj_t * pobj_tmp = base.head;
		base.head = pobj;
		pobj->next = pobj_tmp;
	}

	pobj->intf.name		= intf;
	pobj->intf.filter	= filter;
	pobj->intf.promisc	= promisc;
	pobj->intf.to_ms	= to_ms;
	pobj->intf.count	= 0;

	ret = pcap_lookupnet(pobj->intf.name, &pobj->intf.net, &pobj->intf.mask, errbuf);
	if(ret < 0) {
		if(strstr(errbuf, "no IPv4 address assigned")==NULL) {
			error(errbuf);
		}
	}

	pobj->pcap = pcap_open_live(pobj->intf.name, BUFSZ, pobj->intf.promisc, pobj->intf.to_ms, errbuf);
	if(!pobj->pcap) {
		error(errbuf);
	}

	pobj_datalink(pobj);
	
	pobj->intf.fd = pcap_get_selectable_fd(pobj->pcap);

	if(!strncasecmp(pobj->intf.filter, "none", 4) 
		|| !strncasecmp(pobj->intf.filter, "all", 3) 
		|| !strncasecmp(pobj->intf.filter, "any", 3)) {
	}
	else {
		ret = pcap_compile(pobj->pcap, &pobj->intf.fp, pobj->intf.filter, 0, 0);
		if(ret < 0) {
			error("pcap_compile");
		}
		ret = pcap_setfilter(pobj->pcap, &pobj->intf.fp);
		if(ret < 0) {
			error("pcap_setfilter");
		}
	}


	/* ev */
	event_set(&pobj->intf.ev, pobj->intf.fd, EV_READ | EV_PERSIST, pobj_handler, pobj);
	event_base_set(base.evb, &pobj->intf.ev);
	event_add(&pobj->intf.ev, NULL);

	return pobj;
}


void pobj_list(void) {
	pobj_t * pobj;

	for(pobj = base.head; pobj != NULL; pobj = pobj->next) {
		debug("# INTERFACE: %s => Filter: %s => %s %s\n", 
			pobj->intf.name, pobj->intf.filter, pobj->intf.datalink.name, pobj->intf.datalink.desc);
	}
}



void pobj_stats(void) {
	pobj_t * pobj;
	struct pcap_stat ps;
	int ret;

	for(pobj = base.head; pobj != NULL; pobj = pobj->next) {
		ret = pcap_stats(pobj->pcap, &ps);	
		if(ret < 0) continue;

		printf("# STATS: %10s ::: captured=%i received=%i drops=%i interface_drops=%i :: filter=%s\n", 
			pobj->intf.name, ps.ps_recv - ps.ps_drop, ps.ps_recv, ps.ps_drop, ps.ps_ifdrop, pobj->intf.filter);
	}
	return;
}




void pobj_handler(int fd, short event, void * arg) {

	pobj_t * pobj;
	struct pcap_pkthdr phdr;
	time_t t;
	const unsigned char * raw_packet;

	if(fd < 0 || !arg) error("pobj_handler");

	pobj = (pobj_t *) arg;

	raw_packet = pcap_next(pobj->pcap, &phdr);
	if(!raw_packet) {
		noncrit("pcap_next");
		return;
	}

	pobj->intf.count += 1;

	if(base.opts.pause) return;

	pobj->pkt.raw	= raw_packet;
	pobj->pkt.off	= 0;
	pobj->pkt.phdr	= &phdr;

	pobj_layers_zro(pobj);
	if(base.opts.t > 0) {
		t = time(NULL);
		pobj_layers_add(pobj, INFO_PREFIX, "%.10li:", t);
	}
	if(base.opts.c > 0) {
		pobj_layers_add(pobj, INFO_PREFIX, "%.10i", pobj->intf.count);
	}
	pobj_layers_add(pobj, INFO_INTF, "%s" , pobj->intf.name);

	pobj->intf.datalink.plink.fn((pobj_t *)pobj);

	pobj_layers_print(pobj);

	return;
}



void stdin_handler(int fd, short event, void * arg) {
	int c = 0;
	size_t n;

	n = read(0, &c, 1);

	if(c >= '0' && c <= '9') {
		c = ctoi(c);
		if(c > MAX_VIEWS) {
			puts("# ERROR: No such view.");
			return;
		}
		if(c != base.opts.view) {
			printf("# SWITCHED VIEW: %i\n", c);
			base.opts.view = c;
			return;
		}
	}

	stdin_handle_char(c);

	return;
}


void stdin_handle_char(int c) {

	switch(c) {
		case ' ': {
			/* play/pause */
			if(!base.opts.pause) {
				base.opts.pause = 1;
				puts("# PAUSED");
			}
			else {
				base.opts.pause = 0;
				puts("# RESUMED");
			}
			break;
		}
		case 'e': {
			/* toggle ethernet frames */
			if(!base.opts.e) base.opts.e = 1;
			else base.opts.e = 0;
			break;
		}
		case 'c': {
			/* toggle count */
			if(!base.opts.c) base.opts.c = 1;
			else base.opts.c = 0;
			break;
		}
		case 'p': {
			/* toggle path */
			if(!base.opts.p) { 
				base.opts.p = 1;
				base.opts.i = 1;
			}
			else {
				base.opts.p = 0;
			}
			break;
		}
		case 't': {
			/* toggle timestamp */
			if(!base.opts.t) base.opts.t = 1;
			else base.opts.t = 0;
			break;
		}
		case 's': {
			/* toggle service translation */
			if(!base.opts.s) base.opts.s = 1;
			else base.opts.s = 0;
			break;
		}
		case 'i': {
			/* toggles interface printing */
			if(!base.opts.i) base.opts.i = 1;
			else base.opts.i = 0;
			break;
		}
		case 'E': {
			if(!base.opts.E) {
				base.opts.E = 1;
			}
			else {
				base.opts.E = 0;
			}
			base.opts.t = base.opts.E;
			base.opts.c = base.opts.E;
			base.opts.e = base.opts.E;
			base.opts.p = base.opts.E;
			base.opts.i = base.opts.E;
			base.opts.s = base.opts.E;
			break;
		}
		case 'd':
		case 'v': {
			if(debug == printf) {
				debug = printf_null;
				base.opts.d = 0;
			}
			else {
				debug = printf;
				base.opts.d = 1;
			}
			break;
		}
		case 'h': {
			/* help */
			printf(
				"# HELP:\n"
					"#\t<space>\t\t: Pauses or resumes the capture\n"
					"#\tE\t\t: Toggles everything\n"
					"#\ti\t\t: Toggles printing of interface\n"
					"#\tp\t\t: Toggles printing of \"layer\" path\n"
					"#\te\t\t: Toggles ethernet headers\n"
					"#\tt\t\t: Toggles timestamp\n"
					"#\tc\t\t: Toggles packet count\n"
					"#\ts\t\t: Toggles service translation\n"
					"#\td\t\t: Toggles debugging information\n"
					"#\th\t\t: This help menu\n"
					"#\t0-3\t: Chooses a view layout\n"	
			);
			break;
		}
		case '\r':
		case '\n': {
			/* print some nl's to screen */
			puts("");
			break;
		}
		default: {
			break;
		}
	}

	return;
}



int parse_argv(int argc, char ** argv) {
	pobj_t * pobj;
	char * intf, *filt, *sptr;
	int i;
	

	if(argc < 1) {
		help("Incorrect number of arguments");
	}

	
	for(i = 0; i < argc; i++) {

		if(argv[i][0] == '-') {
			stdin_handle_char(argv[i][1]);
			continue;
		}

		sptr = strtok(argv[i], ",");
		if(!sptr) {
			help("Invalid syntax");
		}
		intf = strdup(sptr);
		sptr = strtok(NULL, "");
		if(!sptr) {
			filt = strdup("all");
		} else {
			filt = strdup(sptr);
		}

		pobj = pobj_create(intf,filt,1,1000,-1);
	}

	pobj_list();

	return 0;
}


int printf_null(const char *format, ...) {
	return 0;
}



void fini_sighandler(int num) {
fini();
}



void fini(void) {

	/* STATS! */
	pobj_stats();	

	fini_term();
	exit(0);
}




void init_term(void) {

	tcgetattr(0, &base.term.o);
	base.term.n = base.term.o;
	base.term.n.c_lflag &= ~ICANON;
	base.term.n.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &base.term.n);


	/* stdin ev */
	event_set(&base.term.ev, 0, EV_READ | EV_PERSIST, stdin_handler, NULL);
	event_base_set(base.evb, &base.term.ev);
	event_add(&base.term.ev, NULL);

}

void fini_term(void) {

	tcsetattr(0, TCSANOW, &base.term.o);
}


void init(void) {
	debug = printf_null;

	base.opts.view = 2;
	signal(SIGINT, fini_sighandler);
	signal(SIGSEGV, fini_sighandler);

	pobj_layers_print_fill();
	p_init();
}


int main(int argc, char ** argv, char ** envp) {

	init();

	event_init();
	base.evb = event_base_new();

	parse_argv(argc-1, &argv[1]);
	atexit(fini);

	routes_parse();
	
	init_term();
	if(base.head == NULL) exit(0);

	svcs_init();
	event_base_dispatch(base.evb);

	return 0;
}
