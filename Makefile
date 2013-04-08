CFLG=-Wall -O3
LIBS=-lpcap -levent -lbsd
SRCS=intsn_parse.c intsn_net.c intsn_misc.c intsn_services.c

all:
	gcc $(CFLG) intsn.c $(SRCS) $(LIBS) -o intsn
run:
	make ; ./intsn eth0,icmp tun0,icmp sit0 sit1 any,"host 192.168.50.100" eth0,arp any,"udp and port 53" eth0,"port 6667" tun0,icmp -d -t -c -s

deps:
	apt-get install libevent-dev libpcap-dev libbsd-dev

clean:
	rm -f intsn
