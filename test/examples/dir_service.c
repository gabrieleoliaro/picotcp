#include "utils.h"
#include <pico_socket.h>
#include <pico_ipv4.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#define MAXENTRIES 10

struct entry {
	char *name;
	char *ip_address;
};

struct entry *table;

int last_entry;


void add_entry(char *name_input, char *ip_input)
{
	assert(table);
	int name_len = strlen(name_input)+1;
	int ip_len = strlen(ip_input)+1;
	assert(ip_len >= 7 && ip_len <= 15);
	assert(last_entry >=0 && last_entry < MAXENTRIES);

	table[last_entry].name = (char*) malloc(name_len*sizeof(char));
	strcpy(table[last_entry].name, name_input);

	table[last_entry].ip_address = (char*) malloc(ip_len*sizeof(char));
	strcpy(table[last_entry].ip_address, ip_input);

	last_entry++;
}

void print_table() {
	assert(table);
	assert(last_entry >= 0 && last_entry < MAXENTRIES);
	printf("last_entry: %i\n",last_entry);
	for (int i=0; i<last_entry; i++) {
		printf("%i: %s\t\t%s\n", i, table[i].name, table[i].ip_address);
	}
	for (int i=last_entry; i<MAXENTRIES; i++) {
		assert(!table[i].name && !table[i].ip_address);
	}
}

char *lookup_name(char *name) {
	assert(table);
	assert(last_entry >= 0 && last_entry < MAXENTRIES);
	for (int i=0; i<last_entry; i++) {
		if (strcmp(name, table[i].name) == 0) {
			return table[i].ip_address;
		}
	}

	return NULL;
}


/*** START TCP ECHO ***/
#define BSIZE (1024 * 10)
static char recvbuf[BSIZE];
static int len = 0;
static int flag = 0;




int send_dir_service(struct pico_socket *s)
{
    assert(len >=0 && table);
	// nothing to lookup
	if (len == 0) {
		return;
	}

    char *lookup_result;
    char *res = lookup_name(recvbuf);
    if (!res) {
    	lookup_result = malloc(strlen("not found!\n")+1);
    	strcpy(lookup_result, "not found!\n");
    } else {
    	lookup_result = malloc(strlen(res)+1);
    	strcpy(lookup_result, res);
    	lookup_result[strlen(res)] = '\n';
    }
    
    int pos = 0, w=0, ww=0, towrite = strlen(lookup_result)+1;
    
    do {
        w = pico_socket_write(s, lookup_result + pos, towrite - pos);
        if (w > 0) {
        	ww += w;
            pos += w;
        }
    } while((w > 0) && (pos < towrite));
    
    len = 0;
    free(lookup_result);
    return ww;
}

void cb_dir_service(uint16_t ev, struct pico_socket *s)
{
    int r = 0;

    picoapp_dbg("dir_service> wakeup ev=%u\n", ev);

    // this gets triggered when data arrives on the socket
    if (ev & PICO_SOCK_EV_RD) {

        yellow();
        printf("\t%s:%d: ", __FILE__, __LINE__);
        blue();
        printf("data arrived on the socket!\n");
        back2white();

        if (flag & PICO_SOCK_EV_CLOSE)
            printf("SOCKET> EV_RD, FIN RECEIVED\n");

        while (len < BSIZE) {
            r = pico_socket_read(s, recvbuf + len, BSIZE - len);
            if (r > 0) {
            	//while we were able to read anything
                len += r;
                
                flag &= ~(PICO_SOCK_EV_RD);
            } else {
            	// done reading I suppose
                flag |= PICO_SOCK_EV_RD;
                break;
            }
        }
        
        if (recvbuf[len-1]== '\n') {
        	recvbuf[len-1] = '\0';
        }

        if (flag & PICO_SOCK_EV_WR) {
            flag &= ~PICO_SOCK_EV_WR;
            send_dir_service(s);
        }
    }


    // this gets triggered when a TCP connection is established
    if (ev & PICO_SOCK_EV_CONN) {
        
        yellow();
        printf("\t%s:%d: ", __FILE__, __LINE__);
        blue();
        printf("connection now established\n");
        back2white();
        
        uint32_t ka_val = 0;
        struct pico_socket *sock_a = {
            0
        };
        struct pico_ip4 orig = {
            0
        };
        uint16_t port = 0;
        char peer[30] = {
            0
        };
        int yes = 1;

        sock_a = pico_socket_accept(s, &orig, &port);
        pico_ipv4_to_string(peer, orig.addr);
        printf("Connection established with %s:%d.\n", peer, short_be(port));
        pico_socket_setoption(sock_a, PICO_TCP_NODELAY, &yes);
        /* Set keepalive options */
        ka_val = 5;
        pico_socket_setoption(sock_a, PICO_SOCKET_OPT_KEEPCNT, &ka_val);
        ka_val = 30000;
        pico_socket_setoption(sock_a, PICO_SOCKET_OPT_KEEPIDLE, &ka_val);
        ka_val = 5000;
        pico_socket_setoption(sock_a, PICO_SOCKET_OPT_KEEPINTVL, &ka_val);
        /* ka_val = 0;
        pico_socket_setoption(sock_a, PICO_SOCKET_OPT_LINGER, &ka_val); */
    }

    if (ev & PICO_SOCK_EV_FIN) {

        yellow();
        printf("\t%s:%d: ", __FILE__, __LINE__);
        blue();
        printf("socket got closed!\n");
        back2white();

        printf("Socket closed. Exit normally. \n");
/*        if (!pico_timer_add(6000, deferred_exit, NULL)) {
            printf("Failed to start exit timer, exiting now\n");
            exit(1);
        }
        */
    }

    if (ev & PICO_SOCK_EV_ERR) {
        
        yellow();
        printf("\t%s:%d: ", __FILE__, __LINE__);
        blue();
        printf("error occurred\n");
        back2white();
        
        printf("Socket error received: %s. Bailing out.\n", strerror(pico_err));
        exit(1);
    }

    if (ev & PICO_SOCK_EV_CLOSE) {

        yellow();
        printf("\t%s:%d: ", __FILE__, __LINE__);
        blue();
        printf("received a FIN segment (other endpoint closed)\n");
        back2white();

        printf("Socket received close from peer.\n");
        if (flag & PICO_SOCK_EV_RD) {
            pico_socket_shutdown(s, PICO_SHUT_WR);
            printf("SOCKET> Called shutdown write, ev = %d\n", ev);
        }
    }


    // triggered when ready to write to the socket
    if (ev & PICO_SOCK_EV_WR) {

        yellow();
        printf("\t%s:%d: ", __FILE__, __LINE__);
        blue();
        printf("now ready to write on the socket\n");
        back2white();

        r = send_dir_service(s);
        if (r == 0)
            flag |= PICO_SOCK_EV_WR;
        else
            flag &= (~PICO_SOCK_EV_WR);
    }
}

void app_dir_service(char *arg)
{
	table = (struct entry *) malloc (sizeof(struct entry) * MAXENTRIES);
	assert(table);
	assert(last_entry==0);
	for (int i=0; i<MAXENTRIES; i++) {
		table[i].name = table[i].ip_address = NULL;
	}

	add_entry("Liam", "192.168.11.37");
	add_entry("Emma", "192.168.12.37");
	add_entry("Oliver", "192.168.13.37");
	add_entry("Sophia", "192.168.14.37");
	print_table();

    char *nxt = arg;
    char *lport = NULL;
    uint16_t listen_port = 0;
    int ret = 0, yes = 1;
    struct pico_socket *s = NULL;
    union {
        struct pico_ip4 ip4;
        struct pico_ip6 ip6;
    } inaddr_any = {
        .ip4 = {0}, .ip6 = {{0}}
    };

    /* start of argument parsing */
    if (nxt) {
        nxt = cpy_arg(&lport, nxt);
        if (lport && atoi(lport)) {
            listen_port = short_be(atoi(lport));
        } else {
            goto out;
        }
    } else {
        /* missing listen_port */
        goto out;
    }

    /* end of argument parsing */
    
    yellow();
    printf("\t%s:%d: ", __FILE__, __LINE__);
    red();
    printf("entered app_dir_service. lport: %s, listen_port: %hu\n", lport, (unsigned short int) listen_port);
    back2white();


    if (!IPV6_MODE)
        s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_dir_service);
    else
        s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_TCP, &cb_dir_service);

    if (!s) {
        printf("%s: error opening socket: %s\n", __FUNCTION__, strerror(pico_err));
        exit(1);
    }

    yellow();
    printf("%s:%d: ", __FILE__, __LINE__);
    red();
    printf("about to print about nagle algorithm\n");
    back2white();
    
    pico_socket_setoption(s, PICO_TCP_NODELAY, &yes);
    

    yellow();
    printf("\t%s:%d: ", __FILE__, __LINE__);
    red();
    printf("just printed about nagle algorithm\n");
    back2white();



    if (!IPV6_MODE)
        ret = pico_socket_bind(s, &inaddr_any.ip4, &listen_port);
    else
        ret = pico_socket_bind(s, &inaddr_any.ip6, &listen_port);

    if (ret < 0) {
        printf("%s: error binding socket to port %u: %s\n", __FUNCTION__, short_be(listen_port), strerror(pico_err));
        exit(1);
    }

    if (pico_socket_listen(s, 40) != 0) {
        printf("%s: error listening on port %u\n", __FUNCTION__, short_be(listen_port));
        exit(1);
    }

    printf("Launching PicoTCP echo server\n");
    yellow();
    printf("\t%s:%d: ", __FILE__, __LINE__);
    red();
    printf("leaving app_dir_service now!\n");
    back2white();
    return;

out:
    fprintf(stderr, "dir_service expects the following format: dir_service:listen_port\n");
    exit(255);
}
/*** END TCP ECHO ***/
