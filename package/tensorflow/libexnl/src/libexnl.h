#define _GNU_SOURCE
#include <sched.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "uthash.h"
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <execinfo.h>
#include <pthread.h>

#define BUFFER128 //defines buffer length
//#define EXEIN_BUFFERGUARD // inserts a couple of canaries to protect the cbuffer where data are placed.

/*errors*/
#define EXEIN_NOERR		0
#define EXEIN_ERR_NLSOCKET	-1
#define EXEIN_ERR_NLBIND	-2
#define EXEIN_ERR_NOMEM		-3
#define EXEIN_ERR_NLCOM		-4
#define EXEIN_ERR_REGISTER	-5
#define EXEIN_ERR_NOPID		-6
#define EXEIN_CANARYERR		-7
#define EXEIN_MUTEXERR		-8

#define EXEIN_MSG_REG		1
#define EXEIN_MSG_KA		2
#define EXEIN_MSG_BK 		4

#define EXEIN_STAT_SK_ENOMEM	3
#define EXEIN_STAT_RF_ENOMEM	2
#define EXEIN_STAT_RF_ENLCOM	1
#define EXEIN_STAT_OK		0

#define EXEIN_SK_STACK_SIZE	4*1024
#define EXEIN_RF_STACK_SIZE	4*1024


/**/
#if defined(BUFFER64)
#define EXEIN_BUFFER_MASK 0x3f
#define EXEIN_BUFFES_SIZE 0x40
#define EXEIN_BUFFES_SIZE_CNT 0x06
#warning "buffer defined to be 64 bytes each"
#elif defined(BUFFER128)
#define EXEIN_BUFFER_MASK 0x7f
#define EXEIN_BUFFES_SIZE 0x80
#define EXEIN_BUFFES_SIZE_CNT 0x07
#warning "buffer defined to be 128 bytes each"
#else
#define EXEIN_BUFFER_MASK 0x1f
#define EXEIN_BUFFES_SIZE 0x20
#define EXEIN_BUFFES_SIZE_CNT 0x05
#warning "buffer defined to be 32 bytes each"
#endif

#define EXEIN_BACKTRACE_SIZE 20
#define NETLINK_USER 31
#define MAX_PAYLOAD 1024 /* maximum payload size*/

/*macros*/
#define EX_FEED_PACKET_SIZE(data) (*(data+5)-*(data+4))+ 7

typedef struct {
        uint16_t hookid;
        uint16_t pid;
} exein_hook_data;

typedef struct {
	UT_hash_handle	hh;
	uint16_t	pid;
	exein_hook_data *data;
	uint8_t		index;
	pthread_mutex_t	lock;
} exein_buffers;

typedef struct {
	struct sockaddr_nl	*src_addr, *dest_addr;
	struct msghdr		*msg_rf, *msg_sk;
	struct nlmsghdr		*nlh_rf, *nlh_sk;
	exein_buffers		*buffers;
	int			sock_fd;
	void			*sk_stack, *rf_stack;
	pid_t			sk_pid, rf_pid, cpid;
	int			trouble;
} exein_shandle;

typedef struct {
	exein_shandle	*uhandle;
	char	loading_done;
	void	*payload;
} proc_args;

typedef struct {
        uint32_t key;
        uint8_t  message_id;
        uint8_t  padding;
        uint16_t tag;
        pid_t    pid;
} exein_prot_req_t;

exein_prot_req_t keepalive={
	.key		= 0,
	.message_id	= EXEIN_MSG_KA,
	.tag		= 0,
	.padding	= 0,
	.pid		= 0,
	};

exein_prot_req_t registration={
	.key		= 0,
	.message_id	= EXEIN_MSG_REG,
	.tag		= 0,
	.padding	= 0,
	.pid		= 0,
	};

void (*exein_new_pid_notify_cb)(uint16_t)=NULL;
void (*exein_removed_pid_notify_cb)(uint16_t)=NULL;

void exein_dummy_pid_notify_cb(uint16_t pid);
int exein_fetch_data(exein_shandle *uhandle, uint16_t pid, uint16_t *dstbuf);

/*
	src_addr
	dest_addr
	bind_pid    nl address where send return messages, usually the application pid
	return the socket handle on success, -1 socket fail
*/
int netlink_setup(exein_shandle *uhandle, pid_t bind_pid);

/*
return 1 on success 0 on fail
*/
int netlink_msg_init(int max_payload, pid_t bind_pid, exein_shandle *uhandle);

/*
return 1 on success 0 on fail
*/
int exein_nl_peer_register(exein_shandle *uhandle, exein_prot_req_t *packet);

/*
return 1 on success 0 on fail
*/
int receive_feeds(void *data);

/*
return 1 on success 0 on fail
*/
int send_keepalives(void *data);

void exein_agent_stop(exein_shandle *uhandle);

/*
return 1 on success 0 on fail
*/
exein_shandle *exein_agent_start(uint32_t key, uint16_t tag);

int exein_block_process(exein_shandle *uhandle, uint16_t pid, uint32_t key, uint16_t tag);
int remove_buffer(exein_shandle *uhandle, uint16_t pid);

/*
returns 1 is pid exists on procfs, 0 if it doesn't
*/
int pid_exists(uint16_t pid);

int exein_janitor(exein_shandle *uhandle);
