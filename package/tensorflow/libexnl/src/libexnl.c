#define DEBUG

#include "libexnl.h"

void * get_pc () { return __builtin_return_address(0); }

void dummy_pid_notify_cb(uint16_t pid){
	printf("New pid (%d) have been observed.\n",pid);
}

int pid_exists(uint16_t pid){
	char procfs_path[24];

	snprintf(procfs_path, 24, "/proc/%d", pid);
	DIR* dir = opendir(procfs_path);
	if(!dir) return EXEIN_ERR_NOPID;
	else closedir(dir);
	return EXEIN_NOERR;
}

int exein_janitor(exein_shandle *uhandle){
	exein_buffers           *buf;

	for(buf=uhandle->buffers; buf != NULL; buf=(exein_buffers *)(buf->hh.next)) {
		if (pid_exists(buf->pid)==EXEIN_ERR_NOPID){
			remove_buffer(uhandle, buf->pid);
			}
		}
	return EXEIN_NOERR;
}

int exein_fetch_data(exein_shandle *uhandle, uint16_t pid, uint16_t *dstbuf){
	exein_buffers		*buf;
	int			dstidx;
	int			i;

	for(buf=uhandle->buffers; buf != NULL; buf=(exein_buffers *)(buf->hh.next)) {
			if (buf->pid==pid){
				pthread_mutex_lock(&buf->lock);
				dstidx=0;
				*(dstbuf+dstidx++)= (buf->data+buf->index)->hookid;
				for (i=(buf->index+1)&EXEIN_BUFFER_MASK; i!=((buf->index)&EXEIN_BUFFER_MASK); i=++i&EXEIN_BUFFER_MASK){
					*(dstbuf+dstidx)= (buf->data+i)->hookid;
					dstidx++;
					}

#ifdef EXEIN_BUFFERGUARD
				//check for buffer overflows
				if (*((uint32_t *)buf->data-1) !=0x76886)	{
					printf("\n\n!!!!!!!!\nBuffer overflow low side\n!!!!!!!!\n\n");
					exit(EXEIN_CANARYERR);
					}
				if ( *((uint32_t *)((char *) buf->data + (sizeof(exein_hook_data)<<EXEIN_BUFFES_SIZE_CNT)))   !=0x76772)	{
					printf("\n\n!!!!!!!!\nBuffer overflow high side @%p founf %d\n!!!!!!!!\n\n", ((char *) buf->data + (sizeof(exein_hook_data)<<EXEIN_BUFFES_SIZE_CNT)), *((uint32_t *)((char *) buf->data + (sizeof(exein_hook_data)<<EXEIN_BUFFES_SIZE_CNT))));
					exit(EXEIN_CANARYERR);
					}
#endif
				pthread_mutex_unlock(&buf->lock);
				return EXEIN_NOERR;
				}
		}
	return EXEIN_ERR_NOPID;
}

int netlink_setup(exein_shandle *uhandle, pid_t bind_pid){

	uhandle->sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if(uhandle->sock_fd<0) return EXEIN_ERR_NLSOCKET;
	memset(uhandle->src_addr, 0, sizeof(struct sockaddr_nl));
	uhandle->src_addr->nl_family = AF_NETLINK;
	uhandle->src_addr->nl_pid = bind_pid;
	if (bind(uhandle->sock_fd, (struct sockaddr *)uhandle->src_addr, sizeof(struct sockaddr_nl))<0) return EXEIN_ERR_NLBIND;
	memset(uhandle->dest_addr, 0, sizeof(struct sockaddr_nl));
	uhandle->dest_addr->nl_family = AF_NETLINK;
	uhandle->dest_addr->nl_pid = 0;
	uhandle->dest_addr->nl_groups = 0;
	return EXEIN_NOERR;
}

int netlink_msg_init(int max_payload, pid_t bind_pid, exein_shandle *uhandle){

	uhandle->msg_sk->msg_iov= (struct iovec *) malloc(sizeof(struct iovec));
	if (!uhandle->msg_sk->msg_iov) return EXEIN_ERR_NOMEM;
	uhandle->msg_sk->msg_iov->iov_base = (struct nlmsghdr *)malloc(NLMSG_SPACE(max_payload));
	uhandle->nlh_sk = uhandle->msg_sk->msg_iov->iov_base;
	if (uhandle->msg_sk->msg_iov->iov_base){
		memset(uhandle->msg_sk->msg_iov->iov_base, 0, NLMSG_SPACE(max_payload));
		((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_len	= NLMSG_SPACE(max_payload);
		((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_pid	= bind_pid;
		((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_flags	= 0;
		uhandle->msg_sk->msg_iov->iov_len	= ((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_len;
		uhandle->msg_sk->msg_name		= (void *)uhandle->dest_addr;
		uhandle->msg_sk->msg_namelen	= sizeof(struct sockaddr_nl);
		uhandle->msg_sk->msg_iovlen	= 1;
		uhandle->msg_sk->msg_control	= NULL;
		uhandle->msg_sk->msg_controllen	= 0;
		uhandle->msg_sk->msg_flags		= 0;
		return EXEIN_NOERR;
		} else return EXEIN_ERR_NOMEM;
}

int exein_nl_peer_register(exein_shandle *uhandle, exein_prot_req_t *rpacket){

	memcpy(NLMSG_DATA(uhandle->nlh_sk), rpacket, MAX_PAYLOAD);
	if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) return EXEIN_ERR_NLCOM;
	if (recvmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) return EXEIN_ERR_NLCOM;
	if (strncmp((char *)NLMSG_DATA(uhandle->nlh_sk), "ACK", 3)!=0) return EXEIN_ERR_REGISTER;
	return EXEIN_NOERR;
}

static void sk_sigsegv_handler(int sig, siginfo_t *si, void *unused){
	switch(sig)
		{
		case SIGSEGV:
			{
			printf("Keep alive thread got SIGSEGV at address: 0x%lx\n",(long) si->si_addr);
			exit(-1);
			}
		default:
		printf("Reecived Signal :%d\n",sig);
		};
}

static void rf_sigsegv_handler(int sig, siginfo_t *si, void *unused){
	switch(sig)
		{
		case SIGSEGV:
			{
			printf("Receive feeds thread got SIGSEGV at address: 0x%lx\n",(long) si->si_addr);
			exit(-1);
			}
		default:
		printf("Reecived Signal :%d\n",sig);
		};
}

static void rf_sigchild_handler(int sig, siginfo_t *si, void *unused){
	switch(sig)
		{
		case SIGCHLD:
			{
			printf("One of the child processes died\n");
			exit(-1);
			}
		default:
		printf("Reecived Signal :%d\n",sig);
		};
}

int send_keepalives(void *data){
	exein_shandle 		*uhandle=	((proc_args *)data)->uhandle;
	void			*payload=	((proc_args *)data)->payload;
	struct sigaction	sa;
	//don't think you're smarter. those stack variables are not there by chance

	((proc_args *)data)->loading_done=1;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sk_sigsegv_handler;
	if (sigaction(SIGSEGV, &sa, NULL) == -1){
		printf("Keep alive can't install handler\n");
		}
	while (1){
		memcpy(	NLMSG_DATA(uhandle->nlh_sk), payload, MAX_PAYLOAD);
		uhandle->nlh_sk->nlmsg_pid=uhandle->cpid;
		if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) {
			uhandle->trouble=EXEIN_STAT_SK_ENOMEM;
			continue;
			}
		sleep(5);
		uhandle->trouble=EXEIN_STAT_OK;
		}
	return EXEIN_NOERR;
}

int receive_feeds(void *data){
	uint16_t		seqn=		0x55aa; //hoping it'll never be matched by chance, I just put fake number there
	uint16_t		*rdata;
	exein_buffers		*buf;
	exein_shandle		*uhandle=	((proc_args *)data)->uhandle;
	struct sigaction	sa;
	int			err;

	//don't think you're smarter. those stack variables are not there by chance

	uhandle->msg_rf=		(struct msghdr *) malloc(sizeof(struct msghdr));
	memcpy(uhandle->msg_rf, uhandle->msg_sk, sizeof(struct msghdr));
	uhandle->msg_rf->msg_iov=	(struct iovec *) malloc(sizeof(struct iovec));
	memcpy(uhandle->msg_rf->msg_iov, uhandle->msg_sk->msg_iov, sizeof(struct iovec));
	uhandle->msg_rf->msg_iov->iov_base = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	uhandle->nlh_rf=(struct nlmsghdr *)uhandle->msg_rf->msg_iov->iov_base;
	((proc_args *) data)->loading_done=	1;

	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = rf_sigsegv_handler;
	if (sigaction(SIGSEGV, &sa, NULL) == -1){
		printf("Receive feeds can't install the signal handler.");
		}
	while (1){
		if ((err=recvmsg(uhandle->sock_fd, uhandle->msg_rf, 0))<0) {
			// TODO: clean up so far allocated things (socket toka)
			printf("recvmsg went wrong %d\n", err);
			uhandle->trouble=EXEIN_STAT_RF_ENLCOM;
			continue;
			}
		rdata = (uint16_t *) NLMSG_DATA(uhandle->nlh_rf);
		if (*(rdata + EX_FEED_PACKET_SIZE (rdata) -1)!=seqn) {
			HASH_FIND(hh,uhandle->buffers,(rdata+2),sizeof(uint16_t),buf);
			if (buf){
				pthread_mutex_lock(&buf->lock);
				(buf->data + buf->index)->pid =    *(rdata+2);
				(buf->data + buf->index)->hookid = *(rdata+3);
				buf->index = ++buf->index & EXEIN_BUFFER_MASK;
				seqn=*(rdata + EX_FEED_PACKET_SIZE (rdata) -1);
				pthread_mutex_unlock(&buf->lock);
				} else {
					if (exein_new_pid_notify_cb!=NULL) {
						(*exein_new_pid_notify_cb)(*(rdata+2));
						}
					if (!(buf=(exein_buffers *) malloc(sizeof(exein_buffers)))){
						uhandle->trouble=EXEIN_STAT_RF_ENOMEM;
						return EXEIN_ERR_NOMEM;
						}
#ifdef EXEIN_BUFFERGUARD

					if (!(buf->data=(exein_hook_data *)malloc(( sizeof(exein_hook_data) << EXEIN_BUFFES_SIZE_CNT)+8))){
						uhandle->trouble=EXEIN_STAT_RF_ENOMEM;
						return EXEIN_ERR_NOMEM;
						}
					*((uint32_t *)buf->data)=0x76886;
					*((uint32_t *) ((char *) buf->data+ (sizeof(exein_hook_data)<<EXEIN_BUFFES_SIZE_CNT) +4) )=0x76772;
					buf->data=(exein_hook_data *) ((uint32_t *)buf->data+1);
#else
					if (!(buf->data=(exein_hook_data *)malloc(sizeof(exein_hook_data)<<EXEIN_BUFFES_SIZE_CNT))){
						uhandle->trouble=EXEIN_STAT_RF_ENOMEM;
						return EXEIN_ERR_NOMEM;
						}
#endif
					buf->index=		1;
					buf->pid=		*(rdata+2);
					buf->data->pid=		*(rdata+2);
					buf->data->hookid= 	*(rdata+3);
					if (pthread_mutex_init(&buf->lock, NULL) != 0) {
						printf("mutex init failed\n");
						return EXEIN_MUTEXERR;
						}
					HASH_ADD(hh,uhandle->buffers,pid,sizeof(uint16_t),buf);
					}
			}
		uhandle->trouble=EXEIN_STAT_OK;
		}
	return EXEIN_NOERR;
}

int remove_buffer(exein_shandle *uhandle, uint16_t pid){
	exein_buffers           *buf;

	HASH_FIND(hh,uhandle->buffers, &pid, sizeof(uint16_t), buf);
	if (buf!=NULL){
		if (exein_removed_pid_notify_cb!=NULL) (*exein_removed_pid_notify_cb)(pid);
		free(buf->data);
		HASH_DEL(uhandle->buffers, buf);
		free(buf);
		return EXEIN_NOERR;
		}
	return EXEIN_ERR_NOPID;
}


int exein_block_process(exein_shandle *uhandle, uint16_t pid, uint32_t key, uint16_t tag){
	exein_prot_req_t block={
        	.key            = key,
	        .message_id     = EXEIN_MSG_BK,
        	.tag            = tag,
	        .padding        = 0,
        	.pid            = pid,
	        };

	memcpy(	NLMSG_DATA(uhandle->nlh_sk), &block, MAX_PAYLOAD);
	uhandle->nlh_sk->nlmsg_pid=pid;
	if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) {
		uhandle->trouble=EXEIN_STAT_SK_ENOMEM;
		return EXEIN_ERR_NLCOM;
		}
	return EXEIN_NOERR;

}

void exein_agent_stop(exein_shandle *uhandle){
	int i;
	exein_buffers *buf;

	kill(uhandle->sk_pid, SIGKILL);
	kill(uhandle->rf_pid, SIGKILL);
	for(buf=uhandle->buffers; buf != NULL; buf=(exein_buffers *)(buf->hh.next)) {
		free(buf);
		}

	close(uhandle->sock_fd);
	free(uhandle->src_addr);
	free(uhandle->dest_addr);
	free(uhandle->msg_sk->msg_iov);
	free(uhandle->msg_sk);
	free(uhandle->nlh_sk);
	free(uhandle->msg_rf->msg_iov);
	free(uhandle->msg_rf);
	free(uhandle->nlh_rf);
	free(uhandle->sk_stack);
	free(uhandle->rf_stack);
}

void stack_trace(){
	void *trace[EXEIN_BACKTRACE_SIZE];
	char **messages = (char **)NULL;
	int i, trace_size = 0;

	trace_size = backtrace(trace, EXEIN_BACKTRACE_SIZE);
	messages = backtrace_symbols(trace, trace_size);
	printf("[stack trace(%d) ]>>>\n", trace_size);
	for (i=0; i < trace_size; i++)
		printf("%s\n", messages[i]);
	printf("<<<[stack trace]\n");
	free(messages);
}



exein_shandle *exein_agent_start(uint32_t key, uint16_t tag)
{
	proc_args		rf_args;
	proc_args		sk_args;
	exein_shandle		*uhandle;
	pid_t			cpid=		0;
	int 			err;
        struct sigaction        sa;
#ifdef DEBUG
	printf("libexnl staring up\n");
#endif
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = rf_sigchild_handler;
        if (sigaction(SIGCHLD, &sa, NULL) == -1){
                printf("main can't install the signal handler.");
                }

	keepalive.key=key;
	keepalive.tag=tag;
	registration.key=key;
	registration.tag=tag;

	uhandle=		(exein_shandle *) malloc(sizeof(exein_shandle));
	memset(uhandle, 0, sizeof(exein_shandle));
	uhandle->dest_addr=	(struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
	uhandle->src_addr=	(struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
	uhandle->msg_sk=	(struct msghdr *) malloc(sizeof(struct msghdr));
	memset(uhandle->msg_sk, 0, sizeof(struct msghdr));
	cpid=getpid();
	if ((err=netlink_setup(uhandle, cpid))<0){
		free(uhandle->msg_sk);
		free(uhandle->src_addr);
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}

	if ((err=netlink_msg_init(MAX_PAYLOAD, cpid, uhandle))<0){
		free(uhandle->msg_sk->msg_iov->iov_base); //nlh
		free(uhandle->msg_sk->msg_iov);
		free(uhandle->msg_sk);
		free(uhandle->src_addr);
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}
	uhandle->cpid=cpid;

	if (exein_nl_peer_register(uhandle, &registration)==EXEIN_NOERR){
		uhandle->sk_stack=	malloc(EXEIN_SK_STACK_SIZE);
		sk_args.uhandle=	uhandle;
		sk_args.payload=	&keepalive;
		sk_args.loading_done=	0;
		uhandle->sk_pid=	clone(&send_keepalives, (char *) uhandle->sk_stack+EXEIN_SK_STACK_SIZE, CLONE_VM, &sk_args);
		uhandle->rf_stack=	malloc(EXEIN_RF_STACK_SIZE);
		rf_args.uhandle=	uhandle;
		rf_args.loading_done=	0;
		uhandle->rf_pid=	clone(&receive_feeds, (char *) uhandle->rf_stack+EXEIN_RF_STACK_SIZE, CLONE_VM, &rf_args);
		} else {
			free(uhandle->msg_sk->msg_iov->iov_base); //nlh
			free(uhandle->msg_sk->msg_iov);
			free(uhandle->msg_sk);
			free(uhandle->src_addr);
			free(uhandle->dest_addr);
			free(uhandle);
			return NULL;
			}
	while (sk_args.loading_done==0) sleep(1);
	while (rf_args.loading_done==0) sleep(1);
	return uhandle;
}
