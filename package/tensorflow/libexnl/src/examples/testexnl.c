#define BUFFER128
#include "../libexnl.h"

uint16_t pidl4=0;
uint16_t data[EXEIN_BUFFES_SIZE];

void test_cb(uint16_t pid){
//	if (pidl4==0)
pidl4=pid;
	printf("Now checking pid %d\n", pid);
}

int main(int argc, char *argv[]){
	exein_shandle	*h;
	int 		i=0;
	int		count=0;

	exein_new_pid_notify_cb=&test_cb;
	h=exein_agent_start(atoi(argv[1]),atoi(argv[2]));
	if (h) while (1){
		if (pidl4!=0) {
			if (exein_fetch_data(h, pidl4, data)==EXEIN_NOERR){
				printf("Data (%d, %d) ==> [", pidl4, count);
				for (i=0;i<EXEIN_BUFFES_SIZE;i++){
					printf("%d, ",data[i]);
					}
				printf("]\n");
				}
			}
		sleep(1);
		count++;
//		if (--count==0){
//			exein_agent_stop(h);
//			exit(1);
//			}
		}
}
