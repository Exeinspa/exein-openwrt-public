/* build

    # inside ntl code folder #
    # git clone gitea@git.exein.local:Exein.io/libexnl.git

    # DO THIS ONLY FOR KERNEL CHANGES AS IT'LL RENDER THE KEY USELESS
    # recompile kernel
    cd linux-4.14.151/; and make -j (nproc); and cd ../
    # DO THIS ONLY FOR KERNEL CHANGES AS IT'LL RENDER THE KEY USELESS


    # clean
    rm initramfs-busybox-x86.cpio.gz
    tar xf initramfs.tar.gz
    rm -rf initramfs/netlink-test.c initramfs/netlink-test

    # copy LKM into intramfs
    cp ./linux-4.14.151/drivers/exein_interface/exein_interface.ko ./initramfs/exein_interface.ko
    
    gcc ../LSM-Exein/ntl-code/ntlcode.c -static -o ./initramfs/netlink-test
    chmod 777 initramfs/netlink-test

    tar cvzf initramfs.tar.gz initramfs/
    ./run-qemu.sh

    # get the random key for communicating with the LKM
    # cat proc/exein/rndkey

    # inside qemu:
    /bin/busybox insmod /exein_interface.ko
    /bin/busybox lsmod
    cat /proc/exein/rndkey
    /bin/busybox ps | /bin/busybox grep -i sh | /bin/busybox head -n 1
    ./netlink-test 1 1 1627542405
    # strace -xvy -s 2048 ./netlink-test
+
*/

#include "../libexnl.h"
#include <unistd.h>
#include <stdlib.h>

uint16_t data[EXEIN_BUFFES_SIZE];

void test_cb(uint16_t pid){
	printf("callback for pid:%d\n", pid);
}

int main(int argc, char const *argv[])
{
    uint16_t pid = strtol(argv[1], NULL, 10);
    uint16_t tag = strtol(argv[2], NULL, 10);
    uint32_t key = strtol(argv[3], NULL, 10);
    printf("Parameters pid:%d, tag:%d, key:%d\n", pid, tag, key);
    
    // pid = getpid();
    // printf("Replacing pid with current:%d\n", pid);
    
	int i = 0;
	int	count = 10;

    exein_new_pid_notify_cb = &test_cb;

    int delay = 8; // seconds

    printf("Exein agent handler...\n");
    exein_shandle *exein_agent_handle = exein_agent_start(key, tag);

    if(exein_agent_handle){
        printf("Exein agent handler started tag:%d, key:%d\n", tag, key);
        while (count > 0){
            sleep(1);
            if (--count==5){
                printf("About to block pid:%d, tag:%d, key:%d\n", pid, tag, key);
                exein_block_process(exein_agent_handle, pid, key, tag);
            }
            printf("Count:%d - - pid:%d, tag:%d, key:%d\n", count, pid, tag, key);
        }

        exein_agent_stop(exein_agent_handle);
        exit(1);
    }
}
