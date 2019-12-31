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
    
    gcc ../libexnl/examples/check_pid.c -static -o ./initramfs/check-pid
    chmod 777 initramfs/check-pid

    tar cvzf initramfs.tar.gz initramfs/
    ./run-qemu.sh



    # get the random key for communicating with the LKM
    # cat proc/exein/rndkey

    # inside qemu:
    /bin/busybox insmod /exein_interface.ko
    /bin/busybox lsmod
    cat /proc/exein/rndkey
    /bin/busybox ps | /bin/busybox grep -i sh | /bin/busybox head -n 1
    ./check-pid 1
    # strace -xvy -s 2048 ./netlink-test
+
*/

#include "../libexnl.c"
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char const *argv[])
{
    uint16_t pid = strtol(argv[1], NULL, 10);
    printf("Parameters pid:%d\n", pid);
    
	int i = 0;
	int	count = 10;

    int delay = 8; // seconds

    while (count > 0){
        sleep(1);
        printf("Pid:%d Exists?=%d\n", pid, pid_exists(pid));
    }

    exit(0);
}