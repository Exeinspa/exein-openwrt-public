# Exein


Exein's framework goal is to accomplish the tasks of protecting the target system from undesirable behavior, introducing the self-protecting and remote-monitoring set of tools into the embedded systems arena.

![splash](/imgs/splash.jpg)

The natural position of a piece of software providing **Run-time anomaly detection** features is within the Linux kernel using the Linux Security Module ecosystem.

The task of analyzing the system behavior enumerating system's event is divided into two macro functions:

- collecting event at OS level (**LSM Exein**)
- provide a mean of communication between kernel space  section and the userspace applications (**Exein_interface**)
- analyzing them using machine learning algorithms (**MLEPlayer**)

The **LSM Exein** is the part of the Exein solution which interfaces with the Linux kernel and exports the system events data to the userspace application module for the analysis. Its main functions are:

- Interface with the Linux Kernel
- Collect the events flows
- enforce policies dictated by the *MLEPlayer*

The **Exein_interface** is the glue that makes possible userspace MLEPlayer to communicate with the *LSM Exein*. It accomplishes this task by defining a new protocol within the Linux Netlink stack. It also provides userspace tools for debugging purposes.

The next part of the list is the code part where the actual computation is performed by the machine learning algorithms.  The code block element is called **MLEPlayer**.

The **MLEPlayer** embodies the following function:

- Receive data from the *Exein_interface*
- Send policies to the *Exein_interface*
- Triggers the machine learning algorithm on the supplied data


![design](/imgs/exein.png)


## User space
- libexnl: the library implements the NetLink agent in charge for collecting data, register the application to the kernel and keep this registration active. It also provides function for fetching data and push policies.
- MLEPlayer: Using Tensorflow 2.0.0 it performs the actual computation tracking the target application behavior.


## Kernel
- LSM this module is embedded within the Linux Kernel image, it collects data from applications and exports them to the requiring MLEPlayers.
- LKM This Linux Kernel Module provides Netlink interface to the MLEPlayer, and some useful tools for debugging the solution
- patch/exec/task_struct In order to make the solution work, few patches to the original Linux Kernel are required. To be more specific, in order to track a process it needs to be easily recognized among others. The patch allow an executable tagged in its ELF header to bring this tag to its task struct, and therefore been recognized among the others. 


## Example
The example shown in this repository represents the porting of the Exein's solution to the Openwrt echo-system.
Here the specs of this example:

- Openwrt 18.06.5
- Linux Kernel 4.14.151

The repository is done such that user can easily test the solution in an emulated environment

To test the solution perform the following tasks:

 1. Download the repository
 2. make the config.exein the current openwrt configuration by using __cp config.exein .config__
 3. run the __make__ utility
 4. Run with __qemu-system-arm__

```
sudo qemu-system-arm -M virt -nographic -smp 1 -kernel bin/targets/armvirt-exein/32-glibc/openwrt-armvirt-exein-32-zImage-initramfs -append "rootwait root=/dev/vda console=ttyAMA0 loglevel=0 norandmaps" -netdev tap,ifname=tap0,id=eth0 -device virtio-net-device,netdev=eth0
```
5. after system has started, run the command for activating the MLEPlayer

```
# dmesg |grep Exein
[    0.001962] ExeinLSM - lsm is active: seed [857594974]
[    9.280018] ExeinLKM - Interface module load complete. Interface ready.
# tf-exein 857594974 /etc/exein/config-13107.ini /etc/exein/model-13107.tflite
```

