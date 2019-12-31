# Exein


Exein framework's goal is to accomplish the task of protecting the target system from undesirable behavior, introducing the self-protecting and remote-monitoring set of tools into the embedded systems arena.

![splash](/imgs/splash.jpg)

The natural position of a piece of software providing **Run-time anomaly detection** features is within the Linux kernel using the Linux Security Module ecosystem.

The task of analyzing the system behavior enumerating system's event is divided into three macro functions:

- Collecting event at OS level (**LSM Exein**)
- Providing a mean of communication between kernel space  section and the userspace applications (**Exein_interface**)
- Analyzing them using machine learning algorithms (**MLEPlayer**)

The **LSM Exein** is the part of the Exein solution which interfaces with the Linux kernel and exports the system events data to the userspace application module for the analysis. Its main functions are:

- Interfacing with the Linux Kernel
- Collecting the events flows
- Enforcing policies dictated by the *MLEPlayer*

The **Exein_interface** is the glue that makes it possible for the userspace MLEPlayer to communicate with the *LSM Exein*. It accomplishes this task by defining a new protocol within the Linux Netlink stack. It also provides userspace tools for debugging purposes.

The next part of the list is the code part where the actual computation is performed by the machine learning algorithms.  The code block element is called **MLEPlayer**.

The **MLEPlayer** embodies the following functions:

- Receives data from the *Exein_interface*
- Sends policies to the *Exein_interface*
- Triggers the machine learning algorithm on the supplied data


![design](/imgs/exein.png)


## User space
- libexnl: the library implements the NetLink agent in charge for collecting data, registers the application to the kernel and keeps this registration active. It also provides functions for fetching data and pushing policies.
- MLEPlayer: Using Tensorflow 2.0.0 it performs the actual computation, tracking the target application behavior.


## Kernel
- LSM: this module is embedded within the Linux Kernel image, it collects data from applications and exports them to the requiring MLEPlayers.
- LKM: This Linux Kernel Module provides Netlink interface to the MLEPlayer, and some useful tools for debugging the solution.
- patch/exec/task_struct: In order to make the solution work, few patches to the original Linux Kernel are required. To be more specific, in order to track a process it needs to be easily recognized among others. The patch allows an executable tagged in its ELF header to bring this tag to its task struct, and therefore to be recognized among the others. 


## Example
The example shown in this repository represents the porting of the Exein's solution to the Openwrt ecosystem.  
Exact versions in use are:

- Openwrt 18.06.5
- Linux Kernel 4.14.151

Users can easily test the solution in an emulated environment by following these steps:

 1. Download the repository
 2. Make the config.exein the current openwrt configuration by using __cp config.exein .config__
 3. Run the __make__ utility
 4. Run with __qemu-system-arm__ by issuing the following command

```
sudo qemu-system-arm -M virt -nographic -smp 1 -kernel bin/targets/armvirt-exein/32-glibc/openwrt-armvirt-exein-32-zImage-initramfs -append "rootwait root=/dev/vda console=ttyAMA0 loglevel=0 norandmaps" -netdev tap,ifname=tap0,id=eth0 -device virtio-net-device,netdev=eth0
```
5. After the system has started, activate the MLEPlayer by issuing the following

```
# dmesg |grep Exein
[    0.001962] ExeinLSM - lsm is active: seed [857594974]
[    9.280018] ExeinLKM - Interface module load complete. Interface ready.
# tf-exein 857594974 /etc/exein/config-13107.ini /etc/exein/model-13107.tflite
```

## Test an Exein protected application

To make you taste how an Exein protected application performs, this repo has been equipped with the OpenWrt HTTP server behavior model.  

Worth to note that the HTTP root directory also includes a trojan CGI-script located at `http://192.168.1.1/cgi-bin/vuln.cgi` which lets an attacker obtain a reverse shell to `TCP:192.168.1.2:4919`.  

During the test you should observe that regular traffic to the server is allowed, whereas the anomal behavior of an HTTP server instance acting as a shell is detected and terminated.  

Looking at the MLEPlayer output, you should see something like the following:

```
Starting Exein monitoring for tag: 13107
libexnl staring up
Now checking pid 835
INFO: Initialized TensorFlow Lite runtime.
Now checking pid 4432
Now checking pid 4438
Removing pid 4432
Now checking pid 4463
Removing pid 4463
Now checking pid 4481
Block process: 4438
Removing pid 4438
Removing pid 4481
```

Here's a brief description of most meaningful parts:  

- The first line __Starting Exein monitoring for tag: 13107__ indicates that the MLEPlayer instance is watching at the tag 13107, the tag assigned to the HTTP server.  

Tags are a central concept of the Exein framework. They act as classifiers and let the Exein framework identify the target processes and their children. 
Tags are basically 16-bits identifiers that are embedded into executables by adding a section within the ELF header ad are checked every time the executable is ran.

- As traffic to the server starts, one by one, the HTTP server processes are added to the watchlist.

__Now checking pid 835__ notifies the process 835 was added to the watchlist.

- As soon as anomalies are detected, the MLEPlayer acts asking the LSM to take action against the abnormal process (see __Block process: 4438__ message).

