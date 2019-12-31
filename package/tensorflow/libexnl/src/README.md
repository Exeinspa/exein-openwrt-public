## libexnl

This library is intended to be used for interfacing the machine learning engine with the kernel infrastructure.
The function exports four functions:
-  **exein_agent_start**: starts the agent, perform the registration for a particular **tag**, keeps it alive, and collects the data flowing from kernel.
- **exein_agent_stop**: deallocates all the structure needed by *exein_agent_start* and stops all the processes spawned needed by it.
- **exein_fetch_data**: returns to the user the hooks buffer data.
- **exein_block_process**: sends a message to the kernel to make a process to be not trusted anymore.
- **exein_janitor**: perform daily cleaning, removing all data came from processes died during computation.

The default circular buffer, used by *exein_agent_start*, is sizeed 32 positions, but it is possible to make it wider, defining **BUFFER64** or **BUFFER128** which change the buffer size respectively to 64 and 128 positions. 

**exein_agent_start** takes two arguments:

 - **key**: it is the per build key that kernel needs as proof that message is authorized. In the debug version of the LSM, this number can be obtained by *cat /proc/exein/rndkey*. In the non-debug version, the key can be only taken from the generated code in the file *security/exein/exein_nn_def.h*, the symbol is **SEEDRND**.
 - **tag**: indicates the process class the client wants to receive feed of.

 The returning value is a pointer to the following structure:
```
typedef struct {
	struct sockaddr_nl	*src_addr, *dest_addr;
	struct msghdr		*msg_rf, *msg_sk;
	struct nlmsghdr		*nlh_rf, *nlh_sk;
	exein_buffers		*data;
	int			sock_fd;
	void			*sk_stack, *rf_stack;
	pid_t			sk_pid, rf_pid, cpid;
	int			trouble;
} exein_shandle;
```
The handle *exein_agent_start* returns have to been used to terminate the agent together with *exein_agent_stop* in order to interrupt the operation that it started.

During the agent  usage it comes handy to have an indication of which and when new processes come into the arena and when they are going away. This is why **exein_new_pid_notify_cb**  and **exein_removed_pid_notify_cb** are there.  The symbols define the call back functions that are invoked each time a new pid come in or goes away. If not defined in the user's context, the callback are just not invoked.

Lastly, the function **exein_block_process** must be used to send messages to the kernel if blocking a particular process is needed.

**exein_fetch_data** is meant to bring to user context the hooks collected data for analysis.

