#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/socket.h>
#include <linux/sched.h>

unsigned long *syscall_table = (unsigned long *)0xffffffff818001e0;
void (*set_pages_rw)(struct page *page, int numpages) = (void *)0xffffffff8102be40;
void (*set_pages_ro)(struct page *page, int numpages) = (void *)0xffffffff8102be00;

asmlinkage long (*original_connect)(int, struct sockaddr __user *, int);
asmlinkage long new_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
	printk(KERN_ALERT "Hooked connect.");
	return (*original_connect)(fd, uservaddr, addrlen);
}
static void* set_syscall(int syscall, void *new_function)
{
	void *original;
	struct page *sys_call_page;
	sys_call_page = virt_to_page(syscall_table);
	set_pages_rw(sys_call_page, 1);
	original = (void *)syscall_table[syscall];
	syscall_table[syscall] = (unsigned long)new_function;
	set_pages_ro(sys_call_page, 1);
	return original;
}
static int init(void)
{
	original_connect = set_syscall(__NR_connect, new_connect);
	return 0;
}
static void exit(void)
{
	set_syscall(__NR_connect, original_connect);
}
module_init(init);
module_exit(exit);


