#include <linux/module.h>
#include <linux/net.h>
#include <linux/mm.h>

extern struct proto_ops inet_stream_ops;

static void disable_page_protection(void)
{
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (value & 0x00010000) {
		value &= ~0x00010000;
		asm volatile("mov %0,%%cr0": : "r" (value));
	}
}
static void enable_page_protection(void)
{
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (!(value & 0x00010000)) {
		value |= 0x00010000;
		asm volatile("mov %0,%%cr0": : "r" (value));
	}
}

int (*old_connect)(struct socket *sock, struct sockaddr *vaddr, int sockaddr_len, int flags);
int connect(struct socket *sock, struct sockaddr *vaddr, int sockaddr_len, int flags)
{
	printk(KERN_ALERT "Hooked connect.");
	return (*old_connect)(sock, vaddr, sockaddr_len, flags);
}
static int init(void)
{
	old_connect = inet_stream_ops.connect;
	disable_page_protection();
	inet_stream_ops.connect = connect;
	enable_page_protection();
	return 0;
}
static void exit(void)
{
	disable_page_protection();
	inet_stream_ops.connect = old_connect;
	enable_page_protection();
}
module_init(init);
module_exit(exit);


