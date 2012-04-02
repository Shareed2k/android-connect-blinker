#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>

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

int (*old_connect)(struct socket *sock, struct sockaddr *uaddr, int sockaddr_len, int flags);
int connect(struct socket *sock, struct sockaddr *uaddr, int sockaddr_len, int flags)
{
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	unsigned char bytes[4];
	bytes[0] = (usin->sin_addr.s_addr >> 0) & 0xFF;
	bytes[1] = (usin->sin_addr.s_addr >> 8) & 0xFF;
	bytes[2] = (usin->sin_addr.s_addr >> 16) & 0xFF;
	bytes[3] = (usin->sin_addr.s_addr >> 24) & 0xFF;
	printk(KERN_ALERT "Hooked connect to: %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
	return (*old_connect)(sock, uaddr, sockaddr_len, flags);
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


