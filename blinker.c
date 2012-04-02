#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>


#define PROC_BLINKER_PORT	"blinker_port"
#define MAX_LENGTH		16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jason A. Donenfeld");
MODULE_DESCRIPTION("Android Screen Blinker");

extern struct proto_ops inet_stream_ops;

static struct proc_dir_entry *proc_blinker_port;
static unsigned int port;

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
	if (ntohl(usin->sin_addr.s_addr) == 2130706433 && ntohs(usin->sin_port) == port) {
		printk(KERN_INFO "blinker: connected to the magic port %u\n", port);
		//TODO: blink the screen
	}
	return (*old_connect)(sock, uaddr, sockaddr_len, flags);
}
int set_port(struct file *file, const char __user *ubuf, unsigned long count, void *data)
{
	char buf[MAX_LENGTH];
	printk(KERN_INFO "blinker: called set_port\n");
	memset(buf, 0, sizeof(buf));
	if (count > MAX_LENGTH)
		count = MAX_LENGTH;
	if (copy_from_user(&buf, ubuf, count))
		return -EFAULT;
	sscanf(buf, "%u", &port);
	return count;
}

int get_port(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	char buf[MAX_LENGTH];
	int len;
	printk(KERN_INFO "blinker: called get_port\n");
	len = snprintf(buf, MAX_LENGTH, "%u\n", port);
	memcpy(page, buf, len);
	return len;
}
static int init(void)
{
	proc_blinker_port = create_proc_entry(PROC_BLINKER_PORT, 0666, NULL);
	proc_blinker_port->read_proc = get_port;
	proc_blinker_port->write_proc = set_port;
	printk(KERN_INFO "blinker: created /proc/blinker_port\n");

	old_connect = inet_stream_ops.connect;
	disable_page_protection();
	inet_stream_ops.connect = connect;
	enable_page_protection();
	printk(KERN_INFO "blinker: remapped inet_stream_ops.connect\n");

	port = 9191;

	return 0;
}
static void exit(void)
{
	disable_page_protection();
	inet_stream_ops.connect = old_connect;
	enable_page_protection();
	printk(KERN_INFO "blinker: unremapped inet_stream_ops.connect\n");

	remove_proc_entry(PROC_BLINKER_PORT, proc_blinker_port);
	printk(KERN_INFO "blinker: removed /proc/blinker_port\n");
}
module_init(init);
module_exit(exit);


