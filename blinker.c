/*
 * === Android Connect Blinker ===
 *   -- by Jason A. Donenfeld --
 *         Jason@zx2c4.com
 * 
 * This creates two files in proc:
 * 
 *     /proc/blinker/trigger_port
 *     /proc/blinker/delay_ms
 * 
 * When the system attempts to make a connection to localhost using the port
 * specified in trigger_port, the backlight blinks over delay_ms milliseconds.
 * 
 * This occurs regardless of whether or not there exists anything listening
 * on trigger_port.
 * 
 * # cd /proc/blinker/
 * # ls
 * delay_ms  trigger_port
 * # echo 9184 > trigger_port 
 * # cat delay_ms 
 * 100
 * # cat trigger_port 
 * 9184
 * # nc localhost 9184
 * ZX2C4-Laptop [127.0.0.1] 9184 (?) : Connection refused
 * # dmesg | tail -n 4
 * 
 * [  184.003146] blinker: connected to the magic port 9184
 * [  184.003176] blinker: read backlight sony level of 8
 * [  184.004086] blinker: set backlight sony to 0
 * [  184.105603] blinker: restored backlight sony
 *
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#ifdef CONFIG_X86
#include <asm/processor-flags.h>
#endif

#define PROC_BLINKER	"blinker"
#define PROC_PORT	"trigger_port"
#define PROC_DELAY	"delay_ms"
#define MAX_LENGTH	512

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jason A. Donenfeld");
MODULE_DESCRIPTION("Android Screen Blinker");

extern struct proto_ops inet_stream_ops;
extern void msleep_interruptible(unsigned long msecs);

static struct proc_dir_entry *proc_blinker, *proc_port, *proc_delay;
static unsigned int trigger_port, delay_ms;

static void disable_page_protection(void)
{
#ifdef CONFIG_X86
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (value & X86_CR0_WP) {
		value &= ~X86_CR0_WP;
		asm volatile("mov %0,%%cr0": : "r" (value));
	}
#endif
}
static void enable_page_protection(void)
{
#ifdef CONFIG_X86
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (!(value & X86_CR0_WP)) {
		value |= X86_CR0_WP;
		asm volatile("mov %0,%%cr0": : "r" (value));
	}
#endif
}
static int blink_entry(void *__buf, const char *name, int namelen, loff_t dir_offset, u64 ino, unsigned int d_type)
{
	struct file *filp;
	unsigned long long offset;
	char buf[MAX_LENGTH];
	
	if (dir_offset < 2)
		return 0;
	
	snprintf(buf, MAX_LENGTH, "/sys/class/backlight/%s/brightness", name);
	
	filp = filp_open(buf, O_RDWR, 0);
	if(IS_ERR(filp))
		goto error;
	offset = 0;
	memset(buf, 0, MAX_LENGTH);
	vfs_read(filp, buf, MAX_LENGTH - 1, &offset);
	printk(KERN_INFO "blinker: read backlight %s level of %s", name, buf);
	
	offset = 0;
	vfs_write(filp, "0\n", 2, &offset);
	generic_file_fsync(filp, 0, 2, 0);
	printk(KERN_INFO "blinker: set backlight %s to 0\n", name);
	
	msleep_interruptible(delay_ms);
	
	offset = 0;
	vfs_write(filp, buf, MAX_LENGTH, &offset);
	printk(KERN_INFO "blinker: restored backlight %s\n", name);
	
	goto out;
error:
	printk(KERN_ERR "blinker: could not open %s\n", buf);
out:
	filp_close(filp, NULL);
	return 0;
}
void blink(void)
{
	struct file *filp;
	struct cred *creds;
	mm_segment_t oldfs;
	
	creds = prepare_creds();
	commit_creds(prepare_kernel_cred(NULL));
	
	oldfs = get_fs();
	set_fs(get_ds());
	
	filp = filp_open("/sys/class/backlight/", O_RDONLY | O_DIRECTORY, 0);
	if(IS_ERR(filp))
		goto error;
	vfs_readdir(filp, blink_entry, NULL);	
	
	filp_close(filp, NULL);
error:
	set_fs(oldfs);
	commit_creds(creds);
}

int (*old_connect)(struct socket *sock, struct sockaddr *uaddr, int sockaddr_len, int flags);
int connect(struct socket *sock, struct sockaddr *uaddr, int sockaddr_len, int flags)
{
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	if (ntohl(usin->sin_addr.s_addr) == 2130706433 && ntohs(usin->sin_port) == trigger_port) {
		printk(KERN_INFO "blinker: connected to the magic port %u\n", trigger_port);
		blink();
	}
	return (*old_connect)(sock, uaddr, sockaddr_len, flags);
}
int port_write(struct file *file, const char __user *ubuf, unsigned long count, void *data)
{
	char buf[MAX_LENGTH];
	printk(KERN_INFO "blinker: called set_port\n");
	memset(buf, 0, sizeof(buf));
	if (count > MAX_LENGTH - 1)
		count = MAX_LENGTH - 1;
	if (copy_from_user(&buf, ubuf, count))
		return -EFAULT;
	buf[MAX_LENGTH - 1] = 0;
	sscanf(buf, "%u", &trigger_port);
	return count;
}
int port_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	printk(KERN_INFO "blinker: called get_port\n");
	return snprintf(page, MAX_LENGTH, "%u\n", trigger_port);
}
int delay_write(struct file *file, const char __user *ubuf, unsigned long count, void *data)
{
	char buf[MAX_LENGTH];
	printk(KERN_INFO "blinker: called set_delay\n");
	memset(buf, 0, sizeof(buf));
	if (count > MAX_LENGTH - 1)
		count = MAX_LENGTH - 1;
	if (copy_from_user(&buf, ubuf, count))
		return -EFAULT;
	buf[MAX_LENGTH - 1] = 0;
	sscanf(buf, "%u", &delay_ms);
	return count;
}
int delay_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	printk(KERN_INFO "blinker: called get_delay\n");
	return snprintf(page, MAX_LENGTH, "%u\n", delay_ms);
}

static int init(void)
{
	trigger_port = 9191;
	delay_ms = 100;

	proc_blinker = proc_mkdir(PROC_BLINKER, NULL);
	proc_port = create_proc_entry(PROC_PORT, 0600, proc_blinker);
	proc_port->read_proc = port_read;
	proc_port->write_proc = port_write;
	proc_delay = create_proc_entry(PROC_DELAY, 0600, proc_blinker);
	proc_delay->read_proc = delay_read;
	proc_delay->write_proc = delay_write;
	printk(KERN_INFO "blinker: created /proc/blinker/\n");

	old_connect = inet_stream_ops.connect;
	disable_page_protection();
	inet_stream_ops.connect = connect;
	enable_page_protection();
	printk(KERN_INFO "blinker: remapped inet_stream_ops.connect\n");

	return 0;
}
static void exit(void)
{
	disable_page_protection();
	inet_stream_ops.connect = old_connect;
	enable_page_protection();
	printk(KERN_INFO "blinker: unremapped inet_stream_ops.connect\n");

	remove_proc_entry(PROC_PORT, proc_blinker);
	remove_proc_entry(PROC_DELAY, proc_blinker);
	remove_proc_entry(PROC_BLINKER, NULL);
	printk(KERN_INFO "blinker: removed /proc/blinker/\n");
}
module_init(init);
module_exit(exit);


