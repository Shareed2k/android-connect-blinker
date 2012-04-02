/*
 * === Android Connect Blinker ===
 *   -- by Jason A. Donenfeld --
 *         Jason@zx2c4.com
 * 
 * This creates two files in proc:
 * 
 *     /proc/blinker/trigger_port
 *     /proc/blinker/backlight_file
 * 
 * When the system attempts to make a connection to localhost using the port
 * specified in trigger_port, backlight_file is used to blink the backlight.
 * 
 * This occurs regardless of whether or not there exists anything listening
 * on trigger_port.
 * 
 * # cd /proc/blinker/
 * # ls
 * backlight_file  trigger_port
 * # echo 9184 > trigger_port 
 * # cat backlight_file 
 * /sys/class/backlight/s5p_bl/brightness
 * # cat trigger_port 
 * 9184
 * # nc localhost 9184
 * ZX2C4-Laptop [127.0.0.1] 9184 (?) : Connection refused
 * # dmesg | tail -n 1
 * [  789.250531] blinker: connected to the magic port 9184
 *
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>


#define PROC_BLINKER	"blinker"
#define PROC_PORT	"trigger_port"
#define PROC_FILE	"backlight_file"
#define MAX_LENGTH	512

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jason A. Donenfeld");
MODULE_DESCRIPTION("Android Screen Blinker");

extern struct proto_ops inet_stream_ops;

static struct proc_dir_entry *proc_blinker;
static struct proc_dir_entry *proc_port;
static struct proc_dir_entry *proc_file;
static unsigned int trigger_port;
static unsigned char backlight_file[MAX_LENGTH];

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
	if (ntohl(usin->sin_addr.s_addr) == 2130706433 && ntohs(usin->sin_port) == trigger_port) {
		printk(KERN_INFO "blinker: connected to the magic port %u\n", trigger_port);
		//TODO: blink the screen
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
int file_write(struct file *file, const char __user *ubuf, unsigned long count, void *data)
{
	char buf[MAX_LENGTH];
	char *line;
	printk(KERN_INFO "blinker: called set_file\n");
	if (count > MAX_LENGTH - 1)
		count = MAX_LENGTH - 1;
	if (copy_from_user(&buf, ubuf, count))
		return -EFAULT;
	buf[count + 1] = 0;
	line = strchr(buf, '\n');
	if (line)
		*line = 0;
	memcpy(backlight_file, buf, sizeof(backlight_file));
	return count;
}

int file_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	printk(KERN_INFO "blinker: called get_file\n");
	return snprintf(page, MAX_LENGTH, "%s\n", backlight_file);
}
static int init(void)
{
	proc_blinker = proc_mkdir(PROC_BLINKER, NULL);
	proc_port = create_proc_entry(PROC_PORT, 0600, proc_blinker);
	proc_port->read_proc = port_read;
	proc_port->write_proc = port_write;
	proc_file = create_proc_entry(PROC_FILE, 0600, proc_blinker);
	proc_file->read_proc = file_read;
	proc_file->write_proc = file_write;
	printk(KERN_INFO "blinker: created /proc/blinker/\n");

	old_connect = inet_stream_ops.connect;
	disable_page_protection();
	inet_stream_ops.connect = connect;
	enable_page_protection();
	printk(KERN_INFO "blinker: remapped inet_stream_ops.connect\n");

	trigger_port = 9191;
	strcpy(backlight_file, "/sys/class/backlight/s5p_bl/brightness");

	return 0;
}
static void exit(void)
{
	disable_page_protection();
	inet_stream_ops.connect = old_connect;
	enable_page_protection();
	printk(KERN_INFO "blinker: unremapped inet_stream_ops.connect\n");

	remove_proc_entry(PROC_PORT, proc_blinker);
	remove_proc_entry(PROC_FILE, proc_blinker);
	remove_proc_entry(PROC_BLINKER, NULL);
	printk(KERN_INFO "blinker: removed /proc/blinker/\n");
}
module_init(init);
module_exit(exit);


