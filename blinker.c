/*
 * === Android Connect Blinker ===
 *   -- by Jason A. Donenfeld --
 *         Jason@zx2c4.com
 * 
 * This creates three files in proc:
 * 
 *     /proc/blinker/trigger_port
 *     /proc/blinker/backlight_file
 *     /proc/blinker/delay_ms
 * 
 * When the system attempts to make a connection to localhost using the port
 * specified in trigger_port, backlight_file is used to blink the backlight
 * for delay_ms milliseconds.
 * 
 * This occurs regardless of whether or not there exists anything listening
 * on trigger_port.
 * 
 * # cd /proc/blinker/
 * # ls
 * backlight_file  delay_ms  trigger_port
 * # echo 9184 > trigger_port 
 * # cat backlight_file 
 * /sys/class/backlight/s5p_bl/brightness
 * # cat delay_ms 
 * 100
 * # cat trigger_port 
 * 9184
 * # nc localhost 9184
 * ZX2C4-Laptop [127.0.0.1] 9184 (?) : Connection refused
 * # dmesg | tail -n 4
 * [  910.109435] blinker: connected to the magic port 9184
 * [  910.109466] blinker: read backlight level of 8
 * [  910.110363] blinker: set backlight to 0
 * [  910.212381] blinker: restored backlight
 * 
 * Development note:
 *     Though this is intended to work on Android/ARM, presently it is only
 *     implemented on x86. Work in progress.
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


#define PROC_BLINKER	"blinker"
#define PROC_PORT	"trigger_port"
#define PROC_FILE	"backlight_file"
#define PROC_DELAY	"delay_ms"
#define MAX_LENGTH	512

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jason A. Donenfeld");
MODULE_DESCRIPTION("Android Screen Blinker");

extern struct proto_ops inet_stream_ops;
extern void msleep_interruptible(unsigned long msecs);

static struct proc_dir_entry *proc_blinker, *proc_port, *proc_file, *proc_delay;
static unsigned int trigger_port, delay_ms;
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

void blink(void)
{
	struct file *filp;
	struct cred *creds;
	mm_segment_t oldfs;
	unsigned long long offset;
	char buf[MAX_LENGTH];
	unsigned long previous_backlight;
	
	creds = prepare_creds();
	commit_creds(prepare_kernel_cred(NULL));
	
	oldfs = get_fs();
	set_fs(get_ds());
	
	filp = filp_open(backlight_file, O_RDWR, 0);
	if(IS_ERR(filp))
		goto error;
	offset = 0;
	vfs_read(filp, buf, MAX_LENGTH - 1, &offset);
	buf[MAX_LENGTH - 1] = 0;
	sscanf(buf, "%lu", &previous_backlight);
	printk(KERN_INFO "blinker: read backlight level of %lu", previous_backlight);
	
	offset = 0;
	vfs_write(filp, "0\n", 2, &offset);
	generic_file_fsync(filp, 0, 2, 0);
	printk(KERN_INFO "blinker: set backlight to 0\n");
	
	msleep_interruptible(delay_ms);
	
	snprintf(buf, MAX_LENGTH, "%lu\n", previous_backlight);
	offset = 0;
	vfs_write(filp, buf, MAX_LENGTH, &offset);
	printk(KERN_INFO "blinker: restored backlight\n");
	
	filp_close(filp, NULL);
	
	goto out;
	
error:
	printk(KERN_ERR "blinker: could not work with %s, error %ld\n", backlight_file, PTR_ERR(filp));
out:
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
	proc_blinker = proc_mkdir(PROC_BLINKER, NULL);
	proc_port = create_proc_entry(PROC_PORT, 0600, proc_blinker);
	proc_port->read_proc = port_read;
	proc_port->write_proc = port_write;
	proc_file = create_proc_entry(PROC_FILE, 0600, proc_blinker);
	proc_file->read_proc = file_read;
	proc_file->write_proc = file_write;
	proc_delay = create_proc_entry(PROC_DELAY, 0600, proc_blinker);
	proc_delay->read_proc = delay_read;
	proc_delay->write_proc = delay_write;
	printk(KERN_INFO "blinker: created /proc/blinker/\n");

	old_connect = inet_stream_ops.connect;
	disable_page_protection();
	inet_stream_ops.connect = connect;
	enable_page_protection();
	printk(KERN_INFO "blinker: remapped inet_stream_ops.connect\n");

	trigger_port = 9191;
	delay_ms = 100;
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
	remove_proc_entry(PROC_DELAY, proc_blinker);
	remove_proc_entry(PROC_BLINKER, NULL);
	printk(KERN_INFO "blinker: removed /proc/blinker/\n");
}
module_init(init);
module_exit(exit);


