/*
*
* Simple patch against 2.6 kernels, to prevent BIOS keyboard buffer attacks
*
* // Jonathan Brossard - jb@endrazine.com - endrazine@gmail.com
*
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>

#define BIOSKeyboardBufferPointers 0x041A
static int patch_init(void)
{

	printk("Cleaning BIOS keyboard buffer\n");

	/*
	* We use PAGE_OFFSET to determine the kernel base address
	* so that we can deal with kernels not loaded at 0xc0000000
	*/
	memset(BIOSKeyboardBufferPointers + PAGE_OFFSET, 0, 36);

	return 0;
}
static int patch_exit(void)
{
	printk("Unloading module\n");
	return 0;
}

module_init(patch_init);
module_exit(patch_exit);
