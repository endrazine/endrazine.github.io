/*
*                      CMOS DUMPER
*          Endrazine - Jonathan Brossard - jb@endrazine.com
*
*
* compiling : gcc cmosd.c -o cmosd.o
* usage : #cmosd > cmos.dump
*
*/
#include <stdio.h>
#include <unistd.h>
#include <asm/io.h>


int main ()
{
        int i;

        if (ioperm(0x70, 2, 1))   //Ask Permission (set to 1) 
        {                         //for ports 0x70 and 0x71
                perror("ioperm");
                exit (1);
        }

        for (i=0;i<64;i++)
        {
          outb(i,0x70);// Write to port 0x70
          usleep(100000);
          printf("%c",inb(0x71));

        }

        if (ioperm(0x71, 2, 0)) // We don't need Permission anymore
        {                        // (set permissions to 0).
                 perror("ioperm");
                 exit(1);
        }

        exit (0);// Quit
}

