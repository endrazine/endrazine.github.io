/*
*                       Reset CMOS
*           Endrazine - Jonathan Brossard - jb@endrazine.com
*/
#
#include <stdio.h>
#include <unistd.h>
#include <sys/io.h>


int main ()
{
        ioperm(0x70, 1, 1);   //Ask Permission (set to 1) 
        ioperm(0x71, 1, 1);

          outb(0x2e,0x70);// Write to port 0x70
          usleep(100000);
          outb(0xff,0x71);  

        if (ioperm(0x70, 3, 0))
        {
                 perror("ioperm");
                 exit(1);
        }
        exit (0);// Quit
}

