;
; Endrazine // Jonathan Brossard // jb@endrazine.com
;
; zero 36 bytes, starting at address 0x40:0x1a

       xor ah, ah
       mov al, 0x40
       mov ds, ax
       mov al, 0x1a
       mov si, ax
       mov cx, 0x24

        xor al,al

cleanall:
        mov [ds:si], ax
        loop cleanall
