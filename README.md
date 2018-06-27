# SLAE Assignments Source Code

This repository contains the source code and build scripts for the assignments in the SecurityTube Linux Assembly Expert (SLAE) course.

Student ID: SLAE-1294

## Building assignments

Required packages are python 2, nasm, build-essential on a 32-bit Linux system. The author used a 32-bit Kali Linux VM.

In general for `program.nasm`, `build.py` will emit files like these:

* `program.elf` - fully linked ELF32 binary containing this code
* `program.raw` - raw bytes of the .text section of the ELF binary
* `shell_test.c` - a C program that invokes the shellcode directly, simulating an EIP overwrite
* `shell_test` - compiled version of the test C program

## Assignment 1: TCP Bind Shell

Run the build script with the desired listening port.

    ./build.py 4444

## Assignment 2: TCP Reverse Shell

Run the build script with the IP address and port of the remote listener. An error will be returned if either will introduce null bytes into the shellcode.

    ./build.py 127.1.1.1 4444
