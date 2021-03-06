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

## Assignment 3: Egghunter

Run the build script with the raw text of an egg script. It will output both the hunter shellcode and the egg shellcode with the appropriate header appended.

    ./build.py ../a1-bind/bind.raw

## Assignment 4: Coder/Decoder

Some unencoded payload is required to build this, as it will be included in encoded form inside the decoder. For testing I have created a separate shellcode under `/execve-stack-shell`. Build it:

    ./build.py

This will produce a `shell.raw` file containing the assembled code.

Then inside `/a4-coder`:

    ./build.py ../execve-stack-shell/shell.raw

The build script will encode shell.raw and embed it in the assembled product.

## Assignment 5: Analysis of MSF payloads

There is nothing to build here. The .raw files and passwd file mentioned in the analysis blog post are kept here for reference.

## Assignment 6: Shellcode polymorphism

There is some miscellaneous stuff about the original shellcodes from shell-storm in the *-original folders. The *-poly folders contain my reworked version of each. No parameters are required for any of these.

      ./build.py

* nc: Creates a bind shell by invoking /bin/nc with suitable parameters
* shadow: Uses a chmod syscall to set /etc/shadow to 0666 permissions
* iptables: Invokes iptables -F to clear firewall rules

## Assignment 7: Crypter and decrypter

This one has two programs, `crypter` and `decrypter`. The shellcode to be encrypted must be prepared separately. For example, to use the execve-stack-shell shellcode and the password `abcdef` run these commands:

     ./build_crypter.sh
     cat ../execve-stack-shell/shell.raw | ./crypter abcdef | tee encrypted.h
     ./build_decrypter.sh

This will build the decrypter with the encrypted shellcode inside it, via the `encrypted.h` header. It can be run by passing the chosen password as a command line parameter:

     ./decrypter abcdef


