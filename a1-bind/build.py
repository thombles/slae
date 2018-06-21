#!/usr/bin/python

TARGET="bind"
DESCRIPTION="TCP bind shellcode"

import sys
import os
import socket

if len(sys.argv) != 2:
    print "Usage: %s <port>" % sys.argv[0]
    sys.exit(1)

port = int(sys.argv[1])
if port < 0 or port > 65535:
    print "Invalid port number. Must be a number 0-65535."
    sys.exit(1)
    
print "Building %s on port %d" % (DESCRIPTION, port)

print "Assembling..."
r = os.system("nasm -f elf32 -o %s.o -DLISTEN_PORT=%d %s.nasm" % (TARGET, socket.htons(port), TARGET))
if r != 0:
    print "nasm returned error"
    sys.exit(1)
    
print "Linking to %s.elf..." % TARGET
r = os.system("ld %s.o -o %s.elf" % (TARGET, TARGET))
if r != 0:
    print "ld returned error"
    sys.exit(1)

print "Extracting raw shellcode to %s.raw..." % TARGET
os.system("objcopy -j .text -O binary %s.elf %s.raw" % (TARGET, TARGET))

print "\nC format:\n"
os.system("hexdump -ve '1/1 \"\\\\x%%.2x\"' %s.raw" % TARGET)

print "\n\nnasm format:\n"
os.system("hexdump -ve '1/1 \"0x%%.2x,\"' %s.raw | sed -e 's/,$//'" % TARGET)

print "\n"
with open("%s.raw" % TARGET, mode='rb') as f:
    raw = f.read()
    if "\x00" in raw:
        print "Null byte is present!"
    else:
        print "No nulls"
