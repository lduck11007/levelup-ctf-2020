#
# -fno-stack-protector | Turn off stack smash detection overhead.
# -m32 | Make the binary 32-bit (easier to pwn)
# -0g | Turn off optimisation, makes the assembly more predicatable (good for debugging)
# -z execstack | Allows code on the stack to be executed (aka allows shellcode)
# -no-pie | Turns off PIE (advanced memory protection that makes it really hard to do anything).
#

CC = gcc
CFLAG = -fno-stack-protector -m32 -Og -z execstack -no-pie
CNAME = challenge

challenge: challenge.c
	$(CC) $(CFLAG) -o $(CNAME) challenge.c