CC = gcc
CFLAG = -fno-stack-protector -m32 -Og -z execstack -no-pie
CNAME = bankofmonsec

main: bankofmonsec.c
	$(CC) $(CFLAG) -o $(CNAME) bankofmonsec.c
