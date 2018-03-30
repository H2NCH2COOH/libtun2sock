all:
	gcc -std=c99 -Wall -Wextra -O2 *.c -o tun10

clean:
	-rm -f *.o tun10
