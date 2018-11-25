target=dpi

src=$(wildcard ./*.c)

obj=$(patsubst %.c, %.o, $(src))

CC=gcc

CFLAGS=-Wall -c -g 

LDFLAGS= -lpcap -g

$(target):$(obj)
	$(CC) $^ $(LDFLAGS) -o $@

%.o:%.c
	$(CC) $(CFLAGS) $< -o $@ 

clean:
	rm -rf $(obj)
	rm -rf $(target)

.PHONY:clean
