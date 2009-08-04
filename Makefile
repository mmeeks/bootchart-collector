CC = gcc
CFLAGS = -g -Wall -Os

all: bootchart-collector

bootchart-collector: bootchart-collector.o
	$(CC) -o $@ $<

clean:
	-rm -f *.o bootchart-collector

dist:
	bzr export bootchart-collector-0.90.2.tar.bz2
