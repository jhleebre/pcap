.PHONY: clean

CC = gcc
CCFLAGS = -m64 -Wall -O3

TARGET = main
OBJS = main.o
LIBS = -lpcap

all: $(TARGET) clean

$(TARGET): $(OBJS)
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS)

.c.o:
	$(CC) $(CCFLAGS) -o $@ -c $^

clean:
	rm -f $(OBJS) *~
