.PHONY: clean

GCC = gcc
GCC_OPT = -m64 -Wall -O3

TARGET = pcapReader
OBJS = pcapReader.o flowManager.o
LIBS = -lpcap
INC = -I../include

all: $(TARGET) clean

$(TARGET): $(OBJS)
	$(GCC) $(GCC_OPT) -o $@ $^ $(LIBS)

.c.o:
	$(GCC) $(GCC_OPT) -o $@ -c $^ $(INC)

clean:
	rm -f $(OBJS) *~
