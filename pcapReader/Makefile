.PHONY: clean

GCC = gcc
GCC_OPT = -m64 -Wall -O3

TARGET = pcapReader
OBJS = pcapReader.o
LIBS = -lpcap

all: $(TARGET) clean

$(TARGET): $(OBJS)
	$(GCC) $(GCC_OPT) -o $@ $^ $(LIBS)

.c.o:
	$(GCC) $(GCC_OPT) -o $@ -c $^

clean:
	rm -f $(OBJS) *~

cleanall:
	rm -f $(TARGET)
