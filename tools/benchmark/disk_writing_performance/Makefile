CC = gcc
CCFLAGS = -m64 -Wall -O3

TARGET = test
OBJS = test.o
LIBS = -lpthread

all: $(TARGET) clean

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

.c.o:
	$(CC) $(CCFLAGS) -o $@ -c $^

clean:
	rm -f $(OBJS) *~

cleanall:
	rm -f $(TARGET)
