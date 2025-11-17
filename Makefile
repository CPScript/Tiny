CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -O2
DEBUGFLAGS = -g -fsanitize=address -fsanitize=undefined
TARGET = tiny
SRC = main.c

.PHONY: all clean debug run test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

debug: $(SRC)
	$(CC) $(CFLAGS) $(DEBUGFLAGS) -o $(TARGET) $(SRC)

run: $(TARGET)
	./$(TARGET)

test: debug
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)
