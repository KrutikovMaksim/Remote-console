CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lws2_32 -ladvapi32
TARGET = my.exe
SOURCE = my.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	del /F /Q $(TARGET) 2>nul || true

.PHONY: clean

