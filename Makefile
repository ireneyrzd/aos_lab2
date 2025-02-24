# Compiler
CC = gcc

# gcc -o myfs -D_FILE_OFFSET_BITS=64 *.c $(pkg-config --cflags --libs fuse)

# Flags
CFLAGS = -D_FILE_OFFSET_BITS=64
LDFLAGS = -L/usr/lib/x86_64-linux-gnu -lfuse -pthread

# Source files 
SRCS = $(wildcard *.c)

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
EXEC = myfs

# Default target
all: $(EXEC)

# Link object files to create the executable
$(EXEC): $(OBJS)
	$(CC) $(OBJS) -o $(EXEC) $(LDFLAGS)

# Compile source files to object files
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

# Run the executable
run: all
	./$(EXEC) test test1

# Clean up build files
clean:
	rm -f $(OBJS) $(EXEC)

.PHONY: all clean run
