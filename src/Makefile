# Include directory
IDIR = ../include

# Compiler
CC = gcc

# Compiler flags to include the header files
CFLAGS = -I$(IDIR) -I/usr/include/curl -Wall -g -fsanitize=address
LDFLAGS = -lcjson -lcurl -fsanitize=address

# Object directory
ODIR = obj

# Header files
_DEPS = ytube_controller.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

# Object files
_OBJ = main.o ytube_controller_func.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

# Compile source files to object files
$(ODIR)/%.o: %.c $(DEPS)
	@mkdir -p $(ODIR)
	$(CC) -c -o $@ $< $(CFLAGS)

# Link object files to create the executable
main: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

# Clean target to remove object files and other temporary files
.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(IDIR)/*~
