# ----------- commands
CC=gcc
AR=ar
RM=rm
MD=mkdir

# ----------- Directories
IDIR =./include
ODIR=build
LDIR=./lib
BIN=./bin
# ----------- Flags
LIBS=-lexnl
CFLAGS=-I$(IDIR) -L$(LDIR)
DEBUGSYM=-g
# ----------- sources
LIBNAME=libexnl

#gcc -fPIC -shared -o libexnl.so libexnl.c && gcc -L. -o testexnl testexnl.c  -lexnl && LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH ./testexnl


$(LIBNAME): $(LIBNAME).c
	$(MD) -p $(ODIR)
	$(MD) -p $(LDIR)
	$(CC) $(DEBUGSYM) -fPIC -c -o $(ODIR)/$@.o $^
	$(CC) -shared -o $(LDIR)/$@.so $(ODIR)/$@.o

samples: examples/testexnl.c examples/block.c
	mkdir -p bin
	$(CC) $(DEBUGSYM) -o $(BIN)/testexnl examples/testexnl.c $(CFLAGS) $(LIBS)
	$(CC) $(DEBUGSYM) -o $(BIN)/block examples/block.c $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	$(RM) -rf $(ODIR)
	$(RM) -rf $(LDIR)
	$(RM) -f $(TEST)
	$(RM) -rf $(BIN)
