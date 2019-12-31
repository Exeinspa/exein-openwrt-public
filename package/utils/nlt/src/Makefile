PROJECT_BINARY_NAME = nlt
PROJECT_SOURCES = nlt.c


all:	$(PROJECT_BINARY_NAME)

$(PROJECT_BINARY_NAME):	$(PROJECT_SOURCES)
	@echo "CFLAGS -> $(CFLAGS)"
	@echo "LDFLAGS -> $(LDFLAGS)"
	@echo "PROJECT_BINARY_NAME -> $(PROJECT_BINARY_NAME)"
	@echo "PROJECT_SOURCES -> $(PROJECT_SOURCES)"
	@echo "LDLIBS -> $(LDLIBS)"
	@echo "--------------------------------------------------------"
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROJECT_BINARY_NAME) $(PROJECT_SOURCES) $(LDLIBS)
clean:
	rm -f $(PROJECT_BINARY_NAME)
