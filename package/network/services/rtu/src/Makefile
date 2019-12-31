PROJECT_BINARY_NAME = rtu
PROJECT_SOURCES = rtu.c


all:	$(PROJECT_BINARY_NAME)

$(PROJECT_BINARY_NAME):	$(PROJECT_SOURCES)
	@echo "CFLAGS -> $(CFLAGS)"
	@echo "LDFLAGS -> $(LDFLAGS)"
	@echo "PROJECT_BINARY_NAME -> $(PROJECT_BINARY_NAME)"
	@echo "PROJECT_SOURCES -> $(PROJECT_SOURCES)"
	@echo "LDLIBS -> $(LDLIBS)"
	@echo "TARGET_PIPPO -> $(TARGET_PIPPO)"
	@echo "--------------------------------------------------------"
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROJECT_BINARY_NAME) $(PROJECT_SOURCES) $(LDLIBS) -fno-stack-protector -z execstack $(TARGET_PIPPO)
	@echo 1111 > exein
	$(OBJCOPY) --add-section .exein=exein --set-section-flags .exein=noload,readonly  $(PROJECT_BINARY_NAME)
	rm exein

clean:
	rm -f $(PROJECT_BINARY_NAME)
