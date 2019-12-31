CC=gcc
NAME=NetlinkClient

$(NAME): nlf.c
	$(CC) -o $@ $^

.PHONY: clean

clean:
	$(RM) -f $(NAME)
