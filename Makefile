LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread -lm -lunicorn
CFLAGS += -g

all: unicorn_test
%: %.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@