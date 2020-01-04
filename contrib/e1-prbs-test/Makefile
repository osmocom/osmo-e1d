LIBOSMO_CFLAGS:=$(shell pkg-config --cflags libosmocore)
LIBOSMO_LIBS:=$(shell pkg-config --libs libosmocore)

CFLAGS=-O2 -g -Wall -Werror $(LIBOSMO_CFLAGS)
LIBS=$(LIBOSMO_LIBS)

all: e1-prbs-test

e1-prbs-test: main.o rx.o tx.o prbs.o utils.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	@rm -f e1-prbs-test e1-prbs-test *.o
