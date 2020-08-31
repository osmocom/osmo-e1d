LIBOSMO_CFLAGS:=$(shell pkg-config --cflags libosmocore libosmo-e1d)
LIBOSMO_LIBS:=$(shell pkg-config --libs libosmocore libosmo-e1d)

CFLAGS=-O2 -g -Wall -Werror $(LIBOSMO_CFLAGS)
LIBS=$(LIBOSMO_LIBS)

all: e1-prbs-test ice40-e1-prbs-check

e1-prbs-test: main.o rx.o tx.o prbs.o utils.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

ice40-e1-prbs-check: ice40-rx.o rx.o prbs.o utils.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	@rm -f e1-prbs-test ice40-e1-prbs-check *.o
