CC=g++
CFLAGS=-c  -Wall
LIBS=-lunbound -lcrypto
LDFLAGS=
SOURCES=main.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=getopenpgpkey

.PHONY: clean


all: $(SOURCES) $(EXECUTABLE) 
	

archive:
	cd ../ && tar zcvf ${EXECUTABLE}.tar.gz getopenpgpkey && cd getopenpgpkey 

clean:
	rm -f $(EXECUTABLE) *.o

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ ${LIBS}

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@
