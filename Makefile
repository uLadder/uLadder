cc=g++
ldflags=-lev
ccflags=-g -Wall

objects = main.o Socks5Server.o Socks5Session.o StreamBuffer.o 
3rdparty = easylogging++.o

all: a.out

a.out : $(objects) $(3rdparty)
	@echo -e "\033[31m[Linking]: $< \033[0m"
	$(cc) -o a.out $(ccflags) $(objects) $(3rdparty) $(ldflags)

$(3rdparty): ccflags-=-Wall

%.o : %.cc
	@echo -e "\033[31m[Compiling]: $< \033[0m"
	$(cc) -c -o $@ $< $(ccflags)

#main.o : main.cc
#easylogging++.o : easylogging++.h easylogging++.cc
#Socks5Server.o : Socks5Server.cc Socks5Server.h
#Socks5Session.o : Socks5Session.cc Socks5Session.h
#StreamBuffer.o : StreamBuffer.cc StreamBuffer.h

.PHONY clean :
	rm ./*.o ./a.out ./logs/*
