CC = gcc
CFLAGS = -Wall
LFLAGS = $(CFLAGS) -lpthread

all : rwwResolver rwwMultithreadedDNS rwwDNS

rwwResolver : resolve.c resolve.h dns_1.h
	$(CC) $(CFLAGS) resolve.c -o rwwResolver

rwwMultithreadedDNS : ricksMultithreadedDNS.c ricksMultithreadedDNS.h triez.c triez.h structs.h sharedFunctions.c sharedFunctions.h dns_1.h
	$(CC) $(LFLAGS) ricksMultithreadedDNS.c -o rwwMultithreadedDNS
	
rwwDNS : ricksDNS.c triez.c triez.h structs.h sharedFunctions.c sharedFunctions.h dns_1.h
	$(CC) $(CFLAGS) ricksDNS.c -o rwwDNS
clean : 
	$(RM) rwwResolver rwwMultithreadedDNS rwwDNS

