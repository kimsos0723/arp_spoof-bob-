all: arpspoof

arpspoof: main.cpp
	g++ -o arpspoof main.cpp -lpcap

clean:
	rm -f arpspoof