CC=i686-pc-mingw32-g++

all: w32sshot

w32sshot:  w32sshot.o W32Process.o
	$(CC) -static -o $@ $^ -lpsapi -lkernel32

%.o: %.cc
	$(CC) -O3 -o $@ -c $<

clean:
	rm -f *.o w32sshot
