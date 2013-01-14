ifndef $(CC)
CC=i686-pc-mingw32-g++
endif



#dlltool -k -d dbghelp.def -l dbghelp.a

all: w32sshot

w32sshot:  w32sshot.o W32Process.o
	$(CC) -static -o $@ $^ dbghelp.a -lpsapi -lkernel32 -lntdll
	cp w32sshot w32sshot.exe

%.o: %.cc
	$(CC) -O3 -o $@ -c $<

clean:
	rm -f *.o w32sshot
