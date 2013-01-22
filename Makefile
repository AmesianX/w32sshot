ifndef $(CC)
CPP=i686-pc-mingw32-g++
CC=i686-pc-mingw32-gcc

endif



#dlltool -k -d dbghelp.def -l dbghelp.a

all: w32sshot slurp.dll fake_7z

fake_7z: fake_7z.o
	$(CC) -o $@ $<

w32sshot:  w32sshot.o W32Process.o
	$(CPP) -static -o $@ $^ dbghelp.a -lpsapi -lkernel32 -lntdll
	cp w32sshot w32sshot.exe

slurp.dll: slurp.o
	$(CC) -shared -o $@ $^ -lpsapi -lkernel32 -lntdll -Wl,--output-def,slurp.def,--out-implib,slurp.a

%.o: %.cc
	$(CPP)  -O3 -o $@ -c $<

%.o: %.c
	$(CC) -O3 -shared -o $@ -c $<

clean:
	rm -f *.o w32sshot
