all: bof

bof:
	@(echo '[+] Building BOF')
	@(x86_64-w64-mingw32-gcc -Os -s -c -Iinclude -o bin/finduserhooks.x64.o src/main.c && x86_64-w64-mingw32-strip --strip-unneeded bin/finduserhooks.x64.o) && echo '[+] Done'  || echo '[!] Error'

clean:
	@(rm ./bin/*.o)