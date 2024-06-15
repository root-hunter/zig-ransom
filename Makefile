build-exe:
	zig build-exe src/main.zig --name zig-ransom --build-id=sha1 -static -O ReleaseSafe
	mv zig-ransom* bin

rundev:
	cp original.txt tests/a1.txt
	zig run src/main.zig
