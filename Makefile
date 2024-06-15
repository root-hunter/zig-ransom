build-exe:
	echo "TODO"

rundev:
	#cp original.txt tests/a1.txt
	zig run src/main.zig

test:
	zig test src/main.zig