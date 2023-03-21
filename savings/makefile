all:
	wasmcc savings.c -o savings.wasm -Oz -Wl,--allow-undefined  -I../ 
	hook-cleaner savings.wasm
	wasm-opt -Oz savings.wasm
	hook-cleaner savings.wasm
	guard_checker savings.wasm
