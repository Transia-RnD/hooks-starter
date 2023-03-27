all:
	wasmcc savings.c -o savings.wasm -Oz -Wl,--allow-undefined  -I../
	wasm-opt savings.wasm -o savings.wasm \
	    --shrink-level=100000000 \
	    --coalesce-locals-learning \
	    --vacuum \
	    --merge-blocks \
	    --merge-locals \
	    --flatten \
	    --ignore-implicit-traps \
	    -ffm \
	    --const-hoisting \
	    --code-folding \
	    --code-pushing \
	    --dae-optimizing \
	    --dce \
	    --simplify-globals-optimizing \
	    --simplify-locals-nonesting \
	    --reorder-locals \
	    --rereloop \
	    --precompute-propagate \
	    --local-cse \
	    --remove-unused-brs \
	    --memory-packing \
	    -c \
	    --avoid-reinterprets \
	    -Oz
	hook-cleaner savings.wasm
	wasm-opt savings.wasm -o savings.wasm \
	    --shrink-level=100000000 \
	    --coalesce-locals-learning \
	    --vacuum \
	    --merge-blocks \
	    --merge-locals \
	    --flatten \
	    --ignore-implicit-traps \
	    -ffm \
	    --const-hoisting \
	    --code-folding \
	    --code-pushing \
	    --dae-optimizing \
	    --dce \
	    --simplify-globals-optimizing \
	    --simplify-locals-nonesting \
	    --reorder-locals \
	    --rereloop \
	    --precompute-propagate \
	    --local-cse \
	    --remove-unused-brs \
	    --memory-packing \
	    -c \
	    --avoid-reinterprets \
	    -Oz
	hook-cleaner savings.wasm
	guard_checker savings.wasm
