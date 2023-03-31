all:
	wasmcc firewall.c -o firewall.wasm -Oz -Wl,--allow-undefined  -I../
	wasm-opt firewall.wasm -o firewall.wasm \
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
	hook-cleaner firewall.wasm
	wasm-opt firewall.wasm -o firewall.wasm \
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
	hook-cleaner firewall.wasm
	guard_checker firewall.wasm
