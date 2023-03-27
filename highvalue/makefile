all: highvalue.wasm highvalue-block.wasm
highvalue.wasm: highvalue.c
	wasmcc highvalue.c -o highvalue.wasm -Oz -Wl,--allow-undefined  -I../
	wasm-opt highvalue.wasm -o highvalue.wasm \
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
	hook-cleaner highvalue.wasm
	wasm-opt highvalue.wasm -o highvalue.wasm \
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
	hook-cleaner highvalue.wasm
	guard_checker highvalue.wasm
highvalue-block.wasm: highvalue-block.c
	wasmcc highvalue-block.c -o highvalue-block.wasm -Oz -Wl,--allow-undefined  -I../
	wasm-opt highvalue-block.wasm -o highvalue-block.wasm \
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
	hook-cleaner highvalue-block.wasm
	wasm-opt highvalue-block.wasm -o highvalue-block.wasm \
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
	hook-cleaner highvalue-block.wasm
	guard_checker highvalue-block.wasm
