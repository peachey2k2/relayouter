fasm = fasm

src = main.asm

inc = macros.inc

out = app

.PHONY: all build run kill clean

all:
	$(info use `make [build] [run] [kill] [clean]` to specify.)
	$(error )

build: $(src) $(inc) Makefile
	$(info --- build ---)
	$(fasm) $(src) ./$(out)

run: build
	$(info --- run ---)
	./$(out)

kill:
	$(info --- kill ---)
	pkill -9 -x $(out) | true

clean:
	$(info --- clean ---)
	rm ./$(out)
