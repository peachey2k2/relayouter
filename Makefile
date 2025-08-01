fasm = fasm

src = src/main.asm

inc = \
	src/header.inc \
	src/data.inc \
	src/glibc_consts.inc \
	src/macros.inc \

out = relayouter

.PHONY: all build run kill clean

all:
	$(info use `make [build] [run] [kill] [clean]` to specify.)
	$(error )

build: $(out)

$(out): $(src) $(inc) Makefile
	$(info --- build ---)
	$(fasm) $(src) ./$(out)
	chmod +x ./$(out)

run: build
	$(info --- run ---)
	./$(out)

kill:
	$(info --- kill ---)
	pkill -9 -x $(out) | true

clean:
	$(info --- clean ---)
	rm ./$(out)
