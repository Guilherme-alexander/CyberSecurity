FILES = ./build/kernel.asm.o ./build/kernel.o
FLAGS = -g -ffreestanding -nostdlib -nostartfiles -nodefaultlibs -Wall -O0 -Iinc

all:
	nasm -f bin ./src/boot.asm -o ./bin/boot.bin
	nasm -f elf -g ./src/kernel.asm -o ./build/kernel.asm.o
	i686-elf-gcc $(FLAGS) -std=gnu99 -c ./src/kernel.c -o ./build/kernel.o
	i686-elf-ld -g -relocatable $(FILES) -o ./build/completeKernel.o
	i686-elf-gcc $(FLAGS) -T ./src/linkScript.ld -o ./bin/kernel.bin -ffreestanding -O0 -nostdlib ./build/completeKernel.o

	dd if=./bin/boot.bin > ./bin/os.bin
	dd if=./bin/kernel.bin >> ./bin/os.bin
	dd if=/dev/zero bs=512 count=8 >> ./bin/os.bin

clean:
	rm -f ./bin/boot.bin ./bin/kernel.bin ./bin/os.bin
	rm -f ./build/kernel.asm.o ./build/kernel.o ./build/completeKernel.o
