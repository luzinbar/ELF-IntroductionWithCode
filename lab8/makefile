all: exec

exec: task3.c task2.c task1.c
	gcc -g -m32 -Wall -o myELF3 task3.c -lm
	gcc -g -m32 -Wall -o myELF2 task2.c -lm
	gcc -g -m32 -Wall -o myELF1 task1.c -lm


.PHONY: clean
clean:
	rm -rf ./*.o myELF3 myELF2 myELF1