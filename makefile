CC=g++
EXE=a3w22
OBJ = a3w22.o
CFLAGS = -std=c++11
FILES_TO_TAR = makefile a3w22.cpp test.dat

%.o: %.cpp 
	$(CC) -c -o $@ $< $(CFLAGS)

$(EXE): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean tar
clean:
	rm -f $(OBJ) $(EXE)
tar:
	tar -cvf CMPUT379-Ass2-Hdesmara.tar $(FILES_TO_TAR)