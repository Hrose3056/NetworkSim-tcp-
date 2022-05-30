CC=g++
EXE=prog
OBJ = prog.o
CFLAGS = -std=c++11
FILES_TO_TAR = makefile prog.cpp test.dat

%.o: %.cpp 
	$(CC) -c -o $@ $< $(CFLAGS)

$(EXE): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean tar
clean:
	rm -f $(OBJ) $(EXE)
tar:
	tar -cvf NetworkSim-TCP-Hdesmara.tar $(FILES_TO_TAR)
