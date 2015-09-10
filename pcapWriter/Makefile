all:
	cp -f ./include/*.h ./src/
	cd ./src && make all
	rm -rf ./build
	mv -f ./src/build/ .
	rm -f ./src/*.h *~ ./src/*~ ./include/*~

clean:
	#cd ./src && make clean
	rm -rf ./build *~ ./src/*~ ./include/*~ 
