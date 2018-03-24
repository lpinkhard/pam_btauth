all: pam_btauth.so

clean:
	rm -f pam_btauth.so pam_btauth.o

pam_btauth.so: pam_btauth.o
	ld -lbluetooth -lssl -x --shared -o pam_btauth.so pam_btauth.o
	chmod a-x pam_btauth.so

pam_btauth.o: pam_btauth.c
	gcc -fPIC -lbluetooth -lssl -c pam_btauth.c
