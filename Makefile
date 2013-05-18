### Makefile --- 

## Author: noahm@crystalline-entity.csail.mit.edu
## Version: $Id: Makefile.tpl 56 2005-10-03 22:43:38Z noahm $
## Keywords: 
## X-URL: 

authd: authd.c
	gcc -g -o authd authd.c

clean:
	-rm -f *.o *~
	-rm -f authd

### Makefile ends here
