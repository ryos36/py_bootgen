#
# Copyright (C) 2014,2015 Sinby Corp.
#

from sys import argv
from bootgen import BootGen

def main():
	argc = len(argv)

	if argc != 2 :
		print "Usage: bootgen system.bit"
		return 0
			
	bit_file = argv[1]
	bit_file_bin = argv[1] + ".bin"

	bootgen = BootGen(None)
	rv = bootgen.strip_bit(bit_file, bit_file_bin)

if __name__ == "__main__":
	exit(main())
