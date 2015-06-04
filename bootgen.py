#
# Copyright (C) 2014,2015 Sinby Corp.
#
from struct import unpack, pack, pack_into
from os import SEEK_SET, path
from time import localtime
import array
from sys import argv
import os

class BootGen(object):
	Version = "0.0"

	# Static constants used
	LOOP_CODE = 0xeafffffe
	WIDTH_DETECTION = 0xaa995566
	IMAGE_ID = "XNLX"
	IMAGE_ID_HEX = 0x584c4e58

	IMAGE_HEADER_TABLE_VERSION = 0x01020000

	PARTITION_ATTRIBUTE_PS = 0x10
	PARTITION_ATTRIBUTE_PL = 0x20

	class FatalError(Exception):
		def __init__(self, msg):
			self.msg = msg
		def __str__(self):
			return "Fatal Error %s" % self.msg

	class FileNotFoundError(Exception):
		def __init__(self, path):
			self.path = path
		def __str__(self):
			return "The file or directory \"%s\" doesn't exist" % self.path

	def __init__(self, fd):
		self.fd = fd
		if fd :
			self.__start = fd.tell()

	def make_boot_header(self, source_offset, image_length, start_of_execution = 0, total_image_length = 0) :
		data = ""
		for i in range(0, 8):
			data += (pack("<L", BootGen.LOOP_CODE))
		data += pack("<L", BootGen.WIDTH_DETECTION)
		data += pack("<4s", BootGen.IMAGE_ID)
		data += pack("<LL", 0, 0x01010000)
		data += pack("<LLLL", source_offset, image_length, 0, start_of_execution)
		if total_image_length == 0 :
			total_image_length = image_length
		data += pack("<LL", total_image_length, 1)
		checksum = BootGen.WIDTH_DETECTION + BootGen.IMAGE_ID_HEX + 0 + 0x01010000 + source_offset + image_length + 0 + start_of_execution + total_image_length + 1

		#print "%x" % (checksum & 0xffffffff)
		#print "%x" % (~(checksum & 0xffffffff) & 0xffffffff)
		data += pack("<L", (~(checksum & 0xffffffff) & 0xffffffff))
		for i in range(0x4c, 0x9c + 4 - 16, 4):
			data += pack("<L", 0)

		#undocumented
		data += pack("<LLLL", 0x0, 0x0, 0x000008c0, 0x00000c80)
		for i in range(0x0a0, 0x89c + 4, 8):
			data += pack("<L", 0xffffffff)
			data += pack("<L", 0)

		for i in range(0, 32):
			data += pack("<B", 0xff)

		return data

	def make_image_header_table(self, image_header_n, partiton_header_offset, image_header_offset, authentication_offset = 0) :
		data = pack("<LLLLL", BootGen.IMAGE_HEADER_TABLE_VERSION, image_header_n, partiton_header_offset, image_header_offset, authentication_offset)

		for i in range(0x14, 64) :
			data += pack("<B", 0xff)
		return data

	def make_image_header(self, next_image_header_offset, partition_header_offset, partition_n, image_length, image_name) : 
		data = pack("<LLLL", next_image_header_offset, partition_header_offset, partition_n, image_length)
		b0 = map(ord, image_name)
		blen = len(b0)
		for v in range(blen, (blen + 3) & ~3 ):
			print v
			b0.append(0x0)
		blen = len(b0)
		buf = array.array('B', '\0' * blen)
		for i in range(0, blen, 4):
			#print l0 * 13, (l0  + 1) * 13
			for j in range(0, 4):
				pack_into("B", buf, i + j, b0[i + (3 - j)])
			#*b0[i: i+ 4])
			#l = unpack("<L", *b0[i: i + 4]) <= NG
			#data += unpack(<"4B", *b0[i: i + 4])
		#print "pack:", pack('B' * len(buf), *buf) <= OK
		data += pack('B' * len(buf), *buf)
		#print "xx:", len(data)
		data += pack(">L", 0)
		for i in range(len(data), 64):
			data += pack("B", 0xff)
		#data += pack("L", 0x99AABBCC)
		return data


	def __skip_field(self, fin, is_print = False) :
		is_print = True
		field_len, = unpack(">H", fin.read(2)) # big endian
		if is_print : print field_len
		field_data = unpack('B' * field_len, fin.read(field_len))
		#if is_print : print field_data
		return field_data

	def skip_field(self, fin, is_print = False) :
		return self.__skip_field(fin, is_print)

	def __copy_body(self, fin, bin_file) :
		field_len, = unpack(">L", fin.read(4)) # big endian
		print "field_len:", field_len
		if bin_file != False :
			fout = open(bin_file, "wb")
		else:
			fout = fd

		for i in range(0, field_len, 4) : 
			data, = unpack(">L", fin.read(4))
			fout.write(pack("<L", data))

		for i in range(0, (field_len + 15) / 16 * 16 - field_len, 4) : 
			fout.write(pack("<L", data))

		if bin_file != False :
			fout.close()

	def strip_bit(self, bit_file, bin_file = False) :
		with open(bit_file, "rb") as fin:
			self.__skip_field(fin) 
			self.__skip_field(fin) 
			self.__skip_field(fin) 

			magic = fin.read(1)
			if magic != 'b' :
				return False
			self.__skip_field(fin) 

			magic = fin.read(1)
			if magic != 'c' :
				return False
			self.__skip_field(fin) 

			magic = fin.read(1)
			if magic != 'd' :
				return False
			self.__skip_field(fin) 

			magic = fin.read(1)
			if magic != 'e' :
				return False
			self.__copy_body(fin, bin_file)

		return True

	def make_partition_header_table(self, partition_data_word_len, extracted_data_word_len, total_data_word_len, destination_load_addr, destination_exec_addr, data_word_offset, attribute, section_n, check_sum_word_offset, image_header_word_offet) :
		data = pack("<LLLL", partition_data_word_len, extracted_data_word_len, total_data_word_len, destination_load_addr)
		data += pack("<LLLL", destination_exec_addr, data_word_offset, attribute, section_n)
		data += pack("<LLLL", check_sum_word_offset, image_header_word_offet, 0, 0)
		header_check_sum = partition_data_word_len + extracted_data_word_len + total_data_word_len + destination_exec_addr + destination_exec_addr + data_word_offset + attribute + section_n + check_sum_word_offset + image_header_word_offet + 0 + 0 + 0 + 0 + 0
		data += pack("<LLL", 0, 0, 0)
		data += pack("<L", ~header_check_sum & 0xffffffff)
		return data
		
	def get_start_address(self, elf_file) :
		if path.basename(elf_file) == "u-boot.elf" :
			start_address = 0x04000000
		else:
			start_address = 0x00100000

		# You can check start address strictly.
		# arm-none-linux-gnueabi-objdump --section=.text -h u-boot.elf | grep .text | cut -c29-36
		return start_address

	def make_boot_bin(self, fsbl_zynq_elf_path, fsbl_zynq_elf_bin, system_bit_path, system_bit_bin, app_elf_path, app_elf_bin, start_address):

		binary_start_offset = 0x1700
		image_length = path.getsize(fsbl_zynq_elf_bin)

		data = self.make_boot_header(binary_start_offset, image_length)
		self.fd.write(data)

		image_header_n = 3
		
		partiton_header_word_offset = 0x320 #* 4
		image_header_word_offset = 0x240 #* 4

		data = self.make_image_header_table(image_header_n, partiton_header_word_offset, image_header_word_offset)
		self.fd.write(data)

		data = self.make_image_header(0x250, 0x0320, 0, 1, path.basename(fsbl_zynq_elf_path));
		self.fd.write(data)

		data = self.make_image_header(0x260, 0x0330, 0, 1, path.basename(system_bit_path));
		self.fd.write(data)

		data = self.make_image_header(0x0, 0x0340, 0, 1, path.basename(app_elf_path));
		self.fd.write(data)

		for i in range(04640 + 32, 06200, 4):
			self.fd.write(pack(">L", 0xffffffff))

		binary_word_offset0 = binary_start_offset / 4
		image_word_length0 = image_length / 4
		data = self.make_partition_header_table(image_word_length0, image_word_length0, image_word_length0, 0, 0, binary_word_offset0, BootGen.PARTITION_ATTRIBUTE_PS, 0x01, 0, 0x0240)
		self.fd.write(data)

		binary_word_offset1 = binary_word_offset0 + ((image_word_length0 + 15) & ~15)
		image_word_length1 = path.getsize(system_bit_bin) / 4
		image_word_length1_16 = ( image_word_length1 + 15 ) & ~15

		data = self.make_partition_header_table(image_word_length1_16, image_word_length1, image_word_length1_16, 0, 0, binary_word_offset1, BootGen.PARTITION_ATTRIBUTE_PL, 0x01, 0, 0x0250)
		self.fd.write(data)

		binary_word_offset2 = binary_word_offset1 + ((image_word_length1 + 15) & ~15)
		image_word_length2 = path.getsize(app_elf_bin) / 4

		data = self.make_partition_header_table(image_word_length2, image_word_length2, image_word_length2, start_address, start_address, binary_word_offset2, BootGen.PARTITION_ATTRIBUTE_PS, 0x01, 0, 0x0260)
		self.fd.write(data)

		#undocumented
		data = self.make_partition_header_table(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		self.fd.write(data)

		for i in range(self.fd.tell(), binary_word_offset0 * 4) :
			self.fd.write(pack("B", 0xff))

		with open(fsbl_zynq_elf_bin, "rb") as f:
			for i in range(0, image_word_length0):
				self.fd.write(f.read(4))

		for i in range(self.fd.tell(), binary_word_offset1 * 4) :
			self.fd.write(pack("B", 0xff))

		with open(system_bit_bin, "rb") as f:
			for i in range(0, image_word_length1):
				self.fd.write(f.read(4))

		for i in range(self.fd.tell(), binary_word_offset2 * 4) :
			self.fd.write(pack("B", 0xff)) #??

		with open(app_elf_bin, "rb") as f:
			for i in range(0, image_word_length2):
				self.fd.write(f.read(4))

		tell_me = self.fd.tell()
		for i in range(tell_me, ( tell_me + 15 ) & ~15):
			self.fd.write(pack("B", 0xff)) 


def main():
	argc = len(argv)

	if argc != 5 :
		print "Usage: bootgen fsbl.elf bit u-boot.elf boot.bin"
		return 0
			
	fsbl_elf = argv[1]
	fsbl_elf_bin = fsbl_elf + ".bin"
	bit_file = argv[2]
	bit_file_bin = argv[2] + ".bin"
	uboot_elf = argv[3]
	uboot_elf_bin = uboot_elf + ".bin"
	boot_bin = argv[4]

	fd = open(boot_bin, "wb")

	bootgen = BootGen(fd)

	rv = os.system("arm-none-linux-gnueabi-objcopy -O binary %s %s" % (fsbl_elf, fsbl_elf_bin))
	if rv != 0 :
		return rv
	rv = bootgen.strip_bit(bit_file, bit_file_bin)
	if rv == False :
		return 1
	rv = os.system("arm-none-linux-gnueabi-objcopy -O binary %s %s" % (uboot_elf, uboot_elf_bin))
	if rv != 0 :
		return rv

	binary_start_offset = 0x1700
	image_length = path.getsize(fsbl_elf_bin)

	data = bootgen.make_boot_header(binary_start_offset, image_length)
	fd.write(data)

	image_header_n = 3
	
	partiton_header_word_offset = 0x320 #* 4
	image_header_word_offset = 0x240 #* 4

	data = bootgen.make_image_header_table(image_header_n, partiton_header_word_offset, image_header_word_offset)
	fd.write(data)

	data = bootgen.make_image_header(0x250, 0x0320, 0, 1, fsbl_elf);
	fd.write(data)

	data = bootgen.make_image_header(0x260, 0x0330, 0, 1, bit_file);
	fd.write(data)

	data = bootgen.make_image_header(0x0, 0x0340, 0, 1, uboot_elf);
	fd.write(data)

	for i in range(04640 + 32, 06200, 4):
		fd.write(pack(">L", 0xffffffff))

	binary_word_offset0 = binary_start_offset / 4
	image_word_length0 = image_length / 4
	data = bootgen.make_partition_header_table(image_word_length0, image_word_length0, image_word_length0, 0, 0, binary_word_offset0, BootGen.PARTITION_ATTRIBUTE_PS, 0x01, 0, 0x0240)
	fd.write(data)

	binary_word_offset1 = binary_word_offset0 + ((image_word_length0 + 15) & ~15)
	image_word_length1 = path.getsize(bit_file_bin) / 4
	image_word_length1_16 = ( image_word_length1 + 15 ) & ~15

	data = bootgen.make_partition_header_table(image_word_length1_16, image_word_length1, image_word_length1_16, 0, 0, binary_word_offset1, BootGen.PARTITION_ATTRIBUTE_PL, 0x01, 0, 0x0250)
	fd.write(data)

	binary_word_offset2 = binary_word_offset1 + ((image_word_length1 + 15) & ~15)
	image_word_length2 = path.getsize(uboot_elf_bin) / 4

	if uboot_elf == "u-boot.elf" :
		start_address = 0x04000000
	else:
		start_address = 0x00100000

	# You can check start address strictly.
	# arm-none-linux-gnueabi-objdump --section=.text -h u-boot.elf | grep .text | cut -c29-36

	data = bootgen.make_partition_header_table(image_word_length2, image_word_length2, image_word_length2, start_address, start_address, binary_word_offset2, BootGen.PARTITION_ATTRIBUTE_PS, 0x01, 0, 0x0260)
	fd.write(data)

	#undocumented
	data = bootgen.make_partition_header_table(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	fd.write(data)

	for i in range(fd.tell(), binary_word_offset0 * 4) :
		fd.write(pack("B", 0xff))

	with open(fsbl_elf_bin, "rb") as f:
		for i in range(0, image_word_length0):
			fd.write(f.read(4))

	for i in range(fd.tell(), binary_word_offset1 * 4) :
		fd.write(pack("B", 0xff))

	with open(bit_file_bin, "rb") as f:
		for i in range(0, image_word_length1):
			fd.write(f.read(4))

	for i in range(fd.tell(), binary_word_offset2 * 4) :
		fd.write(pack("B", 0xff)) #??

	with open(uboot_elf_bin, "rb") as f:
		for i in range(0, image_word_length2):
			fd.write(f.read(4))

	tell_me = fd.tell()
	for i in range(tell_me, ( tell_me + 15 ) & ~15):
		fd.write(pack("B", 0xff)) 

	fd.close()

if __name__ == "__main__":
	exit(main())
