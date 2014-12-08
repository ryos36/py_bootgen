from struct import unpack, pack, pack_into
from os import SEEK_SET, path
from time import localtime
import array
from sys import argv

class BootGen(object):
	Version = "0.0"

	# Static constants used
	LOOP_CODE = 0xeafffffe
	WIDTH_DETECTION = 0xaa995566
	IMAGE_ID = "XNLX"
	IMAGE_ID_HEX = 0x584c4e58

	IMAGE_HEADER_TABLE_VERSION = 0x01020000

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
		for i in range(0x4c, 0x9c + 4, 4):
			data += pack("<L", 0)

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
			#l = unpack("<L", *b0[i: i + 4])
			#data += unpack(<"pack("4B", *b0[i: i + 4])
		#print "pack:", pack('B' * len(buf), *buf)
		data += pack('B' * len(buf), *buf)
		#print "xx:", len(data)
		data += pack("L", 0)
		for i in range(len(data), 64):
			data += pack("B", 0xff)
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

	def make_partition_header_table(self, data_word_len, destination_load_addr, destination_exec_addr, data_word_offset, attribute, section_n, check_sum_word_offset, image_header_word_offet) :
		data = pack("<LLLL", data_word_len, data_word_len, data_word_len, destination_load_addr)
		data += pack("<LLLL", destination_exec_addr, data_word_offset, attribute, section_n)
		data += pack("<LLLL", check_sum_word_offset, image_header_word_offet, 0, 0)
		header_check_sum = data_word_len + data_word_len + data_word_len + destination_exec_addr + destination_exec_addr + data_word_offset + attribute + section_n + check_sum_word_offset + image_header_word_offet + 0 + 0 + 0 + 0 + 0
		data += pack("<LLL", 0, 0, 0)
		data += pack("<L", ~header_check_sum & 0xffffffff)
		return data
		
def main():
	argc = len(argv)

	if argc == 3 :
		with open(argv[2], "rb") as fin:
			bootgen = BootGen(None)
			bootgen.strip_bit(argv[2], "test2")
			return 0
			

	fd = open(argv[1], "wb") if argc >= 2 else None

	bootgen = BootGen(fd)
	data = bootgen.make_boot_header(0x1700, 0x01800c)
	fd.write(data)
	data = bootgen.make_image_header_table(3, 0x0320, 0x0240)
	fd.write(data)

	data = bootgen.make_image_header(0x250, 0x0320, 0, 1, "zynq_fsbl.elf")
	fd.write(data)
	print "data.len:", len(data)

	data = bootgen.make_image_header(0x260, 0x0330, 0, 1, "zc702_2d3d_hdmi_wrapper.bit")
	fd.write(data)

	data = bootgen.make_image_header(0x0, 0x0340, 0, 1, "u-boot.elf")
	fd.write(data)

	for i in range(04640 + 32, 06200, 4):
		fd.write(pack(">L", 0xffffffff))

	data = bootgen.make_partition_header_table(0x6003, 0, 0, 0x05c0, 0x10, 0x01, 0, 0x0240)
	fd.write(data)

	data = bootgen.make_partition_header_table(0x0f6ec0, 0, 0, 0x65d0, 0x20, 0x01, 0, 0x0250)
	fd.write(data)

	data = bootgen.make_partition_header_table(0x01079a, 0x04000000, 0x04000000, 0x0fd490, 0x10, 0x01, 0, 0x0260)
	fd.write(data)

	fd.close()


if __name__ == "__main__":
	exit(main())
