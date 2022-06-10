# IDA Pro Nintendo GameCube REL Loader by oct0xor
# Based on Megazig's rso_ida_loader

import idaapi
import idc
from ida_idp import *
from ida_auto import *
from ida_segment import *
from ida_bytes import *
import struct

START_ADDR = 0x80500000

R_PPC_NONE            = 0     # none 
R_PPC_ADDR32          = 1     # S + A 
R_PPC_ADDR24          = 2     # (S + A) >> 2 
R_PPC_ADDR16          = 3     # S + A 
R_PPC_ADDR16_LO       = 4
R_PPC_ADDR16_HI       = 5
R_PPC_ADDR16_HA       = 6
R_PPC_ADDR14          = 7
R_PPC_ADDR14_BRTAKEN  = 8
R_PPC_ADDR14_BRNTAKEN = 9
R_PPC_REL24           = 10    # (S + A - P) >> 2
R_PPC_REL14           = 11

R_DOLPHIN_NOP         = 201 # C9h current offset += rel.offset
R_DOLPHIN_SECTION     = 202 # CAh current offset = rel.section
R_DOLPHIN_END         = 203 # CBh
R_DOLPHIN_MRKREF      = 204 # CCh

REL_NAMES = {
	R_PPC_NONE           : "R_PPC_NONE",
	R_PPC_ADDR32         : "R_PPC_ADDR32",
	R_PPC_ADDR24         : "R_PPC_ADDR24",
	R_PPC_ADDR16         : "R_PPC_ADDR16",
	R_PPC_ADDR16_LO      : "R_PPC_ADDR16_LO",
	R_PPC_ADDR16_HI      : "R_PPC_ADDR16_HI",
	R_PPC_ADDR16_HA      : "R_PPC_ADDR16_HA",
	R_PPC_ADDR14         : "R_PPC_ADDR14",
	R_PPC_ADDR14_BRTAKEN : "R_PPC_ADDR14_BRTAKEN",
	R_PPC_ADDR14_BRNTAKEN: "R_PPC_ADDR14_BRNTAKEN",
	R_PPC_REL24          : "R_PPC_REL24",
	R_PPC_REL14          : "R_PPC_REL14",
	R_DOLPHIN_NOP        : "R_DOLPHIN_NOP",
	R_DOLPHIN_SECTION    : "R_DOLPHIN_SECTION",
	R_DOLPHIN_END        : "R_DOLPHIN_END",
	R_DOLPHIN_MRKREF     : "R_DOLPHIN_MRKREF",
}

MAIN_DOL = 0

def read_u8(data, pos):
	return struct.unpack(">B", data[pos:pos+1])[0]

def read_u32(data, pos):
	return struct.unpack(">L", data[pos:pos+4])[0]

class parse_header:
	def __init__(self, data):

		self.data = data
		self.pos = 0

		self.module_id = self.read_u32()
		self.prev = self.read_u32()
		self.next = self.read_u32()
		self.section_count = self.read_u32()
		self.section_offset = self.read_u32()
		self.path_offset = self.read_u32()
		self.path_length = self.read_u32()
		self.version = self.read_u32()
		
		# type 1 or later
		self.bss_size = self.read_u32()
		self.rel_offset = self.read_u32()
		self.imp_offset = self.read_u32()
		self.imp_size = self.read_u32()
		self.prolog_section = self.read_u8()
		self.epilog_section = self.read_u8()
		self.unresolved_section = self.read_u8()
		self.bss_section = self.read_u8()
		self.prolog = self.read_u32()
		self.epilog = self.read_u32()
		self.unresolved = self.read_u32()
		
		# type 2 or later
		self.align = self.read_u32()
		self.bss_align = self.read_u32()
		
		# type 3 or later
		self.fix_size = self.read_u32()

	def read_u8(self):
		value = read_u8(self.data, self.pos)
		self.pos += 1
		return value

	def read_u32(self):
		value = read_u32(self.data, self.pos)
		self.pos += 4
		return value

def parse_sections(li, data, rhdr):

	#print("Sections: %d" % rhdr.section_count)
	#print("Sections offset: 0x%X" % rhdr.section_offset)
	
	address = START_ADDR

	sections = {}
	for section_id in range(rhdr.section_count):
	
		offset, length = struct.unpack(">LL", data[rhdr.section_offset+section_id*8:rhdr.section_offset+section_id*8+8])

		if (offset == 0 and length == 0):
			continue
	
		code_section = False
		if (offset & 1):
			code_section = True
			offset &= ~1

		sclass = "DATA"
		name = ".data"

		if (offset == 0):
			sclass = "BSS"
			name = ".bss"

		elif (code_section):
			sclass = "CODE"
			name = ".text"

		name = "%s%u" % (name, section_id)

		add_segm(1, address, address + length, name, sclass)

		set_segm_addressing(getseg(address), 1);

		if (offset):
			li.file2base(offset, address, address + length, idaapi.FILEREG_PATCHABLE)

		if (code_section):
			auto_mark_range(address, address + length, AU_CODE)

		#print("Section %d - 0x%X, 0x%X" % (section_id, offset, length))
		sections[section_id] = [offset, length, address, code_section]
		address += length

	return sections

def get_section_address(sections, section, offset):
	return sections[section][2] + offset

def patch_address32(sections, section, offset, value):
	# S + A
	where = get_section_address(sections, section, offset)
	patch_dword(where, value)
	
def patch_addressLO(sections, section, offset, value):
	# lo(S + A)
	where = get_section_address(sections, section, offset)
	value = value & 0xFFFF
	patch_word(where, value)

def patch_addressHA(sections, section, offset, value):
	# ha(S + A)
	where = get_section_address(sections, section, offset)
	if ((value & 0x8000) == 0x8000):
		value += 0x00010000
	value = (value >> 16) & 0xFFFF
	patch_word(where, value)

def patch_address24(sections, section, offset, value):
	# (S + A - P) >> 2 
	where = get_section_address(sections, section, offset)
	value -= where
	orig = get_original_dword(where)
	orig &= 0xFC000003
	orig |= value & 0x03FFFFFC
	patch_dword(where, orig)

def parse_relocations(data, sections, offset, flag):

	current_section = 0
	current_offset  = 0

	pos = 0
	while (True):

		rel_offset, rel_type, rel_section, rel_addend = struct.unpack(">HBBL", data[pos+offset:pos+offset+8])

		#print("Relocation: 0x%02X (%s), 0x%X, 0x%X, 0x%X" % (rel_type, REL_NAMES[rel_type], rel_section, rel_offset, rel_addend))

		if (rel_type == R_DOLPHIN_END):
			break

		if (flag):
			rel_addend = get_section_address(sections, rel_section, rel_addend)

		if (rel_type == R_DOLPHIN_SECTION):
			current_section = rel_section
			current_offset = 0

		elif (rel_type == R_DOLPHIN_NOP):
			current_offset += rel_offset

		elif (rel_type == R_PPC_ADDR32):
			current_offset += rel_offset
			patch_address32(sections, current_section, current_offset, rel_addend)

		elif (rel_type == R_PPC_ADDR16_LO):
			current_offset += rel_offset
			patch_addressLO(sections, current_section, current_offset, rel_addend)

		elif (rel_type == R_PPC_ADDR16_HA):
			current_offset += rel_offset
			patch_addressHA(sections, current_section, current_offset, rel_addend)

		elif (rel_type == R_PPC_REL24):
			current_offset += rel_offset
			patch_address24(sections, current_section, current_offset, rel_addend)

		else:
			print("Bad relocation type: 0x%d" % rel_type)
			break

		pos += 8

def parse_imports(data, rhdr, sections):

	if (rhdr.imp_offset):
	
		for import_id in range(rhdr.imp_size / 8):
	
			module_id, offset = struct.unpack(">LL", data[rhdr.imp_offset+import_id*8:rhdr.imp_offset+import_id*8+8])
	
			#print("Import %d - 0x%X, 0x%X" % (import_id, module_id, offset))
	
			if (module_id == MAIN_DOL):
				parse_relocations(data, sections, offset, False)

			elif (module_id == rhdr.module_id):
				parse_relocations(data, sections, offset, True)

			else:
				print("Need to link against unknown module 0x%X" % module_id)

def accept_file(li, filename):

	if (filename.endswith('.rel')):

		li.seek(0)
		data = li.read(0x4C)

		rhdr = parse_header(data)
	
		return {'format': 'Nintendo GameCube REL', 'processor': 'ppc'}

	return 0

def load_file(li, neflags, format):

	li.seek(0, 2)
	size = li.tell()

	li.seek(0)	
	data = li.read(size)

	set_processor_type('ppc', SETPROC_LOADER)

	set_selector(1, 0)

	rhdr = parse_header(data)
	
	sections = parse_sections(li, data, rhdr)
	
	parse_imports(data, rhdr, sections)
	
	return 1
