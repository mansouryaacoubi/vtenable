#!/usr/bin/python

import sys, struct

#VSS_OFFSET = 0x00180048
#VSS_SIZE = 0x4000 - 0x48
VSS_OFFSET = 0x000c0048
VSS_SIZE = 0x3f58

#PATCH_OFFSET = 0x1af
PATCH_OFFSET = 0xae
PATCH_VALUE = 0x01
PATCH_VARIABLE = u"Setup"

def hexdump(s,sep=" "):
	return sep.join(map(lambda x: "%02x"%ord(x),s))

def ascii(s):
	s2 = ""
	for c in s:
		if ord(c)<0x20 or ord(c)>0x7e:
			s2 += "."
		else:
			s2 += c
	return s2

def pad(s,c,l):
	if len(s)<l:
		s += c * (l-len(s))
	return s

def chexdump(s,ts=""):
	for i in range(0,len(s),16):
		print ts+"%08x  %s  %s  |%s|"%(i,pad(hexdump(s[i:i+8],' ')," ",23),pad(hexdump(s[i+8:i+16],' ')," ",23),pad(ascii(s[i:i+16])," ",16))

def addup(s):
	if len(s) & 1:
		s = s + "\x00"
	sum = 0
	while len(s):
		sum += struct.unpack("<H",s[:2])[0]
		s = s[2:]
	return sum &0xFFFF

class VAR(object):
	GLOBAL_VARIABLE = "\x61\xdf\xe4\x8b\xca\x93\xd2\x11\xaa\x0d\x00\xe0\x98\x03\x2b\x8c"
	def __init__(self, data):
		hdr = data[:0x20]
		self.magic, self.status, self.attributes, self.nsize, self.dsize, self.guid = struct.unpack("<HHIII16s", hdr)
		if self.magic != 0x55aa:
			raise ValueError("bad magic 0x%x"%self.magic)
		self.bname = data[0x20:0x20+self.nsize]
		self.name = ''.join(data[0x20:0x20+self.nsize:2])
		self.name = self.name.split("\x00")[0]
		self.value = data[0x20+self.nsize:0x20+self.nsize+self.dsize]
		self.data = data[:0x20+self.nsize+self.dsize]
		cdata = data[:0x20] + "\x00\x00" + data[0x20:]
		fdata = "\xaa\x55\x7f\x00" + cdata[4:0x20+self.nsize+self.dsize]
	def update(self):
		self.nsize = len(self.name) * 2 + 2
                self.dsize = len(self.value)
		self.data = struct.pack("<HHIII16s", self.magic, self.status, self.attributes, self.nsize, self.dsize, self.guid)
		self.data += self.name.encode('utf-16le') + "\x00\x00"
		self.data += self.value
		fdata = "\xaa\x55\x7f\x00" + self.data[4:0x20+self.nsize+self.dsize]
                self.data = self.data[:0x20] + self.data[0x20:] 
	def showinfo(self, ts=''):
		print ts+"Variable %s"%repr(self.name)
		print ts+" Attributes: 0x%08x"%self.attributes
		print ts+" Status: 0x%02x"%self.status
		if self.guid == self.GLOBAL_VARIABLE:
			print ts+" VendorGUID: EFI_GLOBAL_VARIABLE (%s)"%' '.join('%02x'%ord(c) for c in self.guid)
		else:
			print ts+" VendorGUID: %s"%' '.join('%02x'%ord(c) for c in self.guid)
		print ts+" Value (0x%x bytes):"%(len(self.value))
		chexdump(self.value, ts+"  ")

print "Loading BIOS..."
bin = open(sys.argv[1], "rb").read()

print "Loading VSS..."
vss = bin[VSS_OFFSET:VSS_OFFSET+VSS_SIZE]

print vss[:4]
if vss[:4] != "$VSS":
	raise ValueError("Invalid VSS signature")

off = 0x10

found = False

while not found and vss[off:off+2] == "\xaa\x55":
	var = VAR(vss[off:])
	if var.name == PATCH_VARIABLE and var.status == 0x7f:
		found = True
	else:
		off += len(var.data)

if not found:
	#print "Variable not found!"
	raise ValueError("Variable not found!")

print "Old state:"
var.showinfo()

var.value = var.value[:PATCH_OFFSET] + chr(PATCH_VALUE) + var.value[PATCH_OFFSET+1:]
var.update()
print "Patched state:"
var = VAR(var.data)
var.showinfo()

print "Updating VSS..."
vss = vss[:off] + var.data + vss[off+len(var.data):]

print "Updating BIOS..."
bin = bin[:VSS_OFFSET] + vss + bin[VSS_OFFSET+VSS_SIZE:]

print "Writing output..."
ofd = open(sys.argv[2], "wb")
ofd.write(bin)
ofd.close()

print "Done"