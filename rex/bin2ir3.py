from _typeshed import Self
from enum import Flag
import os
import sys
import angr

import re

import copy
# import magic

import binascii
import time

from problock import *
from config import *
from utils import  *

starttime = ""
nextblocktime = 0

class FILETYPE:
	Vxexec = 1,
	Vlibobj = 2

ARCHD=["DCD","DCB","DC",".ascii",".word"]
archdataformat = ["word_","dword_","unk_","byte_"]

def get_idbfilename(filename,posfix):
	dirname = get_dir(filename)
	name = get_filename(filename)
	if name.find(".") == -1:
		name += posfix
	else:
		name = name[0:name.rindex(".")] + posfix
	result = dirname + "/" + name
	return result
	

def rm_tmpfile(filename):
	filename = form_filename(filename)
	idbfilename = get_idbfilename(filename,".idb")
	asmfilename = get_idbfilename(filename,".asm")
	os.remove(idbfilename)
	os.remove(asmfilename)
	

def idarun(filename, tmpname):
	# global home_path

	filename = form_filename(filename)
	idbfilename = get_idbfilename(filename,".idb")
	tmpname += "idcom"

	# ida_path = home_path + "/IDA_Pro_v6.4_Linux/"
	# script_path = home_path + "/CRYPTOREX/idascript/bin2iridc.idc"

	print(ida_path + "/idaq -B " + filename)
	os.system(ida_path + "/idaq -B " + filename)
	print(ida_path + "/idaq -S \"" + script_path + tmpname + "\" " + idbfilename)
	#os.system("$HOME/Downloads/IDA_Pro_v6.4_\(Linux\)_and_Hex-Rays_Decompiler_\(ARM\)/IDA_Pro_v6.4_\(Linux\)_and_Hex-Rays_Decompiler_\(ARM\)/idaq -S\"/media/vezir/b2552981-cae5-4a83-9f27-2d07beede43e/CRYPTOREX/idascript/bin2iridc.idc " + tmpname + "\" " + idbfilename)
	os.system(ida_path + "/idaq -S \"" + script_path + tmpname + "\" " + idbfilename)

	rm_tmpfile(filename)

class Binlcominfo:
	def __init__(self, filename):
		self.binfile = ""
		self.functionmap = functioncontainer()
		self.allfuction = list()
		self.allfunctionname = dict()
		self.lcom = dict()
		self.pltstype = dict()
		self.rodatatype = dict()
		self.datatype = dict()
		self.functiondata = dict()
		self.functionsp = dict()
		self.innerfunctions = dict()
		self.externfunctions = dict()
		self.alldata = dict()
		self.externfuncset = set()

		self.flag = {'binfile':1,
					 'allfunction': 0,
					 'lcom': 0,
					 'plt': 0,
					 'rodata': 0,
					 'data': 0,
					 'functiondata': 0
					}
	
		with open(self.filename, 'r') as rfd:
			offset = 0
			resulttype = ""
			while True:
				line = rfd.readline().strip()
				if not line:
					break
				if line == "all function:":
					self.flag = {'binfile':0,
								 'allfunction': 1,
								 'lcom': 0,
								 'plt': 0,
								 'rodata': 0,
								 'data': 0,
								 'functiondata': 0
								}
				elif line == "lcom":
					self.flag = {'binfile':0,
								 'allfunction': 0,
								 'lcom': 1,
								 'plt': 0,
								 'rodata': 0,
								 'data': 0,
								 'functiondata': 0
								}
				elif line == "pltfunctiontype":
					self.flag = {'binfile':0,
								 'allfunction': 0,
								 'lcom': 0,
								 'plt': 1,
								 'rodata': 0,
								 'data': 0,
								 'functiondata': 0
								}
				elif line == ".rodata":
					self.flag = {'binfile':0,
								 'allfunction': 0,
								 'lcom': 0,
								 'plt': 0,
								 'rodata': 1,
								 'data': 0,
								 'functiondata': 0
								}
				elif line == ".data":
					self.flag = {'binfile':0,
								 'allfunction': 0,
								 'lcom': 0,
								 'plt': 0,
								 'rodata': 0,
								 'data': 1,
								 'functiondata': 0
								}
				elif line == "functionenddata":
					self.flag = {'binfile':0,
								 'allfunction': 0,
								 'lcom': 0,
								 'plt': 0,
								 'rodata': 0,
								 'data': 0,
								 'functiondata': 1
								}

				if self.flag['binfile']:
					# binfileflag
					binfile = line
					resulttype, offset = execorlib(binfile)
				elif self.flag['allfunction']:
					field = line.split("\t")
					if len(field) != 2 or len(field) != 3:
						continue

					funcaddr = int(field[0],16) + offset
					self.allfunction.append(funcaddr)
					
					beginsp = field[1].split(":")
					if len(beginsp) == 2:
						self.functionsp[funcaddr] = beginsp[1].strip()
					
					self.innerfunctions[beginsp[0]] = funcaddr
					
					tmpfunction = function()
					funcn = beginsp[0].strip()
					tmpfunction.setfunctionname(funcn)
					self.allfunctionname[funcaddr]=funcn
					
					tmpfunction.addfunctionaddr(funcaddr)
					tmpfunction.setfunctiontype(FUNCTIONTYPE.inner)
					self.functionmap.addfunction(tmpfunction)
				
				elif self.flag['lcom']:
					field = re.split("\s+",line)
					#print(field)
					if len(field) != 2:
						continue
					funcaddr = int(field[0],16) + offset
					self.lcom[funcaddr] = field[1]

				elif self.flag['plt']:
					field = line.split("\t")
					if len(field) != 2 or len(field) != 3:
						continue

					tmp = ""
					tmpl = list()
					tmpfunction = function()

					funcaddr = int(field[0],16) + offset

					functionname = field[1].strip()
					if functionname.startswith("j_") and self.functionmap.getfunction(functionname[0+len("j_"):len(functionname)]) != None:
						tmpfunction = self.functionmap.getfunction(functionname[0+len("j_"):len(functionname)])
						tmpfunction.addfunctionaddr(funcaddr)
						self.functionmap.addfunctionaddr(tmpfunction.getfunctionname(), funcaddr)
						continue
					else:
						tmpfunction.setfunctiontype(FUNCTIONTYPE.extern)
						tmpfunction.addfunctionaddr(funcaddr)
						self.externfuncset.add(field[1].strip())
					tmpfunction.setfunctionname(field[1].strip())
					
					if len(field) == 2:
						tmp = [field[1],tmpl]
					elif len(field) == 3:
						tmpl = re.split("[(),]",field[2])
						for tmpli in range(0,len(tmpl)):
							tmpl[tmpli] = tmpl[tmpli].strip()
							if tmpli == 0:
								tmpfunction.setreturntype(tmpl[tmpli].strip())
								#print(functionname)
								#print("return type")
								#print(tmpl[tmpli].strip())
							else:
								tmpfunction.addarg(tmpl[tmpli].strip())
						tmp = [field[1],tmpl]
						self.externfunctions[field[1]] = funcaddr
					self.pltstype[funcaddr] = tmp
					self.functionmap.addfunction(tmpfunction)
				elif self.flag['rodata'] or self.flag['data']:
					field = line.split("\t")
					if len(field) != 2:
						continue
					
					funcaddr = int(field[0],16) + offset
					self.rodatatype[funcaddr] = field[1]
					for aitem in ARCHD:
						if field[1].startswith(aitem) and not field[1].find(" ") == -1:
							blanklocat = field[1].find(" ")
							self.alldata[funcaddr] = field[1][blanklocat:len(field[1])].strip()
							break
						elif field[1].startswith(aitem):
							self.alldata[funcaddr] = field[1][len(aitem):len(field[1])].strip()
							break

				elif self.flag['functiondata']:
					field = line.split("\t")
					if len(field) != 2:
						continue

					tmpfield1 = field[1][field[1].find(" ") + 1:len(field[1])]
					#print(tmpfield1)

					funcaddr = int(field[0],16) + offset
					if not field[1].startswith("DC") and field[1].isdigit():
						self.functiondata[funcaddr] = int(tmpfield1) + offset
						self.alldata[funcaddr] = int(tmpfield1) + offset
					else:
						self.functiondata[funcaddr] = tmpfield1
						self.alldata[funcaddr] = tmpfield1

class Rulematch:
	def __init__(self, rulefilename):
		
		print(rulefilename)
		
		self.funcnameset = set()
		self.funcdetail = dict()
		self.ruledesresult = dict()
		self. wfuncset = set()
		self.wfuncdetail = dict()

		self.flag = {'ruledes':0,
					 'misusefunction': 0,
					 'depend': 0
					}
		
		with open(self.rulefilename, "r") as rulefd:
			while True:
				line = rulefd.readline().strip()
				if not line:
					break
					
				if line == "ruledes:":
					self.flag = {'ruledes':1,
					 			 'misusefunction': 0,
					 			 'depend': 0
					}

				elif line == "misusefunction:":
					self.flag = {'ruledes':0,
					 			 'misusefunction': 1,
					 			 'depend': 0
								}
				
				elif line == "dependfunc:":
					self.flag = {'ruledes':0,
					 			 'misusefunction': 0,
					 			 'depend': 1
								}				

				if self.flag['ruledes']:
					if len(line) and line[0] == "#":
						continue
					field = line.split("\t")
					if len(field) != 2:
						continue
					
					self.ruledesresult[int(field[0])] = field[1]

				elif self.flag['misusefunction']:
					if not get_functionheader(line):
						continue
					else:
						field, funcprototype, funcheader = get_functionheader(line)
						tmpfunction = get_tmpfunction(field, funcprototype, funcheader, self.ruledesresult)
					
					self.funcnameset.add(funcheader[1])
					self.funcdetail[funcheader[1]] = tmpfunction

				elif self.flag['depend']:
					if not get_functionheader(line):
						continue
					else:
						field, funcprototype, funcheader = get_functionheader(line)
						tmpfunction = get_tmpfunction(field, funcprototype, funcheader, self.ruledesresult)
					
					self.wfuncset.add(funcheader[1])
					self.wfuncdetail[funcheader[1]] = tmpfunction

def constructmycfg(node,proj,functionmap,lcom,externfunctions,mycfg,addrset,pathnode,test,bpspoffset):
	global nextblocktime
	global starttime

	resultleafnode = set()
	# rightresultleafset = set()
	callset = set()

	if not node.beginaddr == 0:
		pathnode.add(node.beginaddr)
	#print("construct0x%X"%node.beginaddr)
	#print(node.beginaddr)

	testa = time.time()
	bl = node.getnextblockaddr(bpspoffset)
	testb = time.time()
	nextblocktime += (testb - testa)

	for bitem in bl:
		nextaddr = None
		nextnode = None
		tmpleaf = set()
		b = bitem[0]
		slide = bitem[1]
		f = functionmap.getfunction(b)

		if f != None:
			if f.getfunctiontype() == FUNCTIONTYPE.inner:
				nextaddr = f.getfunctionaddr()[0]
			else:
				nextnode = problock()
				nextnode.addexternflag()
				nextnode.addexternfun(f.getfunctionname())
				for a in f.getarg():
					nextnode.addexternfunarg(a)
				if not f.getfunctionname() in externfunctions:
					externfunctions[f.getfunctionname()] = list()
				externfunctions[f.getfunctionname()].append(nextnode)
		elif not b.isdigit():
			continue
		else:
			nextaddr = int(b)
		
		if (nextaddr != None) and (not nextaddr in addrset):
			continue
		elif nextnode == None and nextaddr == None:
			continue
		elif nextnode == None and (nextaddr != None):#inner
			block = proj.factory.block(nextaddr)
			irsb = block.vex
			nextnode = problock(irsb,lcom)

		if nextnode.beginaddr in pathnode:
			continue

		if (nextaddr != None) and (nextaddr != 0) and (nextaddr in mycfg):
			nextnode = mycfg[nextaddr][0]
			tmpleaf = mycfg[nextaddr][1]
		else:
			nowtime = time.time()
			if int(nowtime - starttime) / 60 <= 5:
				nextnode,tmpleaf = constructmycfg(nextnode,proj,functionmap,lcom,mycfg,addrset,copy.copy(pathnode),test+1,node.getbpspoffset())
				mycfg[nextaddr] = [nextnode,tmpleaf]
		resultleafnode = resultleafnode.union(tmpleaf)

		if slide == CHILDRENSIZE.Vexit:
			slideflag,locat = node.addleftchildren(nextnode)
			nextnode.addparents([node,slideflag,locat])
		elif slide == CHILDRENSIZE.Vnext:
			slideflag,locat = node.addrightchildren(nextnode)
			nextnode.addparents([node,slideflag,locat])
		elif slide == CHILDRENSIZE.Vlr:
			if nextaddr in callset:
				continue
			slideflag,locat = node.addrightchildren(nextnode)
			nextnode.addparents([node,slideflag,locat])

		if (not nextaddr == None) and (not nextaddr == 0):
			callset.add(nextaddr)

	if node.getleftchildren() == None and node.getrightchildren() == None:
		resultleafnode.add(node)
	return node, resultleafnode

def dfspp(node,time,s=""):
	msg = ""
	for i in range(0,time):
		msg += " "
	msg += str(time) + " " + s + " "
	msg += node.getmetadata()
	for pnode in node.getparents():
		msg += " 0x%X "%pnode[0].beginaddr
	print(msg)
	for cnode in node.getleftchildren():
		dfspp(cnode,time+1)
	for cnode in node.getrightchildren():
		dfspp(cnode,time+1)

def execorlib(filename):
	filetype = get_filetype(filename)
	resulttype = ""
	if any(s in [filetype] for s in [b"application/x-executable"]):
		print("x-ex")
		# wfiletype = "x-ex\n"
		offset = 0
		resulttype = FILETYPE.Vxexec
	elif any(s in [filetype] for s in [b"application/x-sharedlib"]):
		print("x-obj")
		# wfiletype = "x-obj\n"
		offset = 0x400000
		resulttype = FILETYPE.Vlibobj
	return resulttype,offset

def execfunction():
	functionfilename = excfunction_path
	funcnameset = set()
	funcdetail = dict()

	# functionfd = open(functionfilename,"r")
	with open(functionfilename,"r") as functionfd:
		while True:
			line = functionfd.readline().strip()
			if not line:
				break

			field, funcprototype, funcheader = get_functionheader(line) 
			funcnameset.add(funcheader[1])
			
			tfop = funcop()
			tfop.setfunctionname(funcheader[1])
			tfop.setreturntype(funcheader[0])
			topfield = field[1].split(" ")
			for f in topfield:
				infodetailfield = f.split(":")
				if len(infodetailfield) != 3:
					continue
				if infodetailfield[0].strip() == "dest":
					tfop.setfuncdest(int(infodetailfield[1]))
					if infodetailfield[2] == "string":
						tfop.setdesttype(FARGTYPE.Vstring)
					elif infodetailfield[2] == "int":
						tfop.setdesttype(FARGTYPE.Vint)
				elif infodetailfield[0].strip() == "src":
					tfop.setfuncsrc(int(infodetailfield[1]))
					if infodetailfield[2] == "string":
						tfop.setsrctype(FARGTYPE.Vstring)
					elif infodetailfield[2] == "int":
						tfop.setsrctype(FARGTYPE.Vint)
				elif infodetailfield[0].strip() == "len":
					tfop.setfunclen(int(infodetailfield[1]))
			funcdetail[funcheader[1]] = tfop
		functionfd.close()
	return funcnameset,funcdetail

def get_functionheader(line):
	if len(line) and line[0] == "#":
		return 0
	field = line.split("\t")
	if len(field) != 2:
		return 0

	funcprototype = re.split("[(),]",field[0].strip())
	if not len(funcprototype):
		return 0
	funcheader = funcprototype[0].split(" ")
	if len(funcheader) != 2:
		return 0

	if funcheader[1][0] == "*":
		funcheader[1] = funcheader[1][1:len(funcheader[1])]
		funcheader[0] += "*"
	return field, funcprototype, funcheader

def get_tmpfunction(field, funcprototype, funcheader, ruledesresult):
	tmpfunction=function()
	tmpfunction.setfunctionname(funcheader[1])
	tmpfunction.setreturntype(funcheader[0])
	for i in range(1,len(funcprototype)):
		if funcprototype[i] == "":
			continue
		tmpfunction.addarg(funcprototype[i].strip())

	farglocat = field[1].split("")
	for glocatg in farglocat:
		glocat = glocatg.split(":")
		if len(glocat) != 4:
			continue
		if glocat[1].strip() == "string":
			tmpfunction.addfarg([int(glocat[0]),FARGTYPE.Vstring])
		elif glocat[1].strip() == "int":
			tmpfunction.addfarg([int(glocat[0]),FARGTYPE.Vint])
		elif glocat[1].strip() == "len":
			tmpfunction.addfarg([int(glocat[0]),FARGTYPE.Vlen])
		elif glocat[1].strip() == "none":
			tmpfunction.addfarg([int(glocat[0]),FARGTYPE.Vnone])
		tmpfunction.addrule(int(glocat[2]))
		tmpfunction.addruledes(ruledesresult[int(glocat[2])])
		tmpfunction.addlimit(glocat[3])
	
def reversedfs(node,time,prefix=""):
	msg = prefix
	msg += node.getmetadata() + " "
	for pnode in node.getparents():
		reversedfs(pnode[0],time+1,msg)
	if len(node.getparents()) == 0:
		print(msg)

def hex2str(hexstr):
	datad = hexstr
	fdata = ""
	if datad.lower().startswith("0x"):
		dfield = datad.split(",")
		for fditem in dfield:
			tmpdata = fditem.strip()
			if tmpdata.lower().startswith("0x"):
				tmpdata = tmpdata[2:]
				if len(tmpdata) % 2 == 1:
					tmpdata = "0" + tmpdata
				print(tmpdata)
				fdata += binascii.a2b_hex(tmpdata)[::-1]
			else:
				fdata = datad
	else:
		fdata = hexstr
	return fdata

def child_handler(childpro, ntinfo, node, execfuncdetail, tinfo):
	if childpro.externflag() and childpro.getexternfun() in execfuncdetail:
		execfunname = childpro.getexternfun()
		src = execfuncdetail[execfunname].getfuncsrc() - 1
		dest = execfuncdetail[execfunname].getfuncdest() - 1
		destv = 0
		destvtype = 0
		if dest < 4:
			destv = node.getcomarglist()[dest]
			destvtype = ARGTYPE.Voffset
			meta = ""
			vargtype = execfuncdetail[execfunname].getsrctype()
			ntinfo.addalllist(destv,destvtype,meta,vargtype,node.beginaddr,-1,"")
		else:
			destv = dest - 4
			destvtype = ARGTYPE.Vstackv
			meta = ""
			vargtype = execfuncdetail[execfunname].getsrctype()
			ntinfo.addalllist(destv,destvtype,meta,vargtype,node.beginaddr,-1,"")
		if src < 4:
			v = node.getcomarglist()[src]
			vtype = ARGTYPE.Voffset
			vargtype = execfuncdetail[execfunname].getsrctype()
			ntinfo.keyadddup(destv,destvtype,v,vtype)
		else:
			v = src - 4
			vtype = ARGTYPE.Vstackv
			vargtype = execfuncdetail[execfunname].getsrctype()
			ntinfo.keyadddup(destv,destvtype,v,vtype)
	elif childpro.externflag():
		for index in range(0,node.unfixedarglen()):
			offset = node.getunfixedarg(index)
			if tinfo.keyin(offset,ARGTYPE.Voffset):
				tinfo.setntrace(offset,ARGTYPE.Voffset)
	
	return ntinfo, tinfo

def info_walk(info, takeaction, actionv, actiont, alldata, irsb, node, offset):
	if info.ntlen() != 0:
		for sitem in reversed(irsb.statements):
			if sitem.tag == "Ist_IMark":
				if takeaction:
					takeaction = False
					for i in range(0, len(actionv)):
						info.setfaddr(actionv[i], actiont[i], sitem.addr)
						comment = ""
						dataaddr = 0x0
						if not info.gettrace(actionv[i], actiont[i]):
							continue
						if sitem.addr in node.lcom:
							comment = node.lcom[sitem.addr]
						else:
							continue
						#print(comment)
						if info.getargtype(actionv[i], actiont[i]) == FARGTYPE.Vstring:
							if (comment[0] == "\"" and comment[-1] == "\"") or (comment[0] == "\'" and comment[-1] == "\'"):
								info.setfresult(actionv[i], actiont[i],node.lcom[sitem.addr])
								info.setntrace(actionv[i], actiont[i])
						# elif info.getargtype(actionv[i], actiont[i]) == FARGTYPE.Vstring and comment[0] == "\'" and comment[-1] == "\'":
						# 	info.setfresult(actionv[i],actiont[i],node.lcom[sitem.addr])
						# 	info.setntrace(actionv[i], actiont[i])
							else:
								for dfitem in archdataformat:
									if comment.lower().startswith(dfitem):
										dataaddr = int(comment.lower()[len(dfitem):len(comment)],16) + offset
										if dataaddr in alldata:
											nprint = True
											datad = alldata[dataaddr]
											fdata = hex2str(datad)
											info.setfresult(actionv[i],actiont[i],fdata)
											info.setntrace(actionv[i], actiont[i])
											break
							#info.setntrace(actionv[i], actiont[i])
				actionv.clear()
				actiont.clear()
			elif sitem.tag == "Ist_Exit":
				continue
			elif sitem.tag == "Ist_Put":
				if info.keyin(sitem.offset,ARGTYPE.Voffset) and info.gettrace(sitem.offset,ARGTYPE.Voffset):
					eitem = sitem.data
					if eitem.tag == "Iex_Unop":
						pass
					elif eitem.tag == "Iex_Binop":
						pass
					elif eitem.tag == "Iex_Get":
						pass
					elif eitem.tag == "Iex_Load":
						pass
					elif eitem.tag == "Iex_RdTmp":
						takeaction = True
						info.keyupdate(sitem.offset,ARGTYPE.Voffset,eitem.tmp,ARGTYPE.Vtmp)
						actionv.append(eitem.tmp)
						actiont.append(ARGTYPE.Vtmp)
					elif eitem.tag == "Iex_Const":
						if info.getargtype(sitem.offset,ARGTYPE.Voffset) == FARGTYPE.Vint:
							takeaction = True
							info.setfresult(sitem.offset,ARGTYPE.Voffset,eitem.con.value)
							info.setntrace(sitem.offset,ARGTYPE.Voffset)
							actionv.append(sitem.offset)
							actiont.append(ARGTYPE.Voffset)
						elif info.getargtype(sitem.offset,ARGTYPE.Voffset) == FARGTYPE.Vstring:
							takeaction = True
							if eitem.con.value in alldata:
								if isinstance(alldata[eitem.con.value],int) and alldata[eitem.con.value] in alldata:	
									fresult = hex2str(alldata[alldata[eitem.con.value]])
								elif not isinstance(alldata[eitem.con.value],int):
									fresult = hex2str(alldata[eitem.con.value])
	
								info.setfresult(sitem.offset,ARGTYPE.Voffset,fresult)
								info.setntrace(sitem.offset,ARGTYPE.Voffset)

							else:
								info.setfresult(sitem.offset,ARGTYPE.Voffset,eitem.con.value)
								info.setntrace(sitem.offset,ARGTYPE.Voffset)
								actionv.append(sitem.offset)
								actiont.append(ARGTYPE.Voffset)

			elif sitem.tag == "Ist_WrTmp":
				if info.keyin(sitem.tmp,ARGTYPE.Vtmp) and info.gettrace(sitem.tmp,ARGTYPE.Vtmp):
					eitem = sitem.data
					if eitem.tag == "Iex_Unop":
						pass
					elif eitem.tag == "Iex_RdTmp":
						info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,eitem.tmp,ARGTYPE.Vtmp)
					elif eitem.tag == "Iex_Load":
						laddr = eitem.addr
						if info.getargtype(sitem.tmp,ARGTYPE.Vtmp) == FARGTYPE.Vstring:
							if laddr.tag == "Iex_Const":
								if laddr.con.value in alldata and isinstance(alldata[laddr.con.value],int)and alldata[laddr.con.value] in alldata:	
									fresult = hex2str(alldata[alldata[laddr.con.value]])
								elif laddr.con.value in alldata and not isinstance(alldata[laddr.con.value],int):
									fresult = hex2str(alldata[laddr.con.value])
								info.setfresult(sitem.tmp,ARGTYPE.Vtmp,fresult)
								info.setntrace(sitem.tmp,ARGTYPE.Vtmp)
								takeaction = True
							elif laddr.tag == "Iex_RdTmp" and info.gettrace(sitem.tmp,ARGTYPE.Vtmp):
								v = 0
								vtype = ARGTYPE.Vunkown
								if node.instack(laddr.tmp,ARGTYPE.Vtmp):
									tmpvstackdata = node.getstackdata(laddr.tmp,ARGTYPE.Vtmp)
									v = tmpvstackdata[0]
									vtype = tmpvstackdata[1]
								if vtype == ARGTYPE.Voffset:
									info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,v,vtype)
								elif vtype == ARGTYPE.Vtmp:
									info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,v,vtype)
								elif vtype == ARGTYPE.Vconst:
									if v in alldata and isinstance(alldata[v],int)and alldata[v] in alldata:	
										fresult = hex2str(alldata[alldata[v]])
									elif v in alldata and not isinstance(alldata[v],int):
										fresult = hex2str(alldata[laddr.con.value])
									info.setfresult(sitem.tmp,ARGTYPE.Vtmp,fresult)
									info.setntrace(sitem.tmp,ARGTYPE.Vtmp)
									takeaction = True
								elif vtype == ARGTYPE.Vunkown:
									info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,laddr.tmp,ARGTYPE.Vtmp)
									actionv.append(laddr.tmp)
									actiont.append(ARGTYPE.Vtmp)
						elif info.getargtype(sitem.tmp,ARGTYPE.Vtmp) == FARGTYPE.Vint:
							if laddr.tag == "Iex_Const":
								info.setfresult(sitem.tmp,ARGTYPE.Vtmp,laddr.con.value)
								info.setntrace(sitem.tmp,ARGTYPE.Vtmp)
							elif laddr.tag == "Iex_RdTmp" and node.instack(laddr.tmp,ARGTYPE.Vtmp):
								takeaction = True
								stacklocatinfo = node.getstackdata(laddr.tmp ,ARGTYPE.Vtmp)
								v = stacklocatinfo[0]
								vtype = stacklocatinfo[1]
								if vtype == ARGTYPE.Voffset:
									info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,v,ARGTYPE.Voffset)
								elif vtype == ARGTYPE.Vtmp:
									info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,v,ARGTYPE.Vtmp)
								elif vtype == ARGTYPE.Vconst:
									info.setfresult(sitem.tmp,ARGTYPE.Vtmp,v)
									info.setntrace(sitem.tmp,ARGTYPE.Vtmp)
							elif laddr.tag == "Iex_RdTmp":
								info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,laddr.tmp,ARGTYPE.Vtmp)
					elif eitem.tag == "Iex_Const":
						if info.getargtype(sitem.tmp,ARGTYPE.Vtmp) == FARGTYPE.Vint:
							takeaction = True
							info.setfresult(sitem.tmp,ARGTYPE.Vtmp,eitem.con.value)
							info.setntrace(sitem.tmp,ARGTYPE.Vtmp)
							actionv.append(sitem.tmp)
							actiont.append(ARGTYPE.Vtmp)
					elif eitem.tag == "Iex_Binop":
						takeaction = True
					elif eitem.tag == "Iex_Get":
						takeaction = True
						info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,eitem.offset,ARGTYPE.Voffset)
						actionv.append(eitem.offset)
						actiont.append(ARGTYPE.Voffset)
			elif sitem.tag == "Ist_Store":
				if sitem.addr.tag == "Iex_Const":
					if info.keyin(sitem.addr.constants[0].value,ARGTYPE.Vconst) and info.gettrace(sitem.addr.constants[0].value,ARGTYPE.Vconst):
						eitem = sitem.data
						if eitem.tag == "Iex_Const":
							if info.getargtype(sitem.addr.constants[0].value,ARGTYPE.Vconst) == FARGTYPE.Vint:
								info.setfresult(sitem.addr.constants[0].value,ARGTYPE.Vconst,eitem.con.value)
								info.setntrace(sitem.addr.constants[0].value,ARGTYPE.Vconst)
								takeaction = True
							elif info.getargtype(sitem.addr.constants[0].value,ARGTYPE.Vconst) == FARGTYPE.Vstring:
								if eitem.con.value in alldata and isinstance(alldata[eitem.con.value],int)and alldata[eitem.con.value] in alldata:	
									fresult = hex2str(alldata[alldata[eitem.con.value]])
									info.setfresult(sitem.addr.constants[0].value,ARGTYPE.Vconst,fresult)
									info.setntrace(sitem.addr.constants[0].value,ARGTYPE.Vconst)
									takeaction = True
								elif eitem.con.value in alldata and not isinstance(alldata[eitem.con.value],int):
									fresult = hex2str(alldata[eitem.con.value])
									info.setfresult(sitem.addr.constants[0].value,ARGTYPE.Vconst,fresult)
									info.setntrace(sitem.addr.constants[0].value,ARGTYPE.Vconst)
									takeaction = True
								else:
									info.keyupdate(sitem.addr.constants[0].value,ARGTYPE.Vconst,eitem.con.value,ARGTYPE.Vconst)
									actionv.append(eitem.con.value)
									actiont.append(ARGTYPE.Vconst)
									takeaction = True
						elif eitem.tag == "Iex_RdTmp":
							if info.getargtype(sitem.addr.constants[0].value,ARGTYPE.Vconst) == FARGTYPE.Vint:
								if node.instack(eitem.tmp,ARGTYPE.Vtmp):
									takeaction = True
									stacklocatinfo = node.getstackdata(eitem.tmp ,ARGTYPE.Vtmp)
									v = stacklocatinfo[0]
									vtype = stacklocatinfo[1]
									if vtype == ARGTYPE.Voffset:
										info.keyupdate(sitem.addr.constants[0].value,ARGTYPE.Vconst,v,ARGTYPE.Voffset)
									elif vtype == ARGTYPE.Vtmp:
										info.keyupdate(sitem.addr.constants[0].value,ARGTYPE.Vconst,v,ARGTYPE.Vtmp)
									elif vtype == ARGTYPE.Vconst:
										info.setfresult(sitem.addr.constants[0].value,ARGTYPE.Vconst,v)
										info.setntrace(sitem.addr.constants[0].value,ARGTYPE.Vconst)
							elif info.getargtype(sitem.addr.constants[0].value,ARGTYPE.Vconst) == FARGTYPE.Vstring:
								v = 0
								vtype = ARGTYPE.Vunkown
								if node.instack(eitem.tmp,ARGTYPE.Vtmp):
									tmpvstackdata = node.getstackdata(eitem.tmp,ARGTYPE.Vtmp)
									v = tmpvstackdata[0]
									vtype = tmpvstackdata[1]
								if vtype == ARGTYPE.Voffset:
									info.keyupdate(sitem.addr.constants[0].value,ARGTYPE.Vconst,v,vtype)
								elif vtype == ARGTYPE.Vtmp:
									info.keyupdate(sitem.addr.constants[0].value,ARGTYPE.Vconst,v,vtype)
								elif vtype == ARGTYPE.Vconst:
									if v in alldata and isinstance(alldata[v],int)and alldata[v] in alldata:	
										fresult = hex2str(alldata[alldata[v]])
										info.setfresult(sitem.addr.constants[0].value,ARGTYPE.Vconst,fresult)
										info.setntrace(sitem.addr.constants[0].value,ARGTYPE.Vconst)
										takeaction = True
									elif v in alldata and not isinstance(alldata[v],int):
										fresult = hex2str(alldata[laddr.con.value])
										info.setfresult(sitem.addr.constants[0].value,ARGTYPE.Vconst,fresult)
										info.setntrace(sitem.addr.constants[0].value,ARGTYPE.Vconst)
										takeaction = True
								elif vtype == ARGTYPE.Vunkown:
									info.keyupdate(sitem.addr.constants[0].value,ARGTYPE.Vconst,eitem.tmp,ARGTYPE.Vtmp)
									actionv.append(eitem.tmp)
									actiont.append(ARGTYPE.Vtmp)
									takeaction = True
				elif sitem.addr.tag == "Iex_RdTmp":
					if info.keyin(sitem.addr.tmp,ARGTYPE.Vtmp) and info.gettrace(sitem.addr.tmp,ARGTYPE.Vtmp):
						eitem = sitem.data
						if eitem.tag == "Iex_Const":
							if info.getargtype(sitem.addr.tmp,ARGTYPE.Vtmp,ARGTYPE.Vconst) == FARGTYPE.Vint:
								info.setfresult(sitem.addr.tmp,ARGTYPE.Vtmp,eitem.con.value)
								info.setntrace(sitem.addr.tmp,ARGTYPE.Vtmp)
								takeaction = True
							elif info.getargtype(sitem.addr.tmp,ARGTYPE.Vtmp,ARGTYPE.Vconst) == FARGTYPE.Vstring:
								if eitem.con.value in alldata and isinstance(alldata[eitem.con.value],int)and alldata[eitem.con.value] in alldata:	
									fresult = hex2str(alldata[alldata[eitem.con.value]])
									info.setfresult(sitem.addr.tmp,ARGTYPE.Vtmp,fresult)
									info.setntrace(sitem.addr.tmp,ARGTYPE.Vtmp,ARGTYPE.Vconst)
									# takeaction = True
								elif eitem.con.value in alldata and not isinstance(alldata[eitem.con.value],int):
									fresult = hex2str(alldata[eitem.con.value])
									info.setfresult(sitem.addr.tmp,ARGTYPE.Vtmp,fresult)
									info.setntrace(sitem.addr.tmp,ARGTYPE.Vtmp)
									# takeaction = True
								else:
									info.keyupdate(sitem.addr.tmp,ARGTYPE.Vtmp,eitem.con.value,ARGTYPE.Vconst)
									actionv.append(eitem.con.value)
									actiont.append(ARGTYPE.Vconst)
								takeaction = True
						elif eitem.tag == "Iex_RdTmp":
							if info.getargtype(sitem.addr.tmp,ARGTYPE.Vtmp) == FARGTYPE.Vint:
								if node.instack(eitem.tmp,ARGTYPE.Vtmp):
									takeaction = True
									stacklocatinfo = node.getstackdata(eitem.tmp ,ARGTYPE.Vtmp)
									v = stacklocatinfo[0]
									vtype = stacklocatinfo[1]
									if vtype == ARGTYPE.Voffset:
										info.keyupdate(sitem.addr.tmp,ARGTYPE.Vtmp,v,ARGTYPE.Voffset)
									elif vtype == ARGTYPE.Vtmp:
										info.keyupdate(sitem.addr.tmp,ARGTYPE.Vtmp,v,ARGTYPE.Vtmp)
									elif vtype == ARGTYPE.Vconst:
										info.setfresult(sitem.addr.tmp,ARGTYPE.Vtmp,v)
										info.setntrace(sitem.addr.tmp,ARGTYPE.Vtmp)
							elif info.getargtype(sitem.addr.tmp,ARGTYPE.Vtmp) == FARGTYPE.Vstring:
								v = 0
								vtype = ARGTYPE.Vunkown
								if node.instack(eitem.tmp,ARGTYPE.Vtmp):
									tmpvstackdata = node.getstackdata(eitem.tmp,ARGTYPE.Vtmp)
									v = tmpvstackdata[0]
									vtype = tmpvstackdata[1]
								if vtype == ARGTYPE.Voffset:
									info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,v,vtype)
								elif vtype == ARGTYPE.Vtmp:
									info.keyupdate(sitem.tmp,ARGTYPE.Vtmp,v,vtype)
								elif vtype == ARGTYPE.Vconst:
									if v in alldata and isinstance(alldata[v],int)and alldata[v] in alldata:	
										fresult = hex2str(alldata[alldata[v]])
									elif v in alldata and not isinstance(alldata[v],int):
										fresult = hex2str(alldata[laddr.con.value])
							
									info.setfresult(sitem.addr.tmp,ARGTYPE.Vtmp,fresult)
									info.setntrace(sitem.addr.tmp,ARGTYPE.Vtmp)
									takeaction = True
									
								elif vtype == ARGTYPE.Vunkown:
									info.keyupdate(sitem.addr.tmp,ARGTYPE.Vtmp,eitem.tmp,ARGTYPE.Vtmp)
									actionv.append(eitem.tmp)
									actiont.append(ARGTYPE.Vtmp)
							info.keyupdate(sitem.addr.tmp,ARGTYPE.Vtmp,eitem.tmp,ARGTYPE.Vtmp)
							actionv.append(eitem.tmp)
							actiont.append(ARGTYPE.Vtmp)
							takeaction = True	
	return info, takeaction, actionv, actiont

def reversetracedfs(nodeset,tinfo,offset,alldata,soffset,depth,execfuncdetail,allfn,middlefunc,ef,detailreport,wfuncset,pathroad):
	global starttime
	
	node = nodeset[0]
	irsb = node.getirsb()
	takeaction = False
	actionv = list()
	actiont = list()
	ntinfo = traceinfo()
	slidechild = nodeset[1]
	childlocat = nodeset[2]
	# msg = ""
	# for i in range(0,time):
	# 	msg +=" "
	# msg += "0x%X"%node.beginaddr
	# print(msg)

	nowtime = time.time()
	#print(int(nowtime-starttime))
	if int(nowtime - starttime)/60 >= 2:
		return
	if node.beginaddr in pathroad:
		return
	else:
		pathroad.add(node.beginaddr)
	for i in range(0, childlocat):
		if slidechild == CHILRENSLIDE.Vleft:
			childpro = node.getleftchildren()[i]
			ntinfo, tinfo = child_handler(childpro, ntinfo, node, execfuncdetail, tinfo)
			# 
			#if childpro.externflag() and childpro.getexternfun() in wfuncset:
			#	print(childpro.getexternfun())
			
		elif slidechild == CHILRENSLIDE.Vright:
			childpro = node.getrightchildren()[i]
			ntinfo, tinfo = child_handler(childpro, ntinfo, node, execfuncdetail, tinfo)
			# 

	for i in range(0,len(tinfo.vtypel)):

		offset = tinfo.vl[i] + soffset
		nd_s = node.stack[offset]

		if tinfo.vtypel[i] != ARGTYPE.Vstackv or offset >= len(node.stack):
			continue
		elif offset < 0:
			tinfo.setntrace(tinfo.vl[i], tinfo.vtypel[i])

		elif nd_s[1] == ARGTYPE.Vtmp:
			if str(nd_s[0]) + " " + str(nd_s[1]) in node.sprelate:
				for spitem in node.sprelate:
					if node.sprelate[str(nd_s[0]) + " " + str(nd_s[1])] == node.sprelate[spitem] and str(nd_s[0]) + " " + str(nd_s[1]) != spitem:
						field = spitem.split(" ")
						tinfo.keyadddup(tinfo.vl[i],tinfo.vtypel[i],int(field[0]),field[1])
			tinfo.keyupdate(tinfo.vl[i],tinfo.vtypel[i],nd_s[0],nd_s[1])
		elif nd_s[1] == ARGTYPE.Vconst:
			if tinfo.getargtype(tinfo.vl[i],tinfo.vtypel[i]) == FARGTYPE.Vint:
				tinfo.setfresult(tinfo.vl[i],tinfo.vtypel[i],nd_s[0])
				tinfo.setntrace(tinfo.vl[i],tinfo.vtypel[i])
			elif tinfo.getargtype(tinfo.vl[i],tinfo.vtypel[i]) == FARGTYPE.Vstring:
				if nd_s[0] in alldata and isinstance(alldata[nd_s[0]],int) and alldata[nd_s[0]] in alldata:	
					fresult = hex2str(alldata[alldata[nd_s[0]]])
					tinfo.setfresult(tinfo.vl[i],tinfo.vtypel[i],fresult)
					tinfo.setntrace(tinfo.vl[i],tinfo.vtypel[i])
				elif nd_s[0] in alldata and not isinstance(alldata[nd_s[0]],int):
					fresult = hex2str(alldata[nd_s[0]])
					tinfo.setfresult(tinfo.vl[i],tinfo.vtypel[i],fresult)
					tinfo.setntrace(tinfo.vl[i],tinfo.vtypel[i])
				else:
					tinfo.keyupdate(tinfo.vl[i],tinfo.vtypel[i],nd_s[0],nd_s[1])
		elif nd_s[1] == ARGTYPE.Voffset:
			if str(nd_s[0]) + " " + str(nd_s[1]) in node.sprelate:
				for spitem in node.sprelate:
					if node.sprelate[str(nd_s[0]) + " " + str(nd_s[1])] == node.sprelate[spitem] and not str(nd_s[0]) + " " + str(nd_s[1]) == spitem:
						field = spitem.split(" ")
						tinfo.keyadddup(tinfo.vl[i],tinfo.vtypel[i],int(field[0]),field[1])
			tinfo.keyupdate(tinfo.vl[i],tinfo.vtypel[i],nd_s[0],nd_s[1])

	ntinfo, takeaction, actionv, actiont = info_walk(ntinfo, takeaction, actionv, actiont, alldata, irsb, node, offset)
	
	# #if node.beginaddr == 0x402dd8 or node.beginaddr == 0x10550:
	# #	print("vbegin0x%X"%node.beginaddr)
	# #	tinfo.listdebugpp()
	# #	print(node.stack)
	# #	print(node.sprelate)
	# for i in range(0,tinfo.alllen()):
	# 	vv = tinfo.getindexvl(i)
	# 	vtypev = tinfo.getindexvtypel(i)
	# 	if ntinfo.keyin(vv,vtypev) and not ntinfo.gettrace(vv,vtypev):
	# 		tinfo.setfresult(vv,vtypev,ntinfo.getfresult(vv,vtypev))
	# 		tinfo.setfaddr(vv,vtypev,ntinfo.getfaddr(vv,vtypev))
	# 		tinfo.setntrace(vv,vtypev)
	#if node.beginaddr == 0x402dd8 or node.beginaddr == 0x10550:
	#	print("begin0x%X"%node.beginaddr)
	#	tinfo.listdebugpp()
	tinfo, takeaction, actionv, actiont = info_walk(tinfo, takeaction, actionv, actiont, alldata, irsb, node, offset)
	#if node.beginaddr == 0x402dd8 or node.beginaddr == 0x10550:
	#	print("middle0x%X"%node.beginaddr)
	#	tinfo.listdebugpp()
	#	print(node.stack)
	#	print(node.sprelate)
	for i in range(0,tinfo.alllen()):
		vv = tinfo.getindexvl(i)
		vtypev = tinfo.getindexvtypel(i)
		if ntinfo.keyin(vv,vtypev) and not ntinfo.gettrace(vv,vtypev):
			tinfo.setfresult(vv,vtypev,ntinfo.getfresult(vv,vtypev))
			tinfo.setfaddr(vv,vtypev,ntinfo.getfaddr(vv,vtypev))
			tinfo.setntrace(vv,vtypev)

	for i in range(0,len(tinfo.vtypel)):
		if tinfo.vtypel[i] == ARGTYPE.Vconst:
			v = tinfo.vl[i]
			if v in alldata:
				tinfo.setfresult(v,tinfo.vtypel[i],alldata[v])
				tinfo.setntrace(v,tinfo.vtypel[i])
	for i in range(0,len(tinfo.vtypel)):
		if not tinfo.vtypel[i] == ARGTYPE.Vtmp:
			continue
		elif not (tinfo.keyin(tinfo.vl[i],tinfo.vtypel[i]) and tinfo.gettrace(tinfo.vl[i],tinfo.vtypel[i])):
			continue
		elif not str(tinfo.vl[i]) + " " + str(tinfo.vtypel[i]) in node.sprelate:
			continue
		else:
			tinfo.keyupdate(tinfo.vl[i],tinfo.vtypel[i],node.sprelate[str(tinfo.vl[i]) + " " + str(tinfo.vtypel[i])]/node.getwordlen() + node.stackfixnum,ARGTYPE.Vstackv)
	#if node.beginaddr == 0x402dd8 or node.beginaddr == 0x10550:
	#	print("end0x%X"%node.beginaddr)
	#	tinfo.listdebugpp()
	#	print(node.stack)
	#	print(node.sprelate)
	tinfo.listallpp(detailreport)
	tinfo.settntrace()
	if node.beginaddr in allfn:
		dfun = traceinfo2func(tinfo,node,allfn[node.beginaddr])
		if dfun.getfunctionname() in ef:
			middlefunc[dfun.getfunctionname()] = dfun
	if tinfo.ntlen() == 0:
		return
	for pitem in node.getparents():
		reversetracedfs(pitem,traceinfocopy(tinfo),offset,alldata,node.stackoffset,depth+1,execfuncdetail,allfn,middlefunc,ef,detailreport,wfuncset,copy.copy(pathroad))

def reversetrans(nodeset,function,offset,alldata,execfuncdetail,allfuncn,ef,detailreport,wfuncset):
	middlefunc = dict()
	
	node = nodeset[0]
	ti = func2traceinfo(function, node.beginaddr)
	reversetracedfs(nodeset,ti,offset,alldata,0,1,execfuncdetail,allfuncn,middlefunc,ef,detailreport,wfuncset,set())
	return middlefunc

def transbin2IR(filename,outputname,importfc = dict()):
	global nextblocktime
	# global binfo.externfunctions
	global starttime

	outputtime = outputname + "time"
	print("time:%s"%outputtime)

	testbegintime = time.time()
	print("beginlift")

	result = dict()
	detailreport = dict()
	# cfg = None
	alladdrset = set()
	mycfg = dict()

	## match the misuse rule
	#
	# funcnameset,funcdetail,ruledesdic,wfuncset,wfuncdetail = rulematch()
	rulematach = Rulematch(misuseprofile_path)
	funcnameset = rulematach.funcnameset.union(list(importfc.keys()))
	rulematach.funcdetail.update(importfc)

	## get necessary info from binary file
	#
	# binfile,allfunc,allfuncname,lcom,pltstype,rodatatype,datatype,functiondata,functionsp,innerfunctions,externfunctions,functionmap,alldata,externfuncset = binlcominfo(filename)
	binfo = Binlcominfo(filename)
	
	if os.path.getsize(binfo.binfile) / float(1024*1024) > 10:
		return result, detailreport
	print("size:%d"%os.path.getsize(binfo.binfile))
	#if len(externfuncset&funcnameset) == 0:
	#	return result,detailreport
	
	## analysis the format of file
	#
	exportedfunc = nmfile(binfo.binfile)
	print(binfo.binfile)

	## judge the file type of binary file
	#	
	proj = angr.Project(binfo.binfile,load_options={'auto_load_libs': False})
	resulttype, offset = execorlib(binfo.binfile)
	
	## get CFG， for test
	#
	# try:
	# 	if resulttype == FILETYPE.Vxexec or resulttype == FILETYPE.Vlibobj:
	# 		cfg = proj.analyses.CFG()
	# 	# else:
	# 	# 	cfg = proj.analyses.CFG()
	# except BaseException:
	# 	print("BaseException")
	# 	# testendtime = time.time()
	# 	# wtime = testendtime - testbegintime
	# 	# writetime(outputtime, "lift to IR", wtime)
	# 	# print("lift to IR %f" %wtime)
	# 	write_endtime(outputtime, testbegintime, "lift to IR")
	# 	return result,detailreport
	# except Exception:
	# 	print("Exception")
	# 	# testendtime = time.time()
	# 	# wtime = testendtime - testbegintime
	# 	# writetime(outputtime, "lift to IR", wtime)
	# 	# print("lift to IR %f" %wtime)
	# 	write_endtime(outputtime, testbegintime, "lift to IR")
	# 	return result, detailreport

	funcdic = dict(proj.kb.functions)
	# msg = ""

	#wfd = open("/home/zhangli/zhangli/1.txt","w")
	# for item in funcdic:
		# d = funcdic[item]
		#print(dir(d))
		# blockset = d.block_addrs_set
		# bl = list(blockset)
		# for b in bl:
			# block = proj.factory.block(b)
			# irsb = block.vex
			# functionnode = problock(irsb,binfo.lcom)
			# msg = functionnode.getstr()
			#wfd.write(msg)
	#wfd.close()
	print("endlift")
	write_endtime(outputtime, testbegintime, "lift to IR")
	# testendtime = time.time()
	# wtime = testendtime - testbegintime
	# writetime(outputtime, "lift to IR", wtime)
	# print("lift to IR %f" %wtime)
	
	## construct my cfg
	binfo.externfunctions.clear()
	for item in funcdic:
		alladdrset = alladdrset.union(funcdic[item].block_addrs_set)
	
	testbegintime = time.time()
	
	for item in funcdic:
		if not len(funcdic[item].block_addrs_set):
			continue
		b = funcdic[item].addr
		if b in mycfg:
			continue
		block=proj.factory.block(b)
		irsb = block.vex
		node=problock(irsb,binfo.lcom)
		starttime = time.time()
		node,leafset = constructmycfg(node,proj,binfo.functionmap,binfo.lcom,binfo.externfunctions,mycfg,alladdrset,copy.copy(set()),0,None)
		mycfg[b] = [node,leafset]
	# testendtime = time.time()
	# wtime = testendtime-testbegintime
	# writetime(outputtime,"construct cfg",wtime)
	# print("construct cfg %f"%wtime)
	write_endtime(outputtime, testbegintime, "construct cfg")
	print(nextblocktime)

	execfuncset,execfuncdetail = execfunction()
	
	for key in binfo.lcom:
		if len(binfo.lcom[key]):
			binfo.lcom[key] = binfo.lcom[key][1:]

	testbegintime = time.time()
	for item in binfo.externfunctions:
		for elitem in binfo.externfunctions[item]:
			if not elitem.getexternfun() in funcnameset:
				continue
			function = rulematach.funcdetail[elitem.getexternfun()]
			print(elitem.getexternfun())
			for pitem in elitem.getparents():
				finishfuncdetail(function, pitem[0])
				#global starttime
				starttime = time.time()
				tmpresult = reversetrans(pitem,function,offset,binfo.alldata,execfuncdetail,binfo.allfunctionname,exportedfunc,detailreport,rulematach.wfuncset)
				result.update(tmpresult)

	# testendtime = time.time()
	# wtime = testendtime-testbegintime
	# writetime(outputtime,"tain", wtime)
	# print("tain %f"%wtime)
	write_endtime(outputtime, testbegintime, "tain")
	return result, detailreport