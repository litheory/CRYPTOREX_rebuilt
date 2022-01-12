import angr
import pyvex
import subprocess
# import io
# import string

import sys
import os
# import pwd

import gzip
import zipfile
import tarfile
import rarfile

import magic
import binwalk
import shutil
import argparse
# import subprocess

from bin2ir3 import idarun
from bin2ir3 import transbin2IR
import config

from enum import Enum
import copy
import re
import time

#statistical information
numdecompress = 0
numfirmware = 0
numextracted = 0

allruleresult = dict()
soset = dict()
execset = dict()
name2path = dict()
ousingrandset = dict()

cryptlibset = {"libcrypto", "libcrypt", "libssl", "libgcrypt", "libwolfssl", "libmcrypt"}

class randtype(Enum):
	Orand = 1
	Osrand = 2
	Orsrand = 3
	Nrand = 4

class compressmethod(Enum):
	Egz = 0
	Etar = 1
	Etgz = 2
	Ezip = 3
	Erar = 4
	Edir = -2
	Eunknown = -1

def getcompressmethod(filename):
	result = compressmethod.Eunknown
	if os.path.isdir(filename):
		result = compressmethod.Edir
		return result
	filetype = _get_filetype(filename)
	if filetype == "application/gzip":
		result = compressmethod.Egz
	elif filetype == "application/x-tar":
		result = compressmethod.Etar
	elif filetype == "application/zip":
		result = compressmethod.Ezip
	elif filetype == "application/x-rar":
		result = compressmethod.Erar
	return result


def filenameformat(filename):
	filename = filename.replace("(","\\(")
	filename = filename.replace(")","\\)")
	return filename
	

def _get_filetype(data,mime=True):
	return magic.from_file(data,mime)

def un_gz(filename,outputpath):
	g_file = gzip.GzipFile(filename)
	dirname = path2filename(filename)
	open(outputpath +"/" + dirname , "w+").write(g_file.read())
	g_file.close()
	return outputpath +"/" + dirname

def un_tar(filename,outputpath):
	tar = tarfile.open(filename)
	names = tar.getnames()
	dirname = path2filename(filename)
	if os.path.isdir(outputpath+"/" + dirname):
		pass
	else:
		os.mkdir(outputpath+"/"+dirname)
	for name in names:
		tar.extract(name,outputpath + "/" + dirname +"/")
	tar.close()
	return outputpath+"/" + dirname
	


def un_zip(file_name,outputpath):
	zip_file = zipfile.ZipFile(file_name)
	dirname = path2filename(file_name)
	if os.path.isdir(outputpath+"/" + dirname):
		pass
	else:
		os.mkdir(outputpath+"/" + dirname)
	for names in zip_file.namelist():
		print(names)
		try:
			zip_file.extract(names,outputpath+"/" + dirname+ "/")
		except zipfile.BadZipfile as err:
			print(err)
			print(outputpath+"/" + dirname)
		#finally:
			#print("return")
			#return
	zip_file.close()
	return outputpath+"/" + dirname

def un_rar(filename,outputpath):
	rar = rarfile.RarFile(filename)
	dirname = path2filename(filename)
	if os.path.isdir(outputpath + "/" + dirname):
		pass
	else:
		os.mkdir(outputpath + "/" + dirname)
	pwd = os.getcwd()
	os.chdir(outputpath + "/" + dirname)
	rar.extractall()
	rar.close()
	os.chdir(pwd)
	return outputpath + "/" + dirname


def decompress(file_name,outputdir,dc = True):
	filetype = getcompressmethod(file_name)
	#print(file_name)
	global numdecompress
	if filetype == compressmethod.Ezip:
		try:
			if dc:
				numdecompress += 1
			un_zip(file_name,outputdir)
		except BaseException as err:
			print(file_name)
	elif filetype == compressmethod.Erar:
		try:
			un_rar(file_name,outputdir)
			if dc:
				numdecompress += 1
		except BaseException as err:
			print(file_name)
	elif filetype == compressmethod.Egz:
		tmpresult = un_gz(file_name,outputdir)
		if dc:
			numdecompress += 1
		filetype2 = getcompressmethod(tmpresult)
		if not filetype2 == compressmethod.Eunknown:
			decompress(tmpresult,outputdir,dc = False)
		os.remove(tmpresult)
	elif filetype == compressmethod.Etar:
		un_tar(file_name,outputdir)
		if dc:
			numdecompress += 1
	elif filetype == compressmethod.Etgz:
		pass
	elif filetype == compressmethod.Eunknown:
		shutil.copyfile(file_name, outputdir + getfilenamefrompath(file_name))
		pass
	return True

def nmfile(sofile):
	result = set()
	sofile =filenameformat(sofile)
	filetype = _get_filetype(sofile)
	if not filetype == "application/x-sharedlib":
		return result
	output = os.popen("nm -D " + sofile)
	allline = output.read().split("\n")
	for line in allline:
		field = line.split(" ")
		if not len(field) == 3 or not field[1] == "T":
			continue
		result.add(field[2])
	return result


def extractfile(filename,outputdir):
	filetype = _get_filetype(filename)
	if any(s in [filetype] for s in ["application/x-executable",
					"application/x-dosexec",
					"application/x-object",
					"application/pdf",
					"application/msword",
					"image/", "text/", "video/"]):
		return
	filetype = _get_filetype(filename,mime=False)
	if any(s in [filetype] for s in ["executable", "universal binary",
					"relocatable", "bytecode", "applet"]):
		return
	print(filename)
	pwd = os.getcwd()
	os.chdir(outputdir)
	global numfirmware
	numfirmware += 1
	for module in binwalk.scan(filename,"-0","root","-e" ,"-y", "filesystem", signature=True, quiet=True, extract=True):
		print("%s Results:" % module.name)
		for result in module.results:
			if result.file.path in module.extractor.output:
				if result.offset in module.extractor.output[result.file.path].extracted:
					print("Extracted '%s' at offset 0x%X from '%s' to '%s'" % (result.description.split(',')[0],result.offset,result.file.path,str(module.extractor.output[result.file.path].extracted[result.offset])))
	os.chdir(pwd)
	return True


def getfilenamefrompath(path):
	return path[path.rindex("/") + 1:len(path)]

class archtype(Enum):
	Elarm = 0
	Elmips = 1
	Eunknown = -1

def libformat(libname,filetype):
	result = ""
	if not filetype == "application/x-sharedlib":
		return result
	lindex = 0
	if not libname.find("/") == -1:
		lindex = libname.rindex("/")+1
	if not libname.find(".so") == -1:
		result = libname[lindex:libname.find(".so")].strip()
	elif not libname.find(".a") == -1:
		result = libname[lindex:libname.find(".a")].strip()
	else:
		result = libname[lindex:len(libname)]
	return result
	

def listallso(filename,arch):
	# soset = set()
	# commandstr = ""
	# if arch == archtype.Elmips:
	# 	commandstr = "$HOME/buildroot/output/host/bin/ldd"
	# elif arch == archtype.Elarm:
	# 	commandstr = "$HOME/armbuildroot/output/host/bin/ldd"
	# else:
	# 	return soset
	# filename = filenameformat(filename)
	# (status,output) = subprocess.getstatusoutput( commandstr + ' ' + filename)
	# #print(output)
	# #print(filename)
	# #print(filename)
	# outstr = output.splitlines()
	# for line in outstr:
	# 	if "=>" in line:
	# 		soname = line.split("=>")[0]
	# 		#print(soname)
	# 		if not soname.find(".so") == -1:
	# 			soname = soname[:soname.find(".so")].strip()
	# 		elif not soname.find(".a") == -1:
	# 			soname = soname[:soname.find(".a")].strip()
	# 		soset.add(soname)
	# return soset
	soset = set()
	filename = filenameformat(filename)
	# print('list so from: ' + filename)
	output = subprocess.getoutput('readelf -a ' + filename + ' | grep \"Shared library\"')
	outlines = output.splitlines()
	for line in outlines:
		so = line.split()[-1].replace('[', '').replace(']', '')
		so = so.split('.')[0]
		soset.add(so)
		# print('Shared lib: ' + so)
	return soset
	
def _getarch(filename):
	result = archtype.Eunknown
	filetype = ""
	filename = filenameformat(filename)
	filetype = _get_filetype(filename)
	if not any(s in [filetype] for s in ["application/x-executable","application/x-sharedlib"]):
		return result
	(status,output) = subprocess.getstatusoutput('readelf -h ' + filename)
	outstr = output.splitlines()
	if not len(outstr) > 9:
		return result
	fields=outstr[8].split()
	if not len(fields) > 1:
		return result
	if fields[1] == "ARM":
		result = archtype.Elarm
	elif fields[1] == "MIPS":
		result = archtype.Elmips
	return result

def isusecrypt(filename,arch):
	filename = filenameformat(filename)
	result = False
	if arch == archtype.Elarm:
		(status,output) = subprocess.getstatusoutput('armobjdump.sh ' + filename + " | grep -E -i \"gcry|EVP|CAST|SSL|encry|cry|aes|DES|decry\"")
		if(len(output) > 0):
			outstr = output.splitlines()
			outputline = filename
			for line in outstr:
				allfield = line.split()
				if(len(allfield) == 2):
					outputline += " " + allfield[1][0:len(allfield[1])-1]
			print(outputline)
			result = True
	elif arch == archtype.Elmips:
		(status,output) = subprocess.getstatusoutput('mipsobjdump.sh ' + filename + " | grep -E -i \"gcry|EVP|CAST|SSL|encry|cry|aes|DES|decry\"")
		if(len(output) > 0):
                        outstr = output.splitlines()
                        outputline = filename
                        for line in outstr:
                                allfield = line.split()
                                if(len(allfield) == 2): 
                                        outputline += " " + allfield[1][0:len(allfield[1])-1]
                        print(outputline)
                        result = True
	else:
		pass
	return result

def filterfile(filename,outputdir):
	arch = _getarch(filename)
	#print(filename)
	#soset = listallso(filename,arch)
	#if len(soset) == 0:
	#	return
	'''for so in soset:
		
		if "libgcry" in so or "libcry" in so or "libssl" in so or "libgcry" in so: 
			shutil.copyfile(filename, outputdir + getfilenamefrompath(filename))
			#print(filename)
			break
		#print(so)'''
	#print(filename)
	if isusecrypt(filename,arch):
		shutil.copyfile(filename, outputdir + getfilenamefrompath(filename))
	return True


def translateIR(filename,outputdir,importfc = dict()):
	'''print(filename)
	filetype = _get_filetype(filename)
	filename = filenameformat(filename)
	outputdir = filenameformat(outputdir)
	onlyfilename = getfilenamefrompath(filename)
	#option = 0
	if onlyfilename == "busybox":
		return
	if not any(s in [filetype] for s in [b"application/x-executable",
					 b"application/x-object",b"application/x-sharedlib"]):
		#print(filename)
		return
	if filetype == b"application/x-executable":
		option = 0
	elif filetype ==  b"application/x-sharedlib":
		option = 1
	elif filetype == b"application/x-object":
		option = 1
		if filename.endswith(".ko"):
			option = 2
	outputfile = outputdir + "/" + onlyfilename+"ir"
	print("python angrir.py " + filename + " " + outputfile  + " > " + outputfile)
	os.system("python angrir.py " + filename + " " + outputfile  + " > " + outputfile)
	return'''
	onlyfilename = getfilenamefrompath(filename)
	outputfile = outputdir + "/" + onlyfilename
	return transbin2IR(filename,outputfile,importfc)

def getIRtmp(filename,outputdir):
	arch = _getarch(filename)
	#print(filename)
	#soset = listallso(filename,arch)
	#print(soset)
	filetype = _get_filetype(filename)
	filename = filenameformat(filename)
	outputdir = filenameformat(outputdir)
	onlyfilename = getfilenamefrompath(filename)
	if onlyfilename == "busybox":
		return
	if not any(s in [filetype] for s in ["application/x-executable",
						"application/x-object","application/x-sharedlib"]):
		return
	outputdir += onlyfilename
	idarun(filename,outputdir)
	return True
	


def challown(filename):
	filename = filenameformat(filename)
	os.ystem("chown $USER:$USER " + filename)


def mkdir(path):
	if not os.path.exists(path):
		os.makedirs(path)

def getfileowner(filename):
	filename = filenameformat(filename)
	(status,output) = subprocess.getstatusoutput('ls -al ' + filename)
	print(filename)
	print(output)
	result = output.split()[2]
	return result

''' keep dir struct'''
def dfs_dir(path,outputpath,operationf = None,operationd = None):
	stack = []
	ret = []
	stack.append(path)
	if not outputpath == None:
		mkdir(outputpath)
	oresult = True
	while len(stack) > 0:
		tmp = stack.pop(len(stack) - 1)
		#print(tmp)
		try:
			if(os.path.isdir(tmp)):
				print(tmp)
				#ret.append(tmp)
				Doutputpath = tmp[tmp.index(path)+len(path):tmp.rindex("/")]
				destpath = ""
				if Doutputpath == "":
					destpath = outputpath + "/"
				else:
					destpath = outputpath + "/" + Doutputpath + "/"
				if not operationd == None:
					oresult = operationd(tmp,destpath)
				if not oresult:
					continue
				for item in os.listdir(tmp):
					fullfilenamestr = os.path.join(tmp,item)
					stack.append(fullfilenamestr)
			elif(os.path.isfile(tmp)):
				#print(tmp)
				ret.append(tmp)
				Doutputpath = tmp[tmp.index(path)+len(path):tmp.rindex("/")]
				destpath = ""
				if Doutputpath == "":
					destpath = outputpath + "/"
				else:
					destpath = outputpath + "/" + Doutputpath + "/"
				mkdir(destpath)
				if not operationf == None:
					operationf(tmp,destpath)
		except IOError:
			print(tmp)
		except OSError:
			print(tmp)
	return ret

def path2filename(path):
	fullfilename = path[path.rindex("/")+1:len(path)]
	prefixfilename = fullfilename[0:fullfilename.rindex(".")]
	return prefixfilename

def usingrand(fullformatname):
	result=randtype.Nrand
	output = os.popen("nm -D " + fullformatname)
	regex = re.compile('\s+')
	allline = output.read().split("\n")
	functionset = set()
	for line in allline:
		field = regex.split(line)
		if not len(field) == 3 or not field[1] == "U":
			continue
		functionset.add(field[2].strip())
	if "rand" in functionset and "srand" in functionset:
		result = randtype.Orsrand
	elif "rand" in functionset:
		result = randtype.Orand
	elif "srand" in functionset:
		result = randtype.Osrand
	return result

#def rootfinddfs(path,dirname,soset,execset):
def soexecfile(fullname,outputdir):
    global soset
    global execset
    global name2path
    fullname = filenameformat(fullname)
    filetype = _get_filetype(fullname)
    arch = _getarch(fullname)
    filename = ""
    if fullname.find("/") == -1:
        filename = fullname
    else:
        filename = fullname[fullname.rindex("/")+1:len(fullname)]
    #print(filename + ' ' +filetype)
    if filetype == "application/x-executable":
        #print(filename + ' ' +filetype)
        allso = listallso(fullname,arch)
        #print(allso)
        for allsoitem in allso:
            if not allsoitem in execset:
                execset[allsoitem] = set()
            execset[allsoitem].add(filename)
        name2path[filename] = fullname
        if usingrand(fullname) == randtype.Orand:
            ousingrandset[filename] = fullname
        #execset[allso] = filename
    elif filetype == "application/x-sharedlib":
        #print(filename + ' ' +filetype)
        filename = libformat(fullname,filetype)
        allso = listallso(fullname,arch)
        for allsoitem in allso:
            if not allsoitem in soset:
                soset[allsoitem] = set()
            soset[allsoitem].add(filename)
        name2path[filename] = fullname
        if usingrand(fullname) == randtype.Orand:
            ousingrandset[filename] = fullname
        #soset[allso] = filename
    return True

def wdetail(df,prompt,dinfo=dict()):
	wfd = open(df,"a")
	wfd.write(prompt+"\n")
	for item in dinfo:
		wfd.write(dinfo[item][0]+"\n")
	wfd.close()

def wfsummury(sf,prompt,sdict = dict()):
	wfd = open(sf,"a")
	wfd.write(prompt+"\n")
	for item in sdict:
		wfd.write(item + " " + str(sdict[item]) + "\n")
	wfd.close()

def summurycount(dinfo,result):
	for ditemindex in dinfo:
		ditem = dinfo[ditemindex]
		print(ditem[1])
		print(ditem[2])
		if not str(ditem[1]) + " " + str(ditem[2]) in result:
			result[str(ditem[1]) + " " + str(ditem[2])] = 1
		else:
			result[str(ditem[1]) + " " + str(ditem[2])] += 1
		if not str(ditem[1]) + " " + str(ditem[2]) in allruleresult:
			allruleresult[str(ditem[1]) + " " + str(ditem[2])] = 1
		else:
			allruleresult[str(ditem[1]) + " " + str(ditem[2])] += 1

def systemconstruct(dirfullpath,outputdir):
	global soset
	global execset
	global cryptlibset
	global name2path
	global ousingrandset
	dirname = ""
	result = True
	currentset = cryptlibset
	currentnextset = set()
	allfset = currentset
	alleset = set()
	alldepend=dict()
	summtable=dict()
	writefirst = True
	if dirfullpath.find("/") == -1:
		dirname = dirfullpath
	else:
		dirname = dirfullpath[dirfullpath.rindex("/") + 1:len(dirfullpath)]
	print(dirname)
	if dirname.endswith("extracted"):
		testbegintime = time.time()
		transtimesum = 0
		firmname = dirname[0:dirname.find(".extracted")]
		filloutputdir = ""
		if not dirfullpath.find("/") == -1:
			filloutputdir = outputdir + "/" + dirfullpath[dirfullpath.rindex("/") + 1:]
		else:
			filloutputdir = outputdir
		detailreportfile = filloutputdir + ".dreport"
		summuaryreportfile = filloutputdir + ".summary"
		global numextracted
		numextracted += 1
		result = False
		soset.clear()
		execset.clear()
		name2path.clear()
		ousingrandset.clear()
		dfs_dir(dirfullpath,outputdir+"/"+dirname,operationf=soexecfile,operationd=None)
		#libmap
		for currentitem in currentset:
			if currentitem in soset:
				loadsoset = soset[currentitem]
				currentnextset = currentnextset.union(loadsoset)
		while len(currentnextset) > 0:
			currentset = copy.copy(currentnextset)
			currentnextset.clear()
			print(currentset)
			print(allfset)
			for currentitem in currentset:
				print(currentitem)
				if currentitem in allfset or currentitem == "cupsd" or currentitem == "libtorrent-rasterbar" or currentitem == "smbd" or currentitem == "libperl" or currentitem == "libphp5" or currentitem == "libapr-1":# or currentitem == "tdbbackup" or currentitem == "net" or currentitem == "libbigballofmud" or  currentitem == "smbpasswd" or currentitem == "libsysctxlua" or currentitem == "libzebra" or currentitem == "libcurl" or currentitem == "ssl" or currentitem == "zebra" or currentitem == "stunnel" or currentitem == "libntpass":
					continue
				onlyfilename = getfilenamefrompath(name2path[currentitem])
				if os.path.getsize(name2path[currentitem]) / float(1024*1024) > 10:
					continue
				a = time.time()
				getIRtmp(name2path[currentitem],filloutputdir + "/")
				b = time.time()
				print("getIRtmp:%f"%(b-a))
				testbegintime2 = time.time()
				(exporteddic,detailreport) = translateIR(filloutputdir + "/" + onlyfilename + "idcom",filloutputdir)
				testendtime2 = time.time()
				transtimesum += (testendtime2 - testbegintime2)
				if not len(detailreport) == 0 and writefirst:
					writefirst = False
					wdetail(detailreportfile,firmname)
					wdetail(detailreportfile,currentitem)
					wdetail(detailreportfile,name2path[currentitem],detailreport)
					summurycount(detailreport,summtable)
				elif not len(detailreport) == 0:
					wdetail(detailreportfile,currentitem)
					wdetail(detailreportfile,name2path[currentitem],detailreport)
					summurycount(detailreport,summtable)
				alldepend[currentitem] = exporteddic
				if currentitem in soset:
					loadsoset = soset[currentitem]
					currentnextset = currentnextset.union(loadsoset)
			allfset = allfset.union(currentset)
		for allfitem in allfset:
			if allfitem in execset:
				alleset = alleset.union(execset[allfitem])
		print("------")
		print(alleset)
		for execitem in alleset:
			print(execitem)
			if execitem == "openssl" or execitem == "ssh" or execitem == "smbd" or execitem == "perl" or execitem.find("php") == 0 or execitem == "mysqld" or execitem == "pppd" or execitem == "vsftpd" or execitem == "busybox" or execitem == "stunnel" or execitem == "zebra" or execitem == "email" or execitem == "sshd" or execitem == "ldapwhoami" or execitem == "mount.cifs":# or execitem == "httpd" or execitem == "dhclient" or execitem == "guardian" or execitem == "jnap" or execitem == "fwupd" or execitem == "curl" or execitem == "sshd" or execitem == "wget":#wgets for 360
				continue
			if os.path.getsize(name2path[execitem]) / float(1024*1024) > 10:
				continue
			print(execitem)
			so = listallso(name2path[execitem],_getarch(name2path[execitem]))
			importedso = dict()
			for soitem in so:
				if soitem in alldepend:
					importedso.update(alldepend[soitem])
			a = time.time()
			getIRtmp(name2path[execitem],filloutputdir+"/")
			b = time.time()
			print("getIRtmp:%f"%(b-a))
			onlyfilename = getfilenamefrompath(name2path[execitem])
			testbegintime2 = time.time()
			(exporteddic,detailreport) = translateIR(filloutputdir + "/" + onlyfilename + "idcom",filloutputdir,importedso)
			testendtime2 = time.time()
			transtimesum += (testendtime2 - testbegintime2)
			if not len(detailreport) == 0 and writefirst:
				writefirst = False
				wdetail(detailreportfile,firmname)
				wdetail(detailreportfile,execitem)
				wdetail(detailreportfile,name2path[execitem],detailreport)
				summurycount(detailreport,summtable)
			elif not len(detailreport) == 0:
					wdetail(detailreportfile,execitem)
					wdetail(detailreportfile,name2path[execitem],detailreport)
					summurycount(detailreport,summtable)
		testendtime = time.time()
		print("systemconstructtime %f"%(testendtime - testbegintime - transtimesum))
		detailre = dict()
		#print(name2path)
		for randitem in ousingrandset:
			detailre[randitem] = ("using static seed for rand",5,"using static seed for rand")
			wdetail(detailreportfile,name2path[randitem],detailre)
			summurycount(detailre,summtable)
		#print(summtable)
		wfsummury(summuaryreportfile,firmname,summtable)
	return result
	

if __name__ == "__main__":
	if not len(sys.argv) == 6:
		print("Usage:<inputpath> <tmppath> <outputpath> <IRtmppath> <IRpath> (absolution path only)");
		sys.exit(-1);
	inputpath = sys.argv[1];
	tmppath = sys.argv[2];
	outputpath = sys.argv[3];
	irpath = sys.argv[4];
	allreportpath = sys.argv[5];
	globalpath = allreportpath;
	numextracted = 0;
	#os.system("rm -rf  " + tmppath);
	#os.system("rm -rf  " + outputpath);
	os.system("rm -rf  " + irpath);
	a = time.time();
	testr = dfs_dir(inputpath,tmppath,operationf=decompress,operationd = None);
	testr = dfs_dir(tmppath,outputpath,operationf=extractfile,operationd = None);
	b = time.time();
	print("unpack time:%f"%(b-a));
	testr = dfs_dir(outputpath,irpath,operationf = None, operationd = systemconstruct);
	wfsummury(allreportpath,"allsummary",allruleresult);
	print("decompressfile:%d"%numdecompress);
	dmsg = "decompressfile:%d"%numdecompress;
	print("numfirmware:%d"%numfirmware);
	numfirmwaremsg = "numfirmware:%d"%numfirmware;
	print("extracted:%d"%numextracted);
	extractednum = "extracted:%d"%numextracted;
	#wfsummury(allreportpath,numfirmwaremsg);
	#wfsummury(allreportpath,extractednum);
	
	#'''testr = dfs_dir(outputpath,irpath,operationf=filterfile)
	#testr = dfs_dir(outputpath,irpath)
	#print("ir%s\n"%(irpath))
	#testr = dfs_dir(outputpath,irtmppath,operationf=getIRtmp)
	#testr = dfs_dir(irtmppath,irpath,operationf=translateIR)
	#wfsummury(allreportpath,allruleresult)'''
