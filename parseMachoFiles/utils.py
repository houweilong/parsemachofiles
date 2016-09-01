'''
Created on Dec 16, 2015

@author: hwl122902
'''
from __future__ import print_function
import string
import logging
import os
import json
import struct
import collections
import ReadWrite
from macholib.MachO import MachOHeader
from macholib.MachO import MachO
from pango import DESCENT
from macholib.util import fileview
from __builtin__ import True
from capstoneUtils import *
from loader import *

def setLogger():
    logger_root = logging.getLogger()
    console = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s][%(levelname)s][%(process)d][%(filename)s]%(funcName)s: %(message)s")
    console.setFormatter(formatter)
    logger_root.addHandler(console)
    logger_root.setLevel(logging.INFO)
    return logger_root

def fileOffsetToAddress(sample,fileOffset):
    sectionInfos = getSectionInfoMaps(sample)
    offset = 0
    address = fileOffset
    for info in sectionInfos:
        offset = info.get("offset")
        size = info.get("size")
        if fileOffset >= offset and fileOffset <= (offset + size):
            segname = info.get("segname")
            desc = getSegmentInfo(sample,segname)
            address = fileOffset + desc.get("vmaddr") - desc.get("fileoff")
            
    return address

#fle_off = (address-seg.address)+ seg.offset
def addressToFileOffset(sample,sectionInfos,address):
    offset = 0
    for info in sectionInfos:
        addr = info.get("addr")
        size = info.get("size")
        if address >= addr and address <= (addr + size):
            segname = info.get("segname")
            desc = getSegmentInfo(sample,segname)
            offset = address - desc.get("vmaddr") + desc.get("fileoff")
            
    return offset

def getHeader(path):
    m = MachO(path)
    for header in m.headers:
        if isinstance(header, MachOHeader):
            return header
    return None

def getEndianFormat(path):
    header = getHeader(path)
    return header.endian

def getCommandInfos(path,commandName):
    header = getHeader(path)
    descripe = dict(header.header._describe())
    cupType = descripe.get("cputype_string")
    for (index,(lc, cmd, data)) in enumerate(header.commands):
        lc_name = lc.get_cmd_name()
        if lc_name==44:
            if cupType.find("64")!=-1:
                lc_name = "LC_ENCRYPTION_INFO_64"
            else:
                lc_name = "LC_ENCRYPTION_INFO"
        
        if lc_name == commandName:
            return cmd.describe()
        
    return None

def getSectionInfos(path,secName):
    header = getHeader(path)
    for (index,(lc, cmd, data)) in enumerate(header.commands):
        lc_name = lc.get_cmd_name()
        if lc_name=="LC_SEGMENT_64" or lc_name == "LC_SEGMENT":
            for sec in data:
                name = sec.sectname.rstrip('\x00')
                if name == secName:
                    return sec.describe()
    return None

def getFramework(filename):
    header = getHeader(filename)
    seen = set()
    #for all relocatable commands,yield (command_index, command_name, filename)
    for idx, name, other in header.walkRelocatables():
        if other not in seen:
            seen.add(other)
    return seen

def getAllFrameworks(filename):
    header = getHeader(filename)
    frameworks = {}
    count = 0
    for (index,(lc, cmd, data)) in enumerate(header.commands):
        lc_name = lc.get_cmd_name()
        if lc_name == "LC_LOAD_DYLIB":
            count += 1
            frameworks[count] = data.rstrip('\x00').split("/")[-1]
    return frameworks

def getPartOfFile(path,start,size):
    with open(path, 'rb') as fp:
        fh = fileview(fp, start, size)
        fh.seek(0)
        with open("temp","wb") as f:
            f.write(fh.read())  
 

def getMethodNames(path):
    header = getHeader(path)
    desc = getSectionInfos(path, "__objc_methname")
    methNames = {}
    address = fileOffsetToAddress(path,desc.get("offset"))
    getPartOfFile(path,desc.get("offset"),desc.get("size"))
    for l,s in ReadWrite.strings("temp"):
        methNames[hex(address+l)] = s
    os.remove("temp")
    return methNames    

def getCStrings(path):
    header = getHeader(path)
    desc = getSectionInfos(path, "__cstring")
    cStrings = {}
    address = fileOffsetToAddress(path,desc.get("offset"))
    getPartOfFile(path,desc.get("offset"),desc.get("size"))
    for l,s in ReadWrite.strings("temp"):
        cStrings[hex(address+l)] = s
    os.remove("temp")
    return cStrings   

def is64Bit(path):
    header = getHeader(path)
    descripe = dict(header.header._describe())
    cuptype = descripe.get("cputype")
    return (cuptype & CPU_ARCH_ABI64) == CPU_ARCH_ABI64

def isFatBinary(path):
    file = open(path,"rb")
    magic = struct.unpack(">I", file.read(4))[0]
    file.close()
  
    if magic == FAT_MAGIC or magic == FAT_CIGAM:
        return True
    return False

def isNumber(var):
    try:
        int(var,16)
        return True
    except Exception:
        return False

def getSegments(path):
    header = getHeader(path)
    segments = []
    for (index,(lc, cmd, data)) in enumerate(header.commands):
        lc_name = lc.get_cmd_name()
        if lc_name=="LC_SEGMENT_64" or lc_name == "LC_SEGMENT":
            segments.append(cmd.describe())
    return segments

def getSectionInfoMaps(sample):
    sectionInfos = []
    header = utils.getHeader(sample)
    for (index,(lc, cmd, data)) in enumerate(header.commands):
        lc_name = lc.get_cmd_name()
        if lc_name=="LC_SEGMENT_64" or lc_name == "LC_SEGMENT":
            for sec in data:
                infos = {}
                infos["sectname"] = sec.sectname.rstrip('\x00')
                infos["segname"] = sec.segname.rstrip('\x00')
                infos["addr"] = sec.addr
                infos["size"] = sec.size
                infos["flags"] = sec.flags
                infos["offset"] = sec.offset
                sectionInfos.append(infos)
    
    return sectionInfos
  
def getSegmentInfo(sample,segname):
    sectionInfos = []
    header = utils.getHeader(sample)
    for (index,(lc, cmd, data)) in enumerate(header.commands):
        lc_name = lc.get_cmd_name()
        if lc_name=="LC_SEGMENT_64" or lc_name == "LC_SEGMENT":
            if cmd.segname.rstrip('\x00') == segname:
                return cmd.describe()
    return None

def findSymbolAtOffset(sample,symbolNames,offset):
    symbolName = symbolNames.get(hex(offset))
    return symbolName

def findSectionByName(sample,sectname,segname):
    sections = getSections(sample)
    for section in sections:
        if (segname == None or section.segname.rstrip('\x00') == segname) \
        and section.sectname.rstrip('\x00') == sectname:
            return section
    return None

def userInfoForSection(section):
    info = {}
    if section == None:
        return None
    info["segname"] =  section.segname.rstrip('\x00')
    info["sectname"] = section.segname.rstrip('\x00')
    info["address"] = section.address
    return info

def getDict(description,value):
    tmp = {}
    tmp["description"] = description
    tmp["value"] = value
    return tmp

def getSymbolStrs(sample):
    desc = utils.getCommandInfos(sample,"LC_SYMTAB")
    strTable = {}
    strAddress = desc.get("stroff")
    strSize = desc.get("strsize")
    utils.getPartOfFile(sample,strAddress, strSize)
    for l,s in ReadWrite.strings("temp"):
        strTable[hex(strAddress+l)] = s
    strTable = collections.OrderedDict(sorted(strTable.items()))
    os.remove("temp")
    return  strTable

def getSections(sample):
    header = utils.getHeader(sample)
    sections = []
    for (index,(lc, cmd, data)) in enumerate(header.commands):
        lc_name = lc.get_cmd_name()
        if lc_name=="LC_SEGMENT_64" or lc_name == "LC_SEGMENT":
            for sec in data:
                sections.append(sec)
    return sections

def getSectionByIndex(sections,index):
    if index < len(sections):
        return sections[index-1]
    return None

def getSymbolByIndex(syms,index):
    if index < len(syms):
        return syms[index]
    return None

