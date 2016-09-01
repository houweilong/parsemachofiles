'''
Created on Dec 9, 2015

@author: hwl122902
'''
import utils
import collections
import SymbolContents
import ReadWrite
from capstoneUtils import *
from loader import *

def createCStringsNode(sample,section):
    strs = {}
    address = section.offset
    utils.getPartOfFile(sample,section.offset,section.size)
    for l,s in ReadWrite.strings("temp"):
        strs[hex(address+l).rstrip("L")] = s
    os.remove("temp")
    
    strs = collections.OrderedDict(sorted(strs.items()))
    return strs    

def createLiteralsNode(sample,section,stride):
    endian = utils.getEndianFormat(sample)
    literals = {}
    address = section.offset
    getPartOfFile(sample,section.offset,section.size)
    offset = 0 
    length = os.path.getsize("temp")
    while offset < length:
        byte,data = ReadWrite.readInt8("temp",endian,offset)
        offset += byte
        literalStr = ""
        if stride == 4:
            literalStr = float(data)
      
        elif stride == 8: 
            literalStr = double(data)
        else:
            literalStr = long(data)
            
        literals[hex(address).rstrip("L")] = literalStr
        address += byte
     
    os.remove("temp")
    literals = collections.OrderedDict(sorted(literals.items()))  
    return literals

def createPointersNode(sample,section,symbolNames):
    endian = utils.getEndianFormat(sample)
    pointers = {}
    address = section.offset
    utils.getPartOfFile(sample,section.offset,section.size)
    offset = 0 
    length = os.path.getsize("temp")
    os.rename("temp","pointers")
    s = "->"
    sectionInfos = utils.getSectionInfoMaps(sample)
    while offset < length:
        byte,ptr = ReadWrite.readInt32("pointers",endian,offset)
        offset += byte
        
        if section.sectname.rstrip('\x00') == "__objc_selrefs":
            symbolName = symbolNames.get(hex(ptr).rstrip("L"))
            if symbolName == None:
                pointers[hex(address).rstrip("L")] = hex(ptr)
            else:
                seq = (hex(ptr),symbolName)
                pointers[hex(address).rstrip("L")] = s.join(seq)
        else:
            pointers[hex(address).rstrip("L")] = hex(ptr)
            
            
        address += byte
    
    os.remove("pointers")
    pointers = collections.OrderedDict(sorted(pointers.items()))    
    return pointers
        
def createTextNode(sample,section,outputPath):
    #prepare disassembler params
    header = utils.getHeader(sample)
    strs = utils.getSymbolStrs(sample)
    inSymbols = SymbolContents.getISymbols(sample)
    names = SymbolContents.getFunctionNames(sample,strs)
    #open capstone 
    target_arch = 0
    target_mode = 0
    if header.header.cputype == CPU_TYPE_ARM:
        target_arch = CS_ARCH_ARM
        target_mode = CS_MODE_ARM
    elif header.header.cputype == CPU_TYPE_ARM64:
        target_arch = CS_ARCH_ARM64
        target_mode = CS_MODE_ARM
    else:
        print("NO CPU FOUND!")
    
    md = Cs(target_arch, target_mode)
    md.skipdata = True
    md.detail = True
    #set or not thumb mode for 32 bits ARM targets 
    if header.header.cputype == CPU_TYPE_ARM:
        if header.header.cpusubtype == CPU_SUBTYPE_ARM_V7 \
            or header.header.cpusubtype == CPU_SUBTYPE_ARM_V7F \
            or header.header.cpusubtype == CPU_SUBTYPE_ARM_V7S \
            or header.header.cpusubtype == CPU_SUBTYPE_ARM_V7K \
            or header.header.cpusubtype == CPU_SUBTYPE_ARM_V8 :
            md.mode = CS_MODE_THUMB
        else:
            md.mode = CS_MODE_ARM
    
    code = Codes(md)       
    utils.getPartOfFile(sample,section.offset, section.size)
    os.rename("temp", "codes")
    if section.sectname.rstrip('\x00') == "__text":
        desc = utils.getCommandInfos(sample, "LC_FUNCTION_STARTS")
        utils.getPartOfFile(sample, desc.get("dataoff"), desc.get("datasize"))
        if utils.is64Bit(sample):
            getFunctions(code,inSymbols,names,"temp",section.offset,outputPath)
        else:
            getFunctions(code,inSymbols,names,"temp",section.offset,outputPath)
        os.remove("temp")
    else:
        fcode = open("codes","rb")
        CODE = fcode.read()
        code.disAssembly(md,inSymbols,CODE,section.offset,outputPath)
        fcode.close()
        
    
    os.remove("codes")
    
 
def createIndPointersNode(sample,section,inSymbols):
    endian = utils.getEndianFormat(sample)
    pointers = {}
    offset = 0
    addr = section.offset
    utils.getPartOfFile(sample,addr,section.size)
    while offset<section.size:
        byte,data = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        
        symbolName = inSymbols.get(hex(addr).rstrip("L"))
        if symbolName is None:
            symbolName = hex(data).rstrip("L")
        pointers[hex(addr).rstrip("L")] = symbolName
        
        addr += byte
    os.remove("temp")
    pointers = collections.OrderedDict(sorted(pointers.items()))
    return pointers

def createIndPointers64Node(sample,section,inSymbols):
    endian = utils.getEndianFormat(sample)
    pointers = {}
    offset = 0
    addr = section.offset
    utils.getPartOfFile(sample,addr,section.size)
    while offset<section.size:
        byte,data = ReadWrite.readInt64("temp",endian,offset)
        offset += byte
        
        symbolName = inSymbols.get(hex(addr).rstrip("L"))
        if symbolName is None:
            symbolName = hex(data).rstrip("L")
        pointers[hex(addr).rstrip("L")] = symbolName
        
        addr += byte
    os.remove("temp")
    pointers = collections.OrderedDict(sorted(pointers.items()))
    return pointers

def createIndStubsNode(sample,section,inSymbols):
    pointers = {}
    offset = 0
    addr = section.offset
    stride = section.reserved2
    while offset<section.size:
        offset += stride
        symbolName = inSymbols.get(hex(addr).rstrip("L"))
        pointers[hex(addr).rstrip("L")] = symbolName
        
        addr += stride
     
    pointers = collections.OrderedDict(sorted(pointers.items()))   
    return pointers

