'''
Created on Dec 16, 2015

@author: hwl122902
'''
import utils
import os
import SymbolContents
import ReadWrite
import collections
from loader import *


def createObjCCFStringsNode(sample,section,cStrings,sectionInfos):
    endian = utils.getEndianFormat(sample)
    cfStrings = {}
    offset = 0
    addr = section.offset
    length = section.size
    utils.getPartOfFile(sample,addr,length)
    while offset < length:
          
        symbolName = None
        offset += 4
        description = "CFString Ptr"
        cfStrings[hex(addr).rstrip("L")] = utils.getDict(description,"___CFConstantStringClassReference")
        addr += 4

        if offset >= length:
            break
        
        byte,data = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "   "
        cfStrings[hex(addr).rstrip("L")] = utils.getDict(description,hex(data).rstrip("L"))
        addr += byte
        
        if offset >= length:
            break
        
        byte,cstr = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "String"
        symbolName = cStrings.get(hex(cstr).rstrip("L"))
        if symbolName is None:
            symbolName = ""
        cfStrings[hex(addr).rstrip("L")] = utils.getDict(description,symbolName)
        addr += byte
        
        if offset >= length:
            break
        
        byte,size = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "Size"
        cfStrings[hex(addr).rstrip("L")] = utils.getDict(description,size)
        addr += byte
     
    cfStrings = collections.OrderedDict(sorted(cfStrings.items()))
    os.remove("temp")   
    return cfStrings

def createObjCCFStrings64Node(sample,section,cStrings,sectionInfos):
    endian = utils.getEndianFormat(sample)
    cfStrings = {}
    offset = 0
    addr = section.offset
    length = section.size
    utils.getPartOfFile(sample,addr,length)
    while offset < length:
          
        symbolName = None
        offset += 8
        description = "CFString Ptr"
        cfStrings[hex(addr).rstrip("L")] = utils.getDict(description,"___CFConstantStringClassReference")
        addr += 8

        if offset >= length:
            break
        
        byte,data = ReadWrite.readInt64("temp",endian,offset)
        offset += byte
        description = "   "
        cfStrings[hex(addr).rstrip("L")] = utils.getDict(description,hex(data).rstrip("L"))
        addr += byte
        
        if offset >= length:
            break
        
        byte,cstr = ReadWrite.readInt64("temp",endian,offset)
        offset += byte
        description = "String"
        symbolName = cStrings.get(hex(cstr).rstrip("L"))
        if symbolName is None:
            symbolName = ""
        cfStrings[hex(addr).rstrip("L")] = utils.getDict(description,symbolName)
        addr += byte
        
        if offset >= length:
            break
        
        byte,size = ReadWrite.readInt64("temp",endian,offset)
        offset += byte
        description = "Size"
        cfStrings[hex(addr).rstrip("L")] = utils.getDict(description,size)
        addr += byte
     
    cfStrings = collections.OrderedDict(sorted(cfStrings.items())) 
    os.remove("temp")  
    return cfStrings   
  
def createObjCModulesNode(sample,section):
    endian = utils.getEndianFormat(sample)
    objcModules = {}
    offset = 0
    addr = section.offset
    length = section.size
    utils.getPartOfFile(sample,addr,length)
    while offset < length:
        byte,version = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "Version"
        objcModules[hex(addr).rstrip("L")] = utils.getDict(description,version)
        addr += byte
        
        if offset >= length:
            break
        
        byte,size = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "Size"
        objcModules[hex(addr).rstrip("L")] = utils.getDict(description,size)
        addr += byte
        
        if offset >= length:
            break
    
        byte,name = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "Name"
        objcModules[hex(addr).rstrip("L")] = utils.getDict(description,hex(name).rstrip("L"))
        addr += byte
        
        if offset >= length:
            break
        
        byte,symtab = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "Symtab"
        objcModules[hex(addr).rstrip("L")] = utils.getDict(description,hex(symtab).rstrip("L"))
        addr += byte
        
    objcModules = collections.OrderedDict(sorted(objcModules.items())) 
    os.remove("temp")  
    return objcModules  

def createObjC2PointerListNode(sample,section):
    endian = utils.getEndianFormat(sample)
    classSysbols = SymbolContents.getClassSymbols(sample)
    objC2Pointers = {}
    offset = 0
    addr = section.offset
    length = section.size
    utils.getPartOfFile(sample,addr,length)
    while offset < length:  
        byte,pointer = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "Pointer"
        value = classSysbols.get(hex(pointer).rstrip("L"))
        if value is None or pointer == 0:
            value = pointer
        objC2Pointers[hex(addr).rstrip("L")] = utils.getDict(description,value)
        addr += byte
        
    objC2Pointers = collections.OrderedDict(sorted(objC2Pointers.items())) 
    os.remove("temp")  
    return objC2Pointers  

def createObjC2Pointer64ListNode(sample,section):
    endian = utils.getEndianFormat(sample)
    classSysbols = SymbolContents.getClassSymbols(sample)
    objC2Pointers = {}
    offset = 0
    addr = section.offset
    length = section.size
    utils.getPartOfFile(sample,addr,length)
    while offset < length:  
        byte,pointer = ReadWrite.readInt64("temp",endian,offset)
        offset += byte
        description = "Pointer"
        value = classSysbols.get(hex(pointer).rstrip("L"))
        if value is None or pointer == 0:
            value = pointer
        objC2Pointers[hex(addr).rstrip("L")] = utils.getDict(description,value)
        addr += byte
        
    objC2Pointers = collections.OrderedDict(sorted(objC2Pointers.items())) 
    os.remove("temp")  
    return objC2Pointers  
        
   
def createObjC2MsgRefsNode(sample,section):
    endian = utils.getEndianFormat(sample)
    objC2MsgRefs = {}
    offset = 0
    addr = section.offset
    length = section.size
    utils.getPartOfFile(sample,addr,length)
    while offset < length:  
        byte,imp = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "IMP"
        objC2MsgRefs[hex(addr).rstrip("L")] = utils.getDict(description,hex(imp).rstrip("L"))
        addr += byte
        
        if offset >= length:
            break
        
        byte,sel = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "SEL"
        objC2MsgRefs[hex(addr).rstrip("L")] = utils.getDict(description,hex(sel).rstrip("L"))
        addr += byte
        
    objC2MsgRefs = collections.OrderedDict(sorted(objC2MsgRefs.items())) 
    os.remove("temp")  
    return objC2MsgRefs 

def createObjC2MsgRefs64Node(sample,section):
    endian = utils.getEndianFormat(sample)
    objC2MsgRefs = {}
    offset = 0
    addr = section.offset
    length = section.size
    utils.getPartOfFile(sample,addr,length)
    while offset < length:  
        byte,imp = ReadWrite.readInt64("temp",endian,offset)
        offset += byte
        description = "IMP"
        objC2MsgRefs[hex(addr).rstrip("L")] = utils.getDict(description,hex(imp).rstrip("L"))
        addr += byte
        
        if offset >= length:
            break
        
        byte,sel = ReadWrite.readInt64("temp",endian,offset)
        offset += byte
        description = "SEL"
        objC2MsgRefs[hex(addr).rstrip("L")] = utils.getDict(description,hex(sel).rstrip("L"))
        addr += byte
        
    objC2MsgRefs = collections.OrderedDict(sorted(objC2MsgRefs.items())) 
    os.remove("temp")  
    return objC2MsgRefs  
        
        
def createObjCImageInfoNode(sample,section):
    endian = utils.getEndianFormat(sample)
    objC2ImageInfo = {}
    offset = 0
    addr = section.offset
    length = section.size
    utils.getPartOfFile(sample,addr,length)
    while offset < length:  
        byte,version = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "Version"
        objC2ImageInfo[hex(addr).rstrip("L")] = utils.getDict(description,hex(version).rstrip("L"))
        addr += byte
        
        if offset >= length:
            break
        
        byte,flags = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "Flags"
        value = ""
        if flags & OBJC_IMAGE_IS_REPLACEMENT:
            value = "0x1 OBJC_IMAGE_IS_REPLACEMENT"
        if flags & OBJC_IMAGE_SUPPORTS_GC:
            value = "0x2 OBJC_IMAGE_SUPPORTS_GC"
        if flags & OBJC_IMAGE_GC_ONLY:
            value = "0x4 OBJC_IMAGE_GC_ONLY"
        
        objC2ImageInfo[hex(addr).rstrip("L")] = utils.getDict(description,value)
        addr += byte
        
    objC2ImageInfo = collections.OrderedDict(sorted(objC2ImageInfo.items())) 
    os.remove("temp")  
    return objC2ImageInfo  
  
    
    
  
  
