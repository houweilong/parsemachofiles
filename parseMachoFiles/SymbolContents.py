'''
Created on Dec 9, 2015

@author: hwl122902
'''

import json
import os
import utils
import collections
import ReadWrite
from macholib.mach_o import * 
from loader import *
from capstoneUtils import *


def get_library_ordinal(n_desc):
    return ((n_desc) >> 8) & 0xff

def set_library_ordinal(n_desc,ordinal):
    n_desc = ((n_desc) & 0x00ff) | (((ordinal) & 0xff) << 8)

def createSymbolsNode(sample,strs,path,baseAddr,baseStrAddr,nsym):
    endian = utils.getEndianFormat(sample)
    frameworks = utils.getAllFrameworks(sample)
    sections = utils.getSections(sample)
    count = 0
    symbols = {}
    addr = baseAddr
    offset = 0
    while count < nsym:
        count += 1
        byte,data = ReadWrite.readInt32(path,endian,offset)
        offset += byte
        description = "String Table Index"
        value = strs.get(hex(baseStrAddr+data).rstrip("L"))
        if value is None:
            value = ""
        symbols[hex(addr)] = utils.getDict(description,value)
        addr += byte
        
        byte,n_type = ReadWrite.readInt8(path,endian,offset)
        offset += byte
        types = []
        description = "Type"
        
        if n_type & N_STAB:
            types.append("E0  N_STAB")
        else:
            if n_type & N_TYPE == N_UNDF:
                types.append("00  N_UNDF")
            elif n_type & N_TYPE == N_ABS:
                types.append("02  N_ABS")
            elif n_type & N_TYPE == N_SECT:
                types.append("0E  N_SECT")
            elif n_type & N_TYPE == N_PBUD:
                types.append("0C  N_PBUD")
            elif n_type & N_TYPE == N_INDR:
                types.append("0A  N_INDR")
      
            if n_type & N_PEXT:
                types.append("10  N_PEXT")
            if n_type & N_EXT:
                types.append("01  N_EXT")
            
        symbols[hex(addr)] = utils.getDict(description,types)
        addr += byte
        
        byte,n_sect = ReadWrite.readInt8(path,endian,offset)
        offset += byte
        section = utils.getSectionByIndex(sections,n_sect)
        description = "Section Index"
        if n_sect == NO_SECT or section is None:
            value = "NO_SECT"
        else:
            value = str(n_sect) + "(" + section.segname.rstrip('\x00') + "," + section.sectname.rstrip('\x00') + ")"
        symbols[hex(addr)] = utils.getDict(description,value)
        addr += byte
        
        byte,n_desc = ReadWrite.readInt16(path,endian,offset)
        offset += byte
        descriptions = []
        description = "Description"
    
        if n_type & N_STAB == 0 and n_type & N_TYPE == N_UNDF or n_type & N_TYPE == N_PBUD and n_type & N_EXT:
            if n_desc & REFERENCE_TYPE == REFERENCE_FLAG_UNDEFINED_NON_LAZY: 
                descriptions.append("0  REFERENCE_FLAG_UNDEFINED_NON_LAZY")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_UNDEFINED_LAZY:
                descriptions.append("1  REFERENCE_FLAG_UNDEFINED_LAZY")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_DEFINED:
                descriptions.append("2  REFERENCE_FLAG_DEFINED")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_PRIVATE_DEFINED:
                descriptions.append("3  REFERENCE_FLAG_PRIVATE_DEFINED")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY:
                descriptions.append("4  REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY:
                descriptions.append("5  REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY")    
            else:
                descriptions.append(n_desc & REFERENCE_TYPE,"???")     
      
            libOrdinal = get_library_ordinal(n_desc)
            framework = frameworks.get(libOrdinal)
            if framework is None:
                descriptions.append("Library Ordinal " + str(libOrdinal))
            else:
                descriptions.append("Library Ordinal " + str(libOrdinal) + "(" + framework + ")")
    
        if n_desc & N_ARM_THUMB_DEF == N_ARM_THUMB_DEF:
            descriptions.append("0008  N_ARM_THUMB_DEF") 
        if n_desc & REFERENCED_DYNAMICALLY == REFERENCED_DYNAMICALLY:
            descriptions.append("0010  REFERENCED_DYNAMICALLY") 
        if n_desc & N_NO_DEAD_STRIP == N_NO_DEAD_STRIP:
            descriptions.append("0020  N_NO_DEAD_STRIP")
        if n_desc & N_WEAK_REF == N_WEAK_REF:
            descriptions.append("0040  N_WEAK_REF")
        if n_type & N_TYPE == N_UNDF:
            if n_desc & N_REF_TO_WEAK == N_REF_TO_WEAK:
                descriptions.append("0080  N_REF_TO_WEAK")
        else:
            if n_desc & N_WEAK_DEF == N_WEAK_DEF:
                descriptions.append("0080  N_WEAK_DEF")
            if n_desc & N_SYMBOL_RESOLVER == N_SYMBOL_RESOLVER:
                descriptions.append("0100  N_SYMBOL_RESOLVER")
        symbols[hex(addr)] = utils.getDict(description,descriptions)
        addr += byte
    
        byte,n_value = ReadWrite.readInt32(path,endian,offset)
        offset += byte
        if n_type & N_TYPE == N_SECT:
            description = "Value"
            if n_type & N_STAB or section is None:
                if n_value == 0:
                    value = "0"
                else:
                    value = n_value
            else:
                value = str(n_value) + "(s+" + str(n_value - section.addr) + ")"
        else:
            description = "Value"
            value = n_value
        symbols[hex(addr)] = utils.getDict(description,value)
        addr += byte
     
    symbols = collections.OrderedDict(sorted(symbols.items()))   
    return symbols

def createSymbols64Node(sample,strs,path,baseAddr,baseStrAddr,nsym):
    endian = utils.getEndianFormat(sample)
    frameworks = utils.getAllFrameworks(sample)
    sections = utils.getSections(sample)
    count = 0
    symbols = {}
    addr = baseAddr
    offset = 0
    while count < nsym:
        count += 1
        
        byte,data = ReadWrite.readInt32(path,endian,offset)
        offset += byte
        description = "String Table Index"
        value = strs.get(hex(baseStrAddr+data).rstrip("L"))
        if value is None:
            value = ""
        symbols[hex(addr)] = utils.getDict(description,value)
        addr += byte
        
        byte,n_type = ReadWrite.readInt8(path,endian,offset)
        offset += byte
        types = []
        description = "Type"
        
        if n_type & N_STAB:
            types.append("E0  N_STAB")
        else:
            if n_type & N_TYPE == N_UNDF:
                types.append("00  N_UNDF")
            elif n_type & N_TYPE == N_ABS:
                types.append("02  N_ABS")
            elif n_type & N_TYPE == N_SECT:
                types.append("0E  N_SECT")
            elif n_type & N_TYPE == N_PBUD:
                types.append("0C  N_PBUD")
            elif n_type & N_TYPE == N_INDR:
                types.append("0A  N_INDR")
      
            if n_type & N_PEXT:
                types.append("10  N_PEXT")
            if n_type & N_EXT:
                types.append("01  N_EXT")
            
        symbols[hex(addr)] = utils.getDict(description,types)
        addr += byte
    
        byte,n_sect = ReadWrite.readInt8(path,endian,offset)
        offset += byte
        section = utils.getSectionByIndex(sections,n_sect)
        description = "Section Index"
        if n_sect == NO_SECT or section is None:
            value = "NO_SECT"
        else:
            value = str(n_sect) + "(" + section.segname.rstrip('\x00') + "," + section.sectname.rstrip('\x00') + ")"
        symbols[hex(addr)] = utils.getDict(description,value)
        addr += byte
        
        byte,n_desc = ReadWrite.readInt16(path,endian,offset)
        offset += byte
        descriptions = []
        description = "Description"
    
        if n_type & N_STAB == 0 and n_type & N_TYPE == N_UNDF or n_type & N_TYPE == N_PBUD and n_type & N_EXT:
            if n_desc & REFERENCE_TYPE == REFERENCE_FLAG_UNDEFINED_NON_LAZY: 
                descriptions.append("0  REFERENCE_FLAG_UNDEFINED_NON_LAZY")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_UNDEFINED_LAZY:
                descriptions.append("1  REFERENCE_FLAG_UNDEFINED_LAZY")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_DEFINED:
                descriptions.append("2  REFERENCE_FLAG_DEFINED")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_PRIVATE_DEFINED:
                descriptions.append("3  REFERENCE_FLAG_PRIVATE_DEFINED")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY:
                descriptions.append("4  REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY")    
            elif n_desc & REFERENCE_TYPE == REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY:
                descriptions.append("5  REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY")    
            else:
                descriptions.append(n_desc & REFERENCE_TYPE,"???")     
      
            libOrdinal = get_library_ordinal(n_desc)
            framework = frameworks.get(libOrdinal)
            if framework is None:
                descriptions.append("Library Ordinal " + str(libOrdinal))
            else:
                descriptions.append("Library Ordinal " + str(libOrdinal) + "(" + framework + ")")
    
        if n_desc & REFERENCED_DYNAMICALLY == REFERENCED_DYNAMICALLY:
            descriptions.append("0010  REFERENCED_DYNAMICALLY") 
        if n_desc & N_NO_DEAD_STRIP == N_NO_DEAD_STRIP:
            descriptions.append("0020  N_NO_DEAD_STRIP")
        if n_desc & N_WEAK_REF == N_WEAK_REF:
            descriptions.append("0040  N_WEAK_REF")
        if n_desc & N_WEAK_DEF == N_WEAK_DEF:
            if n_type & N_TYPE == N_UNDF or n_type & N_TYPE == N_PBUD:
                descriptions.append("0080  N_REF_TO_WEAK")
            else:
                descriptions.append("0080  N_WEAK_DEF")
        if n_desc & N_SYMBOL_RESOLVER == N_SYMBOL_RESOLVER:
            descriptions.append("0100  N_SYMBOL_RESOLVER")
        symbols[hex(addr)] = utils.getDict(description,descriptions)
        addr += byte
    
        byte,n_value = ReadWrite.readInt64(path,endian,offset)
        offset += byte
        if n_type & N_TYPE == N_SECT:
            description = "Value"
            if n_type & N_STAB or section is None:
                if n_value == 0:
                    value = "0"
                else:
                    value = n_value
            else:
                value = str(n_value) + "(s+" + str(n_value - section.addr) + ")"
        else:
            description = "Value"
            value = n_value
        symbols[hex(addr)] = utils.getDict(description,value)
        addr += byte
    
    symbols = collections.OrderedDict(sorted(symbols.items()))  
    return symbols

def getClassSymbols(sample):
    endian = utils.getEndianFormat(sample)
    strs = utils.getSymbolStrs(sample)
    desc = utils.getCommandInfos(sample,"LC_SYMTAB")
    baseStrAddr = desc.get("stroff")
    symAddress = desc.get("symoff")
    nsym = desc.get("nsyms")
    is64 = utils.is64Bit(sample)
    if is64:
        utils.getPartOfFile(sample,symAddress, nsym*16)
    else:
        utils.getPartOfFile(sample,symAddress, nsym*12)
    count = 0
    classSymbols = {}
    offset = 0
    while count < nsym:
        count += 1
        
        byte,data = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        description = "String Table Index"
        value = strs.get(hex(baseStrAddr+data).rstrip("L"))
        if value is None:
            value = ""
        
        offset += 4
        
        if is64:
            byte,n_value = ReadWrite.readInt64("temp",endian,offset)
        else:
            byte,n_value = ReadWrite.readInt32("temp",endian,offset)
        offset += byte
        classSymbols[hex(n_value).rstrip("L")] = value
    
    classSymbols = collections.OrderedDict(sorted(classSymbols.items()))  
    return classSymbols

def getFunctionNames(sample,strs):
    endian = utils.getEndianFormat(sample)
    sectionInfos = utils.getSectionInfoMaps(sample)
    desc = utils.getCommandInfos(sample,"LC_SYMTAB")
    baseStrAddr = desc.get("stroff")
    symAddress = desc.get("symoff")
    nsym = desc.get("nsyms")
    if utils.is64Bit(sample):
        step = 16
        utils.getPartOfFile(sample,symAddress, nsym*16)
    else:
        step = 12
        utils.getPartOfFile(sample,symAddress, nsym*12)
    os.rename("temp","tmp")
    count = 0
    names = {}
    offset = 0
    is64 = utils.is64Bit(sample)
    while count < nsym:
        count += 1
        
        byte,data = ReadWrite.readInt32("tmp",endian,offset)
        offset += 8
        value = strs.get(hex(baseStrAddr+data).rstrip("L"))
        if value is None:
            continue
        
        if is64:
            byte,n_value = ReadWrite.readInt64("tmp",endian,offset)
        else:
            byte,n_value = ReadWrite.readInt32("tmp",endian,offset)
        offset += byte
        key = utils.addressToFileOffset(sample,sectionInfos,n_value)
        names[hex(key)] = value
    os.remove("tmp")
    return names

def getSymbolsList(sample,strs):
    endian = utils.getEndianFormat(sample)
    count = 0
    symbols = {}
    symbolsList = []
    step = 0
    desc = utils.getCommandInfos(sample,"LC_SYMTAB")
    baseStrAddr = desc.get("stroff")
    symAddress = desc.get("symoff")
    nsym = desc.get("nsyms")
    if utils.is64Bit(sample):
        step = 16
        utils.getPartOfFile(sample,symAddress, nsym*16)
    else:
        step = 12
        utils.getPartOfFile(sample,symAddress, nsym*12)
    os.rename("temp","tmp")
    offset = 0  
    while count < nsym:
        count += 1
        
        byte,data = ReadWrite.readInt32("tmp",endian,offset)
        offset += step
        value = strs.get(hex(baseStrAddr+data).rstrip("L"))
        if value is None:
            value = ""
        symbolsList.append(value)
    os.remove("tmp")
    return symbolsList

def createISymbolsNode(sample,symbolsList,path,baseAddr,nindsym):
    endian = utils.getEndianFormat(sample)
    sections = utils.getSections(sample)
    is64 = utils.is64Bit(sample)
    count = 0
    inSymbols = {}
    addr = baseAddr
    offset = 0
    
    while count < nindsym:
        desc = []
        nsect = len(sections)
        while nsect > 0:
            nsect -= 1
            section = sections[nsect]
            flag = section.flags
#             print(section.reserved1)
            if (flag & SECTION_TYPE != S_SYMBOL_STUBS \
            and flag & SECTION_TYPE != S_LAZY_SYMBOL_POINTERS \
            and flag & SECTION_TYPE != S_LAZY_DYLIB_SYMBOL_POINTERS \
            and flag & SECTION_TYPE != S_NON_LAZY_SYMBOL_POINTERS) \
            or section.reserved1 > count:
                #section type or indirect symbol index mismatch
                continue
            
            nsect = 0
            #calculate stub or pointer length
            if section.reserved2 > 0:
                length = section.reserved2
            else:
                if is64:
                    length = 8
                else:
                    length = 4
        
            #calculate indirect value location
            indirectOffset = section.offset + (count - section.reserved1) * length
        
            #read indirect symbol index
            byte,indirectIndex = ReadWrite.readInt32(path,endian,offset)
            offset += byte
        
            if indirectIndex & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) == 0:
                if indirectIndex >= len(symbolsList):
                    raise Exception("index is out of range " + str(indirectIndex))
                symbolName = utils.getSymbolByIndex(symbolsList,indirectIndex)
                description = "Symbol"
                value = symbolName
                desc.append(utils.getDict(description,value)) 
            else:
                description = "Symbol"
                value = []
          
                if indirectIndex == INDIRECT_SYMBOL_LOCAL:
                    value.append("80000000  INDIRECT_SYMBOL_LOCAL")
                elif indirectIndex == INDIRECT_SYMBOL_ABS:
                    value.append("40000000  INDIRECT_SYMBOL_ABS")
                else:
                    value.append("80000000  INDIRECT_SYMBOL_LOCAL")
                    value.append("40000000  INDIRECT_SYMBOL_ABS")
                desc.append(utils.getDict(description,value))
            
            description = "Section"
            value = "(" + section.segname.rstrip('\x00') + "," + section.sectname.rstrip('\x00') + ")"
            desc.append(utils.getDict(description,value))
            
        
            description = "Indirect Address"
            value = hex(indirectOffset).rstrip("L") + "($+" + str(indirectOffset - section.offset) + ")"
            desc.append(utils.getDict(description,value))
            inSymbols[hex(addr)] = desc
            addr += byte
            
        count += 1
    
    inSymbols = collections.OrderedDict(sorted(inSymbols.items()))  
    return inSymbols

def getISymbols(sample):
    endian = utils.getEndianFormat(sample)
    symbols = utils.getSymbolStrs(sample)
    symbolsList = getSymbolsList(sample,symbols)
    sections = utils.getSections(sample)
    is64 = utils.is64Bit(sample)
    count = 0
    inSymbols = {}
    offset = 0
    desc = utils.getCommandInfos(sample,"LC_DYSYMTAB")
    inSymAddress = desc.get("indirectsymoff")
    nSymbol = desc.get("nindirectsyms")
    utils.getPartOfFile(sample, inSymAddress, nSymbol*4)
    os.rename("temp","tmp")
    while count < nSymbol:
        nsect = len(sections)
        while nsect > 0:
            nsect -= 1
            section = sections[nsect]
            flag = section.flags
#             print(section.reserved1)
            if (flag & SECTION_TYPE != S_SYMBOL_STUBS \
            and flag & SECTION_TYPE != S_LAZY_SYMBOL_POINTERS \
            and flag & SECTION_TYPE != S_LAZY_DYLIB_SYMBOL_POINTERS \
            and flag & SECTION_TYPE != S_NON_LAZY_SYMBOL_POINTERS) \
            or section.reserved1 > count:
                #section type or indirect symbol index mismatch
                continue
            
            nsect = 0
            #calculate stub or pointer length
            if section.reserved2 > 0:
                length = section.reserved2
            else:
                if is64:
                    length = 8
                else:
                    length = 4
        
            #calculate indirect value location
            indirectOffset = section.offset + (count - section.reserved1) * length
        
            #read indirect symbol index
            byte,indirectIndex = ReadWrite.readInt32("tmp",endian,offset)
            offset += byte
        
            if indirectIndex & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) == 0:
                if indirectIndex >= len(symbolsList):
                    raise Exception("index is out of range " + str(indirectIndex))
                symbolName = utils.getSymbolByIndex(symbolsList,indirectIndex)
                inSymbols[hex(indirectOffset).rstrip("L")] = symbolName

        count += 1
    os.remove("tmp")
    return inSymbols
            
