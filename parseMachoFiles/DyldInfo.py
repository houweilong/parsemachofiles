'''
Created on Dec 9, 2015

@author: hwl122902
'''

import json
import utils
import os
import ReadWrite
from loader import *
from capstoneUtils import *

def createRebaseNode(sample,path,baseAddr):
    endian = utils.getEndianFormat(sample)
    length = os.path.getsize(path)
    opcodes = {}
    actions = []
    offset = 0
    addr = baseAddr
    address = 0
    scale = 0
    typeValue = 0
    while offset<length:
        byte,data = ReadWrite.readInt8(path,endian,offset)
        offset += byte
        
        opcode = data & REBASE_OPCODE_MASK
        immediate = data & REBASE_IMMEDIATE_MASK
    
        if opcode ==  REBASE_OPCODE_DONE:
            description = "REBASE_OPCODE_DONE"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        elif opcode == REBASE_OPCODE_SET_TYPE_IMM:
            typeValue = immediate
            typeString = ""
            if typeValue == REBASE_TYPE_POINTER:
                typeString = "REBASE_TYPE_POINTER"
            elif typeValue == REBASE_TYPE_TEXT_ABSOLUTE32:
                typeString  = "REBASE_TYPE_TEXT_ABSOLUTE32"
            elif typeValue == REBASE_TYPE_TEXT_PCREL32:
                typeString = "REBASE_TYPE_TEXT_PCREL32"
            else:
                typeString = "Unknown"
            
            description = "REBASE_OPCODE_SET_TYPE_IMM"
            value = "type (" + str(typeValue) + "," + typeString + ")"
            
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
        elif opcode == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            segmentIndex = immediate
            description = "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"
            value = "segment (" + str(segmentIndex) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
         
            if offset>=length:
                break
            newByte,newData = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "offset (" + str(newData) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
        
            segments = utils.getSegments(sample)
            if segmentIndex>len(segments):
                raise Exception("index is out of range " + str(segmentIndex))
        
        elif opcode == REBASE_OPCODE_ADD_ADDR_ULEB:
            description = "REBASE_OPCODE_ADD_ADDR_ULEB"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
            
            if offset>=length:
                break
            newByte,newData = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "offset (" + str(newData) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
            
            
         
        elif opcode == REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            scale = immediate
            description = "REBASE_OPCODE_ADD_ADDR_IMM_SCALED"
            value = "scale (" + str(scale) + ")"
            opcodes[hex(addr)] = utils.getDict(description,"")
            addr += byte
            
        
        elif opcode == REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            count = immediate
            description = "REBASE_OPCODE_DO_REBASE_IMM_TIMES"
            value = "count (" + str(count) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
            
        
        elif opcode ==  REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
            description = "REBASE_OPCODE_DO_REBASE_ULEB_TIMES"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
            
            if offset>=length:
                break
            newByte,newData = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "count ("+ str(newData) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
            
        elif opcode == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
            description = "REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
            
            if offset>=length:
                break
            newByte,newData = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "offset (" + str(newData) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
            
        elif opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
            description = "REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
            
            if offset>=length:
                break
            newByte,newData = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "count (" + str(newData) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
            
            if offset>=length:
                break
            newByte,skip = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "skip (" + str(skip) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
            
        else:
            addr += byte
    
    return opcodes   



def createBindingNode(filePath,path,baseAddr):
    endian = utils.getEndianFormat(filePath)
    length = os.path.getsize(path)
    opcodes = {}
    offset = 0
    addr = baseAddr
    while offset<length:
        byte,data = ReadWrite.readInt8(path,endian,offset)
        offset += byte
        
        opcode = data & BIND_OPCODE_MASK
        immediate = data & BIND_IMMEDIATE_MASK
    
        if opcode ==  BIND_OPCODE_DONE:
            description = "BIND_OPCODE_DONE"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
        elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            libOrdinal = immediate
            description = "BIND_OPCODE_SET_DYLIB_ORDINAL_IMM"
            value = "dylib (" + str(libOrdinal) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
    
        elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            description = "BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
            if offset>=length:
                break
            newByte,libOrdinal = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "dylib (" + str(libOrdinal) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
        
        elif opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        
            #Special means negative
            if immediate == 0:
                libOrdinal = 0
            else: 
                signExtended = immediate | BIND_OPCODE_MASK #This sign extends the value
                libOrdinal = signExtended
        
            description = "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM"
            value = "dylib (" + str(libOrdinal) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
        elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            symbolFlags = immediate
            description = "BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM"
            value = "flags (" + str(symbolFlags) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte

            if offset>=length:
                break
            newByte,symbolName = ReadWrite.readString(path,offset)
            offset += newByte
            description = "string"
            value = "name (" + symbolName + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
        
        elif opcode == BIND_OPCODE_SET_TYPE_IMM:
            typeValue = immediate
            description = "BIND_OPCODE_SET_TYPE_IMM"
            typeString = ""
            if typeValue == BIND_TYPE_POINTER:
                typeString = "BIND_TYPE_POINTER"
            elif typeValue == BIND_TYPE_TEXT_ABSOLUTE32:
                typeString = "BIND_TYPE_TEXT_ABSOLUTE32"
            elif typeValue == BIND_TYPE_TEXT_PCREL32:
                typeString = "BIND_TYPE_TEXT_PCREL32"
            else:
                typeString = "???"
            value = "type (" + typeString + ")"
            opcodes[hex(addr)] = utils.getDict(description,typeString)
            addr += byte
        elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
            description = "BIND_OPCODE_SET_ADDEND_SLEB"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
            if offset>=length:
                break
            newByte,addend = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "sleb128"
            value = "addend (" + str(addend) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
    
        elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            segmentIndex = immediate
            description = "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"
            value = "segment (" + str(segmentIndex) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
            if offset>=length:
                break
            newByte,val = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "offset (" + str(val) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
        
        elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
            description = "BIND_OPCODE_ADD_ADDR_ULEB"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
            if offset>=length:
                break
            newByte,val = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "offset (" + str(val) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte   
        
        elif opcode ==  BIND_OPCODE_DO_BIND:  
            description = "BIND_OPCODE_DO_BIND"  
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB :
            description = "BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB"
            value = "" 
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
            if offset>=length:
                break
            newByte,val = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "offset (" + str(val) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte 

        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            scale = immediate
            description = "BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED"
            value = "scale (" + str(scale) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
     
        elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            description = "BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB"
            value = ""
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
        
            if offset>=length:
                break
            newByte,count = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "count (" + str(count) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
        
            if offset>=length:
                break
            newByte,skip = ReadWrite.read_uleb128(path,offset)
            offset += newByte
            description = "uleb128"
            value = "skip (" + str(skip) + ")"
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += newByte
        
        else:
            addr += byte
    
    return opcodes

def printSymbols(filePath,path,baseAddr):
    endian = utils.getEndianFormat(filePath)
    length = os.path.getsize(path)
    opcodes = {}
    offset = 0
    addr = baseAddr
    while offset<length:
        byte,terminalSize = ReadWrite.readInt8(path,endian,offset)
        offset += byte
        
        description = "Terminal Size"
        value = str(terminalSize)
        opcodes[hex(addr)] = utils.getDict(description,value)
        addr += byte
        
        if terminalSize != 0 and offset<length:
            byte,flags = ReadWrite.read_uleb128(path,offset)
            offset += byte
            value = []
            
            if (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_REGULAR:
                value.append("00  EXPORT_SYMBOL_FLAGS_KIND_REGULAR")
            if (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL:
                value.append("01  EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL")
            if flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION:
                value.append("04  EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION")
            if flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
                value.append("08  EXPORT_SYMBOL_FLAGS_REEXPORT")
            if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
                value.append("10  EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER")
            description = "Flags" 
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
            
            if offset>=length:
                break
            
            byte,offsets = ReadWrite.read_uleb128(path,offset)
            offset += byte
            description = "Symbol Offset"
            value = hex(offsets)
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
    
        if offset>=length:
            break
        byte,childCount = ReadWrite.readInt8(path,endian,offset)
        offset += byte
        
        if terminalSize==0 and childCount==0:
            break
        
        description = "Child Count"
        value = str(childCount)
        opcodes[hex(addr)] = utils.getDict(description,value)
        addr += byte
        
        
        while childCount > 0 and offset < length:
            byte,label = ReadWrite.readString(path,offset)
            offset += byte
            description = "Node Label"
            value = label
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte

            if offset>=length:
                break
            byte,skip = ReadWrite.read_uleb128(path,offset)
            offset += byte
            description = "Next Node"
            value = hex(baseAddr+skip)
            opcodes[hex(addr)] = utils.getDict(description,value)
            addr += byte
                
            childCount -= 1
        
    return opcodes

