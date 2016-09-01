'''
Created on Dec 16, 2015

@author: hwl122902
'''
import struct
import os
import string

def readInt8(path,endian,offset = 0):
    file = open(path,"rb")
    file.seek(offset)
    result = struct.unpack(endian + "B", file.read(1))[0]
    file.close()
    return 1,result    

def readInt16(path,endian,offset = 0):
    file = open(path,"rb")
    file.seek(offset)
    result = struct.unpack(endian + "H", file.read(2))[0]
    file.close()
    return 2,result    

def readInt32(path,endian,offset = 0):
    file = open(path,"rb")
    file.seek(offset)
    result = struct.unpack(endian + "I", file.read(4))[0]
    file.close()
    return 4,result    

def readInt64(path,endian,offset = 0):
    file = open(path,"rb")
    file.seek(offset)
    result = struct.unpack(endian + "Q", file.read(8))[0]
    file.close()
    return 8,result    

def readBytes(path,offset,length):
    file = open(path,"rb")
    file.seek(offset)
    result = file.read(length)
    file.close()
    return result 

def strings(filename, min=1):
    with open(filename, "rb") as f:
        result = ""
        length = 0
        address = 0
        for c in f.read():
            length += 1
            if c in string.printable:
                address += 1
                result += c
                continue
            if len(result) >= min:
                yield (length-address-1),result
            result = ""
            address = 0
            
#return all the file in this path
def readPath(path):
    fileList = []
    files = os.listdir(path)
    for f in files:
        if(os.path.isfile(path + "/" + f)):
            fileList.append(f)
    return fileList

def readBinaray(path,endian,form):
    size = struct.calcsize(form)
    binList = []
    offset = 0
    fin = open(path,"rb") 
    length = os.path.getsize(path)
    while offset<length:
        bin = struct.unpack(endian+form,fin.read(size))[0]
        offset += size
        binList.append(hex(bin))
    fin.close()
    return binList

def readString(path,off = 0):
    offset = off
    fin = open(path,"rb") 
    fin.seek(offset)
    cr = struct.unpack("c",fin.read(1))[0]
    byte = 1
    offset += 1
    result = ""
    while cr != "\0":
        result += cr
        fin.seek(offset)
        cr = struct.unpack("c",fin.read(1))[0]
        byte += 1
        offset += 1
        #str = str.decode('unicode-escape').encode('utf-8')
    fin.close()
    return byte,result 

def read_uleb128(path,offset=0):
    file = open(path,"rb")
    file.seek(offset)
    result = 0
    bit = 0
    byte = 0
    while True:
        byte += 1
        tmp = struct.unpack(">B", file.read(1))[0]
        slice = tmp&0x7f
        result |= (slice << bit)
        bit += 7;
        if not tmp&0x80:
            break
        if bit>=64 or slice << bit >> bit != slice:
            raise Exception("uleb128 too big")
    file.close()
    return byte,result
    
    
  
  
