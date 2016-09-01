from capstone import *
import struct
import utils
import os
import ReadWrite

class Codes(object):
    
    def __init__(self,md):
        self.md = md
        
    def readBinarayCode(self,path,inSymbols,names,baseAddr,start,length,outputPath):
        name = names.get(hex(start).rstrip("L"))
        if name is None:
            name = "sub_" + hex(start).rstrip("L")
        with open(outputPath + "/" + "assembly","a+") as f:
            f.write("-------------function " + name + " starts------------" + "\n")
        fin = open(path,"rb")
        fin.seek(start-baseAddr) 
        CODE = fin.read(length)
        self.disAssembly(self.md,inSymbols,CODE,start,outputPath)
        
        with open(outputPath + "/" + "assembly","a+") as f:
            f.write("-------------function " + name + " ends------------" + "\n")
            f.write("\n")
        fin.close()


    def disAssembly(self,md,inSymbols,code,address,outputPath):
        try:
            for (address, size, mnemonic, op_str) in md.disasm_lite(code, address):
                with open(outputPath + "/" + "assembly","a+") as f:
                    if utils.isNumber(op_str.lstrip("#")):
                        op_fun = inSymbols.get(op_str.lstrip("#"))
                        if op_fun is not None:
                            op_str = "[" + op_str.lstrip("#") + "->" + op_fun + "]"
                    f.write("0x%x:\t%s\t%s" %(address, mnemonic, op_str))
                    f.write("\n")
        except CsError as e:
            print("ERROR: %s" %e) 
        
def getFunctionStarts(path,baseAddr):
    length = os.path.getsize(path)
    offset = 0
    addr = baseAddr
    function_starts = []
    while offset<length:
        byte,data = ReadWrite.read_uleb128(path,offset)
        if offset!=0:
            addr+=data
        function_starts.append(addr)
        offset += byte
    return function_starts

def getFunctions(code,inSymbols,names,path,baseAddr,outputPath):
    logger = utils.setLogger()
    starts = getFunctionStarts(path,baseAddr)
    length = len(starts)
    logger.info("It will disassembly the function in this file,please wait ...")
    for i in range(length):
        if i+1<length:
            size = starts[i+1]-starts[i]
            code.readBinarayCode("codes", inSymbols,names,baseAddr, starts[i], size,outputPath)
    logger.info("all function has been disassembled")

