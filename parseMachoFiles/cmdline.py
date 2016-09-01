'''
Created on Dec 9, 2015

@author: hwl122902
'''
import utils
import os
import hashlib
import json
import collections
import SymbolContents
import SectionContents 
import DyldInfo
import objc
from biplist import *
from loader import *
from macholib.MachO import MachO


def splitFatBinaryFile(path,outputPath):
    logger = utils.setLogger()
    if not utils.isFatBinary(path):
        logger.info("this file is not fat binary file,can not be splited")
        return
    
    m = MachO(path)
    for header in m.headers:
        utils.getPartOfFile(path,header.offset,header.size)
        fin = open("temp","rb")
        s1 = hashlib.sha1(fin.read()).hexdigest()
        fin.close()
        os.rename("temp", outputPath + "/" + s1)
    logger.info("this fat binary file has been splited sucessfully")
        

def getHeaderOfMacho(filePath,outputPath):
    rout = {}
    logger = utils.setLogger()
    header = utils.getHeader(filePath)
    descripe = dict(header.header._describe())
    rout["MachoHeader"] = descripe
    magicNum = descripe.get("magic")
    cuptypeNum = descripe.get("cputype")
    if magicNum == MH_MAGIC:
        descripe["magic_string"] = "MH_MAGIC"
    elif magicNum == MH_CIGAM:
        descripe["magic_string"] = "MH_CIGAM"
    elif magicNum == MH_MAGIC_64:
        descripe["magic_string"] = "MH_MAGIC_64"
    elif magicNum == MH_CIGAM_64:
        descripe["magic_string"] = "MH_CIGAM_64"
        
        
    if cuptypeNum == CPU_TYPE_ANY:
        descripe["cputype_string"] = "CPU_TYPE_ANY"
    elif cuptypeNum == CPU_TYPE_I386:
        descripe["cputype_string"] = "CPU_TYPE_I386"
    elif cuptypeNum == CPU_TYPE_ARM:
        descripe["cputype_string"] = "CPU_TYPE_ARM"
    elif cuptypeNum == CPU_TYPE_POWERPC:
        descripe["cputype_string"] = "CPU_TYPE_POWERPC"
    elif cuptypeNum == CPU_TYPE_POWERPC64:
        descripe["cputype_string"] = "CPU_TYPE_POWERPC64"
    elif cuptypeNum == CPU_TYPE_X86_64:
        descripe["cputype_string"] = "CPU_TYPE_X86_64"
    elif cuptypeNum == CPU_TYPE_ARM64:
        descripe["cputype_string"] = "CPU_TYPE_ARM64"
        
    outFinal = json.dumps(rout, encoding='latin1')
    with open(outputPath + "/" + "headers","w") as f:
        f.write(outFinal)
    logger.info("It has got the headers of the mach-o file sucessfully")
    
def readInfoFile(filePath,outputPath):
    logger = utils.setLogger()
    try:
        fout = {}
        plist = readPlist(filePath)
        fout["plist"] = plist
        outFinal = json.dumps(fout, encoding='latin1')
        with open(outputPath + "/" + "Info.plist","w") as f:
            f.write(outFinal)
        logger.info("It has finished parsing Info.plist")
    except (InvalidPlistException, NotBinaryPlistException), e:
        print("this file is not a plist:", e)
        
def getAllLoadCommandInfos(filePath,outputPath):
    infos = {}   
    logger = utils.setLogger()
    header = utils.getHeader(filePath)
    for (index,(lc, cmd, data)) in enumerate(header.commands):
        command = {}
        desc = cmd.describe()
        lc_name = lc.get_cmd_name()
        if lc_name==44:
            if utils.is64Bit(filePath):
                lc_name = "LC_ENCRYPTION_INFO_64"
            else:
                lc_name = "LC_ENCRYPTION_INFO" 
        if isinstance(data, str):
            desc["Name"] = data.rstrip('\x00')
        command[lc_name] = desc
        infos[index] = command 
    infos = collections.OrderedDict(sorted(infos.items()))
    outFinal = json.dumps(infos, encoding='latin1')
    with open(outputPath + "/" + "loadCommands","w") as f:
        f.write(outFinal)
    logger.info("It has got all infos of load commands sucessfully")

def getAllFrameworks(filePath,outputPath):
    frameworks = {}
    logger = utils.setLogger()
    frameworks["frameworks"] = list(utils.getFramework(filePath))
    outFinal = json.dumps(frameworks, encoding='latin1')
    with open(outputPath + "/" + "frameworks","w") as f:
        f.write(outFinal)
    logger.info("It has got all infos of load commands sucessfully")

def getDynamicLoaderInfo(filePath,outputPath):
    logger = utils.setLogger()
    desc = utils.getCommandInfos(filePath,"LC_DYLD_INFO")
    if desc is None:
        desc = utils.getCommandInfos(filePath,"LC_DYLD_INFO_ONLY")
    rebase_off = desc.get("rebase_off")
    rebase_size = desc.get("rebase_size")
    if rebase_off is not None and rebase_size is not None:
        utils.getPartOfFile(filePath,rebase_off, rebase_size)
        opcodes = DyldInfo.createRebaseNode(filePath,"temp",rebase_off)
        opcodes = collections.OrderedDict(sorted(opcodes.items()))
        desc["Rebase Info(opcodes)"] = opcodes
     
    bind_off = desc.get("bind_off")
    bind_size = desc.get("bind_size") 
    if bind_off is not None and bind_size is not None:      
        utils.getPartOfFile(filePath,bind_off, bind_size)
        opcodes = DyldInfo.createBindingNode(filePath,"temp",bind_off)
        opcodes = collections.OrderedDict(sorted(opcodes.items()))
        desc["Binding Info(opcodes)"] = opcodes
     
    weak_bind_off = desc.get("weak_bind_off")
    weak_bind_size = desc.get("weak_bind_size") 
    if weak_bind_off is not None and weak_bind_size is not None:        
        utils.getPartOfFile(filePath,weak_bind_off, weak_bind_size)
        opcodes = DyldInfo.createBindingNode(filePath,"temp",weak_bind_off)
        opcodes = collections.OrderedDict(sorted(opcodes.items()))
        desc["Weak Binding Info(opcodes)"] = opcodes
    
    lazy_bind_off = desc.get("lazy_bind_off")
    lazy_bind_size = desc.get("lazy_bind_size") 
    if lazy_bind_off is not None and lazy_bind_size is not None:        
        utils.getPartOfFile(filePath,lazy_bind_off, lazy_bind_size)
        opcodes = DyldInfo.createBindingNode(filePath,"temp",lazy_bind_off)
        opcodes = collections.OrderedDict(sorted(opcodes.items()))
        desc["Lazy Binding Info(opcodes)"] = opcodes
     
    export_off = desc.get("export_off")
    export_size = desc.get("export_size") 
    if export_off is not None and export_size is not None:       
        utils.getPartOfFile(filePath,export_off, export_size)
        opcodes = DyldInfo.printSymbols(filePath,"temp",export_off)
        opcodes = collections.OrderedDict(sorted(opcodes.items()))
        desc["Export Info(opcodes)"] = opcodes
            
    if os.path.exists("temp"):
        os.remove("temp")
    outFinal = json.dumps(desc, encoding='latin1')
    with open(outputPath + "/" + "dynamicLoaderInfo","w") as f:
        f.write(outFinal)
    logger.info("It has got all infos of dynamic loader info sucessfully")

def getSymbolTables(filePath,outputPath):
    logger = utils.setLogger()
    strs = utils.getSymbolStrs(filePath)
    desc = utils.getCommandInfos(filePath,"LC_SYMTAB")
    strAddress = desc.get("stroff")
    symAddress = desc.get("symoff")
    if utils.is64Bit(filePath):
        utils.getPartOfFile(filePath,desc.get("symoff"), desc.get("nsyms")*16)
        os.rename("temp","tmp")
        symbolStrs = SymbolContents.createSymbols64Node(filePath,strs,"tmp",symAddress,strAddress,desc.get("nsyms"))
    else:
        utils.getPartOfFile(filePath,desc.get("symoff"), desc.get("nsyms")*12)
        os.rename("temp","tmp")
        symbolStrs = SymbolContents.createSymbolsNode(filePath,strs,"tmp",symAddress,strAddress,desc.get("nsyms"))
            
    desc["symbols"] = symbolStrs
    os.remove("tmp")
    outFinal = json.dumps(desc, encoding='latin1')
    with open(outputPath + "/" + "symbolTables","w") as f:
        f.write(outFinal)
    logger.info("It has got all infos of symbol tables sucessfully")
    
def getDynamicSymbolTables(filePath,outputPath):
    logger = utils.setLogger()
    strs = utils.getSymbolStrs(filePath)
    symbolsList = SymbolContents.getSymbolsList(filePath,strs)
    desc = utils.getCommandInfos(filePath,"LC_DYSYMTAB")
    inSymAddress = desc.get("indirectsymoff")
    nSymbol = desc.get("nindirectsyms")
    utils.getPartOfFile(filePath, inSymAddress, nSymbol*4)
    os.rename("temp","tmp")
    desc["inSymbols"] = SymbolContents.createISymbolsNode(filePath,symbolsList,"tmp",inSymAddress,nSymbol)
    os.remove("tmp")
    outFinal = json.dumps(desc, encoding='latin1')
    with open(outputPath + "/" + "dynamicSymbolTables","w") as f:
        f.write(outFinal)
    logger.info("It has get all infos of dynamic symbol tables sucessfully")
        
def getAllPointersOfMacho(filePath,outputPath):
    logger = utils.setLogger()
    pointers = {}
    sections = utils.getSections(filePath)
    symbolNames = utils.getMethodNames(filePath)
    inSymbols = SymbolContents.getISymbols(filePath)
    for section in sections:
        flag = section.flags & SECTION_TYPE
        if flag == S_4BYTE_LITERALS:
            secDesc = section.describe()
            secDesc["Floating Point Literals"] = SectionContents.createLiteralsNode(filePath,section,4)
            pointers[section.sectname.rstrip('\x00')] = secDesc
            
        elif flag == S_8BYTE_LITERALS:
            secDesc = section.describe()
            secDesc["Floating Point Literals"] = SectionContents.createLiteralsNode(filePath,section,8)
            pointers[section.sectname.rstrip('\x00')] = secDesc
            
        elif flag == S_16BYTE_LITERALS:
            secDesc = section.describe()
            secDesc["Floating Point Literals"] = SectionContents.createLiteralsNode(filePath,section,8)
            pointers[section.sectname.rstrip('\x00')] = secDesc
        #================ sections with pointer content ============================
        elif flag == S_LITERAL_POINTERS:
            secDesc = section.describe()
            secDesc["Literal Pointers"] = SectionContents.createPointersNode(filePath,section,symbolNames)
            pointers[section.sectname.rstrip('\x00')] = secDesc
        elif flag == S_MOD_INIT_FUNC_POINTERS:
            secDesc = section.describe()
            secDesc["Module Init Func Pointers"] = SectionContents.createPointersNode(filePath,section,symbolNames)
            pointers[section.sectname.rstrip('\x00')] = secDesc
        elif flag == S_MOD_TERM_FUNC_POINTERS:
            secDesc = section.describe()
            secDesc["Module Term Func Pointers"] = SectionContents.createPointersNode(filePath,section,symbolNames)
            pointers[section.sectname.rstrip('\x00')] = secDesc
        elif flag == S_LAZY_SYMBOL_POINTERS:
            secDesc = section.describe()
            if utils.is64Bit(filePath):
                secDesc["Lazy Symbol Pointers"] = SectionContents.createIndPointers64Node(filePath,section,inSymbols)
            else:
                secDesc["Lazy Symbol Pointers"] = SectionContents.createIndPointersNode(filePath,section,inSymbols)
            pointers[section.sectname.rstrip('\x00')] = secDesc
        elif flag == S_NON_LAZY_SYMBOL_POINTERS:
            secDesc = section.describe()
            if utils.is64Bit(filePath):
                secDesc["Non-Lazy Symbol Pointers"] = SectionContents.createIndPointers64Node(filePath,section,inSymbols)
            else:
                secDesc["Non-Lazy Symbol Pointers"] = SectionContents.createIndPointersNode(filePath,section,inSymbols)
            pointers[section.sectname.rstrip('\x00')] = secDesc
        elif flag == S_LAZY_DYLIB_SYMBOL_POINTERS:
            secDesc = section.describe()
            if utils.is64Bit(filePath):
                secDesc["Lazy Dylib Symbol Pointers"] = SectionContents.createIndPointers64Node(filePath,section,inSymbols)
            else:
                secDesc["Lazy Dylib Symbol Pointers"] = SectionContents.createIndPointersNode(filePath,section,inSymbols)
            pointers[section.sectname.rstrip('\x00')] = secDesc
        elif flag == S_SYMBOL_STUBS:
            secDesc = section.describe()
            secDesc["Symbol Stubs"] = SectionContents.createIndStubsNode(filePath,section,inSymbols)
            pointers[section.sectname.rstrip('\x00')] = secDesc
        else:
            pass
    outFinal = json.dumps(pointers, encoding='latin1')
    with open(outputPath + "/" + "pointers","w") as f:
        f.write(outFinal)

def processObjcSections(filePath, outputPath,sections):
    logger = utils.setLogger()
    cfStrings = {}
    cStrings = utils.getCStrings(filePath)
    sectionInfos = utils.getSectionInfoMaps(filePath)
    hasObjCModules = False
    for section in sections:
        sectionName = section.sectname.rstrip("\x00")
        segmentName = section.segname.rstrip("\x00")
        if sectionName == "__cfstring":
            secDesc = section.describe()
            if utils.is64Bit(filePath):
                secDesc["C String Literals"] = objc.createObjCCFStrings64Node(filePath, section, cStrings, sectionInfos)
            else:
                secDesc["C String Literals"] = objc.createObjCCFStringsNode(filePath, section, cStrings, sectionInfos)
            cfStrings[segmentName+"("+sectionName+")"] = secDesc
        
        #first Objective-C ABI
        if sectionName == "__module_info" and segmentName == "__OBJC":
            hasObjCModules = True
            secDesc = section.describe()
            cfStrings[segmentName+"("+sectionName+")"] = secDesc
        
        if sectionName == "__class_ext" and segmentName == "__OBJC":
            secDesc = section.describe()
            cfStrings[segmentName+"("+sectionName+")"] = secDesc
        
        if sectionName == "__protocol_ext" and segmentName == "__OBJC":
            secDesc = section.describe()
            cfStrings[segmentName+"("+sectionName+")"] = secDesc
        
        #second Objective-C ABI
        if not hasObjCModules:
            if (sectionName == "__category_list" and segmentName == "__OBJC2") \
             or (sectionName == "__objc_catlist" and segmentName == "__DATA"):
                secDesc = section.describe()
                if utils.is64Bit(filePath):
                    secDesc["ObjC2 Category List"] = objc.createObjC2Pointer64ListNode(filePath,section)
                else:
                    secDesc["ObjC2 Category List"] = objc.createObjC2PointerListNode(filePath,section)
                cfStrings[segmentName+"("+sectionName+")"] = secDesc
            
            if (sectionName == "__class_list" and segmentName == "__OBJC2") \
             or (sectionName == "__objc_classlist" and segmentName == "__DATA"):
                secDesc = section.describe()
                if utils.is64Bit(filePath):
                    secDesc["ObjC2 Class List"] = objc.createObjC2Pointer64ListNode(filePath,section)
                else:
                    secDesc["ObjC2 Class List"] = objc.createObjC2PointerListNode(filePath,section)
                cfStrings[segmentName+"("+sectionName+")"] = secDesc
            
            if (sectionName == "__class_refs" and segmentName == "__OBJC2") \
             or (sectionName == "__objc_classrefs" and segmentName == "__DATA"):
                secDesc = section.describe()
                if utils.is64Bit(filePath):
                    secDesc["ObjC2 References"] = objc.createObjC2Pointer64ListNode(filePath,section)
                else:
                    secDesc["ObjC2 References"] = objc.createObjC2PointerListNode(filePath,section)
                cfStrings[segmentName+"("+sectionName+")"] = secDesc
            
            if (sectionName == "__super_refs" and segmentName == "__OBJC2") \
             or (sectionName == "__objc_superrefs" and segmentName == "__DATA"):
                secDesc = section.describe()
                if utils.is64Bit(filePath):
                    secDesc["ObjC2 References"] = objc.createObjC2Pointer64ListNode(filePath,section)
                else:
                    secDesc["ObjC2 References"] = objc.createObjC2PointerListNode(filePath,section)
                cfStrings[segmentName+"("+sectionName+")"] = secDesc
            
            if (sectionName == "__protocol_list" and segmentName == "__OBJC2") \
             or (sectionName == "__objc_protolist" and segmentName == "__DATA"):
                secDesc = section.describe()
                if utils.is64Bit(filePath):
                    secDesc["ObjC2 Pointer List"] = objc.createObjC2Pointer64ListNode(filePath,section)
                else:
                    secDesc["ObjC2 Pointer List"] = objc.createObjC2PointerListNode(filePath,section)
                cfStrings[segmentName+"("+sectionName+")"] = secDesc
            
            if (sectionName == "__message_refs" and segmentName == "__OBJC2") \
             or (sectionName == "__objc_msgrefs" and segmentName == "__DATA"):
                secDesc = section.describe()
                if utils.is64Bit(filePath):
                    secDesc["ObjC2 Message References"] = objc.createObjC2MsgRefs64Node(filePath,section)
                else:
                    secDesc["ObjC2 Message References"] = objc.createObjC2MsgRefsNode(filePath,section)
                cfStrings[segmentName+"("+sectionName+")"] = secDesc
            
        if (sectionName == "__image_info" and segmentName == "__OBJC2") \
            or (sectionName == "__objc_imageinfo" and segmentName == "__DATA"):
            secDesc = section.describe()
            secDesc["ObjC2 Image Info"] = objc.createObjCImageInfoNode(filePath,section)
            cfStrings[segmentName+"("+sectionName+")"] = secDesc
            
    outFinal = json.dumps(cfStrings, encoding='latin1')
    with open(outputPath + "/" + "objcInfos","w") as f:
        f.write(outFinal)
    logger.info("It has got all infos of objective-c sections in the mach-o file sucessfully")
        

if __name__ == "__main__":
    logger = utils.setLogger()
    path = "machoFiles/ToolbarSearch"
    outputPath = "/home/hwl122902/Desktop"
    getDynamicSymbolTables(path,outputPath)
