
from __future__ import print_function, absolute_import
import os, sys
import cmdline 
import utils
import json
import collections
import SectionContents
from loader import *
from macholib.util import is_platform_file

gCommand = None

def check_file(filePath,gCommand,outputPath):
    if not os.path.exists(filePath):
        print("the input file does not exist,please input again")
        sys.exit(1)
        
    if not os.path.exists(outputPath):
        print("the output path does not exist,please input again")
        sys.exit(1)

    try:
        is_macho = is_platform_file(filePath)
        is_fat = utils.isFatBinary(filePath)
        is_InfoPlist = (gCommand == "plist") \
            and (filePath.split("/")[-1] == "Info.plist")

    except IOError as msg:
        print('%s: %s: %s' % (gCommand, path, msg), file=sys.stderr)
        sys.exit(1)

    if not (is_macho or is_fat or is_InfoPlist):
        print("the input file is not macho file or fat binary file or Info.plist,please input again")
        sys.exit(1)


def print_usage(fp):
    print("Usage: python main.py [options] <mach-o-file> output <dir>", file=sys.stderr)
    print("    where options are:", file=fp)
    print("      H         :  get the header of this mach-o file", file=fp)
    print("    plist       :  get the infos in the Info.plist file", file=fp)
    print("    split       :  split fat binary file to mach-o file", file=fp)
    print("    objc        :  get all infos of objective-c sections in this mach-o files", file=fp)
    print("    strings     :  get all strings in this mach-o files", file=fp)
    print("    pointers    :  get all pointers in this mach-o files", file=fp)
    print("    disassembly :  get all functions in this mach-o file", file=fp)
    print("    framework   :  get all frameworks in this mach-o file", file=fp)
    print("    symbols     :  get all symbol tables in this mach-o file", file=fp)
    print("    dSymbols    :  get all dynamic symbol tables in this mach-o file", file=fp)
    print("    dlInfos     :  get all dynamic loader info in this mach-o file", file=fp)
    print("    lCommands   :  get all infos of Load Commands in this mach-o file", file=fp)
  
def main():
    global gCommand
    global outputPath
    logger = utils.setLogger()
    
    if len(sys.argv) != 5:
        print_usage(sys.stderr)
        sys.exit(1)

    if sys.argv[3] != "output":
        print("the fourth parameter must be 'output' ")
        sys.exit(1)
        
    gCommand = sys.argv[1]
    outputPath = sys.argv[4]
    filePath = sys.argv[2]
    
    check_file(filePath,gCommand,outputPath)
    
    if gCommand != "plist":
        sections = utils.getSections(filePath)
    
    if gCommand == "H":
        cmdline.getHeaderOfMacho(filePath,outputPath)
    
    elif gCommand == "plist":
        cmdline.readInfoFile(filePath,outputPath)
    
    elif gCommand == "split":
        cmdline.splitFatBinaryFile(filePath,outputPath)
        
    elif gCommand == "objc":
        cmdline.processObjcSections(filePath, outputPath,sections)
                 
    elif gCommand == "strings":
        strings = {}
        for section in sections:
            flag = section.flags & SECTION_TYPE
            if flag == S_CSTRING_LITERALS:
                secDesc = section.describe()
                secDesc["C String Literals"] = SectionContents.createCStringsNode(filePath,section)
                strings[section.sectname.rstrip('\x00')] = secDesc
        outFinal = json.dumps(strings, encoding='latin1')
        with open(outputPath + "/" + "strings","w") as f:
            f.write(outFinal)
        logger.info("It has got all strings of the mach-o file sucessfully")
     
    elif gCommand == "pointers":
        cmdline.getAllPointersOfMacho(filePath,outputPath)
        logger.info("It has got all pointers of the mach-o file sucessfully")
                   
    elif gCommand == "disassembly":
        for section in sections:
            flag = section.flags & SECTION_TYPE
            if section.flags & S_ATTR_PURE_INSTRUCTIONS and flag != S_SYMBOL_STUBS:
                SectionContents.createTextNode(filePath,section,outputPath)

    elif gCommand == "framework":
        cmdline.getAllFrameworks(filePath,outputPath)
        
    elif gCommand == "symbols":
        cmdline.getSymbolTables(filePath,outputPath)
    
    elif gCommand == "dSymbols":
        cmdline.getDynamicSymbolTables(filePath,outputPath)
    
    elif gCommand == "dlInfos":
        cmdline.getDynamicLoaderInfo(filePath,outputPath)
    
    elif gCommand == "lCommands":
        cmdline.getAllLoadCommandInfos(filePath,outputPath)

    else:
        print_usage(sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
    
