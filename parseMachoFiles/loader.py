'''
Created on Dec 9, 2015

@author: hwl122902
'''

FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca    #NXSwapLong(FAT_MAGIC) */

CPU_ARCH_ABI64 = 0x01000000      # 64 bit ABI 
#The following are used to encode rebasing information
REBASE_TYPE_POINTER = 1
REBASE_TYPE_TEXT_ABSOLUTE32 = 2
REBASE_TYPE_TEXT_PCREL32 = 3

REBASE_OPCODE_MASK = 0xF0
REBASE_IMMEDIATE_MASK = 0x0F
REBASE_OPCODE_DONE = 0x00
REBASE_OPCODE_SET_TYPE_IMM = 0x10
REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20
REBASE_OPCODE_ADD_ADDR_ULEB = 0x30
REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40
REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50
REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60
REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80



#The following are used to encode binding information
BIND_TYPE_POINTER = 1
BIND_TYPE_TEXT_ABSOLUTE32 = 2
BIND_TYPE_TEXT_PCREL32 = 3

BIND_SPECIAL_DYLIB_SELF = 0
BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1
BIND_SPECIAL_DYLIB_FLAT_LOOKUP = -2

BIND_SYMBOL_FLAGS_WEAK_IMPORT = 0x1
BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = 0x8

BIND_OPCODE_MASK = 0xF0
BIND_IMMEDIATE_MASK = 0x0F
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0



#The following are used on the flags byte of a terminal node in the export information.
EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03
EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x00
EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x01
EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = 0x04
EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10

N_STAB = 0xe0 
N_PEXT = 0x10  
N_TYPE = 0x0e  
N_EXT = 0x01  


#Values for N_TYPE bits of the n_type field.
N_UNDF = 0x0        
N_ABS = 0x2        
N_SECT = 0xe       
N_PBUD = 0xc        
N_INDR = 0xa        

NO_SECT = 0   #symbol is not in any section 
MAX_SECT = 255   #1 thru 255 inclusive 

#Reference type bits of the n_desc field of undefined symbols 
REFERENCE_TYPE = 0x7
#types of references 
REFERENCE_FLAG_UNDEFINED_NON_LAZY = 0
REFERENCE_FLAG_UNDEFINED_LAZY = 1
REFERENCE_FLAG_DEFINED = 2
REFERENCE_FLAG_PRIVATE_DEFINED = 3
REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY = 4
REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY = 5

SELF_LIBRARY_ORDINAL = 0x0
MAX_LIBRARY_ORDINAL = 0xfd
DYNAMIC_LOOKUP_ORDINAL = 0xfe
EXECUTABLE_ORDINAL = 0xff


N_ARM_THUMB_DEF = 0x0008   #symbol is a Thumb function (ARM) */
REFERENCED_DYNAMICALLY = 0x0010
N_NO_DEAD_STRIP = 0x0020  #symbol is not to be dead stripped */
N_WEAK_REF = 0x0040 #symbol is weak referenced */
N_SYMBOL_RESOLVER = 0x0100 

N_REF_TO_WEAK = 0x0080 #reference to a weak symbol */

SECTION_TYPE = 0x000000ff    #256 section types 
S_SYMBOL_STUBS = 0x8    #section with only symbol
S_LAZY_SYMBOL_POINTERS = 0x7    #section with only lazy symbol
S_NON_LAZY_SYMBOL_POINTERS = 0x6    #section with only non-lazy


S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10    #section with only lazy
S_SYMBOL_STUBS = 0x8    #section with only symbol

S_LITERAL_POINTERS = 0x5    #section with only pointers to */
S_MOD_INIT_FUNC_POINTERS = 0x9    #section with only function
S_MOD_TERM_FUNC_POINTERS = 0xa    #section with only function
S_CSTRING_LITERALS = 0x2    #section with only literal C strings*/
S_4BYTE_LITERALS = 0x3     #section with only 4 byte literals */
S_8BYTE_LITERALS = 0x4    #section with only 8 byte literals */
S_16BYTE_LITERALS = 0xe    #section with only 16 byte

CPU_TYPE_ARM = 12
CPU_ARCH_ABI64 = 0x01000000        #64 bit ABI */
CPU_TYPE_ARM64 = (CPU_TYPE_ARM | CPU_ARCH_ABI64)
CPU_SUBTYPE_ARM_V7 = 9
CPU_SUBTYPE_ARM_V7F = 10  # Cortex A9 */
CPU_SUBTYPE_ARM_V7S = 11 # Swift */
CPU_SUBTYPE_ARM_V7K = 12 # Kirkwood40 */
CPU_SUBTYPE_ARM_V8 = 13

S_ATTR_PURE_INSTRUCTIONS = 0x80000000    #section contains only true

OBJC_IMAGE_IS_REPLACEMENT = (1<<0)
OBJC_IMAGE_SUPPORTS_GC = (1<<1)
OBJC_IMAGE_GC_ONLY = (1<<2)

MH_MAGIC = 0xfeedface    #the mach magic number */
MH_CIGAM = 0xcefaedfe    #NXSwapInt(MH_MAGIC) */
MH_MAGIC_64 = 0xfeedfacf  #the 64-bit mach magic number */
MH_CIGAM_64 = 0xcffaedfe  #NXSwapInt(MH_MAGIC_64) */

CPU_TYPE_ANY = -1  #Machine types known by all.

CPU_TYPE_X86 = 7
CPU_TYPE_I386 = CPU_TYPE_X86        #compatibility */
CPU_TYPE_POWERPC = 18
CPU_TYPE_POWERPC64 = (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)
CPU_TYPE_X86_64 = (CPU_TYPE_X86 | CPU_ARCH_ABI64)


if __name__ == "__main__":
    print(0xD00&0xF0)