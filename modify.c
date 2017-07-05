/*
 * C语言文件: modify.c
 *
 * 描述: 修改so文件（ELF文件）方法名以及方法对应的hash
 *
 * 用法:
 *          modify <lib***.so> <dst_sym> <src_sym>
 *         （提示: 当 dst_sym == src_sym, ELF 文件不会有任何改变。）
 *
 * 作者: barryng (swingsky.wu@gmail.com)
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>

#define EI_NIDENT (16)

typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint16_t Elf32_Section;

/* 函数声明 */
Elf32_Half readValueFromFile(int fd,Elf32_Off target_offset);
void writeValueToFile(int fd, Elf32_Off target_offset, int value);
Elf32_Off searchValueFromFileBetweenOffset(int fd, Elf32_Half value, Elf32_Off begin_offset, Elf32_Off end_offset);
int getSymbolIndexAndModifySymbol(int fd
                                  , char *src_symbol
                                  , char *tar_symbol
                                  , unsigned int SymTblFileOffset
                                  , int SymTblNum
                                  , char SymNamStrTable[]
                                  , unsigned int SymNamStrTblFileOffset);
static unsigned int ELFHash(char *str, unsigned int length);

/* 下面的数据结构定义取自 elf.h 头文件 */

/* The ELF file header. This appears at the start of every ELF file. */

typedef struct
{
    unsigned char e_ident[EI_NIDENT];  /* Magic number and other info */
    Elf32_Half    e_type;              /* Object file type */
    Elf32_Half    e_machine;           /* Architecture */
    Elf32_Word    e_version;           /* Object file version */
    Elf32_Addr    e_entry;             /* Entry point virtual address */
    Elf32_Off     e_phoff;             /* Program header table file offset */
    Elf32_Off     e_shoff;             /* Section header table file offset */
    Elf32_Word    e_flags;             /* Processor-specific flags */
    Elf32_Half    e_ehsize;            /* ELF header size in bytes */
    Elf32_Half    e_phentsize;         /* Program header table entry size */
    Elf32_Half    e_phnum;             /* Program header table entry count */
    Elf32_Half    e_shentsize;         /* Section header table entry size */
    Elf32_Half    e_shnum;             /* Section header table entry count */
    Elf32_Half    e_shstrndx;          /* Section header string table index */
} myElf32_Ehdr;

/* Program segment header. */

typedef struct
{
    Elf32_Word    p_type;              /* Segment type */
    Elf32_Off     p_offset;            /* Segment file offset */
    Elf32_Addr    p_vaddr;             /* Segment virtual address */
    Elf32_Addr    p_paddr;             /* Segment physical address */
    Elf32_Word    p_filesz;            /* Segment size in file */
    Elf32_Word    p_memsz;             /* Segment size in memory */
    Elf32_Word    p_flags;             /* Segment flags */
    Elf32_Word    p_align;             /* Segment alignment */
} myElf32_Phdr;

/* Section header. */

typedef struct
{
    Elf32_Word    sh_name;             /* Section name (string tbl index) */
    Elf32_Word    sh_type;             /* Section type */
    Elf32_Word    sh_flags;            /* Section flags */
    Elf32_Addr    sh_addr;             /* Section virtual addr at execution */
    Elf32_Off     sh_offset;           /* Section file offset */
    Elf32_Word    sh_size;             /* Section size in bytes */
    Elf32_Word    sh_link;             /* Link to another section */
    Elf32_Word    sh_info;             /* Additional section information */
    Elf32_Word    sh_addralign;        /* Section alignment */
    Elf32_Word    sh_entsize;          /* Entry size if section holds table */
} myElf32_Shdr;

/* Symbol table entry. */

typedef struct
{
    Elf32_Word    st_name;             /* Symbol name (string tbl index) */
    Elf32_Addr    st_value;            /* Symbol value */
    Elf32_Word    st_size;             /* Symbol size */
    unsigned char st_info;             /* Symbol type and binding */
    unsigned char st_other;            /* No defined meaning, 0 */
    Elf32_Section st_shndx;            /* Section index */
} myElf32_Sym;

/* The syminfo section if available contains additional information about
 every dynamic symbol. */

typedef struct
{
    Elf32_Half si_boundto;             /* Direct bindings, symbol bound to */
    Elf32_Half si_flags;               /* Per symbol flags */
} myElf32_Syminfo;


/* Main routine */

int main(int argc, char *argv[])
{
    myElf32_Ehdr *e_hdr_ptr;
    //myElf32_Phdr *p_hdr_ptr; // 未使用
    myElf32_Shdr *s_hdr_ptr;
    
    myElf32_Sym  *symptr;
    myElf32_Syminfo *HashSymPtr;
    
    int fd, i;
    unsigned char buf[256];
    
    unsigned int ProHdrFileOffset;
    unsigned int SecHdrFileOffset;
    unsigned int NamStrSecTblIndex;
    unsigned int ProHdrTblEntrNum;
    unsigned int SecHdrTblEntrNum;
    unsigned int ProHdrTblEntrSize;
    unsigned int SecHdrTblEntrSize;
    
    unsigned int SecNamStrTblFileOffset = 0;
    char SecNameStrTable[1024];
    unsigned int SecNameIndex = 0;
    
    unsigned char SymTblEntry[16];
    
    unsigned int DebugInfoFileOffset = 0;
    int DebugInfoSymTblNum = 0;
    unsigned int DebugInfoStrTblFileOffset = 0;
    char DebugInfoStrTable[163840];
    unsigned int DebugInfoStrTblSize = 0;
    
    unsigned int SymTblFileOffset = 0;
    int SymTblNum = 0;
    unsigned int SymNamStrTblFileOffset = 0;
    char SymNamStrTable[163840];
    unsigned int SymNamStrTblSize = 0;
    
    unsigned int HashOffset = 0;
    int HashTblNum = 0;
    
    unsigned char src_sym[16], dst_sym[16];
    unsigned char tmp_sym_addr[4];
    unsigned char tmp_sym_size[4];
    unsigned int src_sym_tbl = 0, dst_sym_tbl = 0;
    
    // hash info
    Elf32_Half nbucket = 0;
    Elf32_Half nchain = 0;
    Elf32_Word hash_size = 0;
    Elf32_Off bucket_off = 0;
    Elf32_Word chain_off = 0;
    
    /* 参数检查 */
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <object_file> <dst_sym> <src_sym>\n", argv[0]);
        exit(1);
    }
    
    /* 打开文件 */
    if ( (fd = open(argv[1], O_RDWR)) == -1 ) {
        fprintf(stderr, "Can't open file \"%s\".\n", argv[1]);
        exit(1);
    }
    
    /* 读取 ELF 文件头 */
    if ( read(fd, buf, 52) != 52 ) {
        fprintf(stderr, "read error\n");
        close(fd); exit(1);
    }
    
    e_hdr_ptr = (myElf32_Ehdr *)buf;
    
    /* 记下程序头表在文件中的偏移、节头表在文件中的偏移、
     节名表所在的节的索引序号、程序头表表项字节长度、程序头表表项数目、
     节头表表项字节长度、节头表表项数目。*/
    ProHdrFileOffset  = (unsigned int)e_hdr_ptr->e_phoff;
    SecHdrFileOffset  = (unsigned int)e_hdr_ptr->e_shoff;
    NamStrSecTblIndex = (unsigned int)e_hdr_ptr->e_shstrndx;
    ProHdrTblEntrNum  = (unsigned int)e_hdr_ptr->e_phnum;
    SecHdrTblEntrNum  = (unsigned int)e_hdr_ptr->e_shnum;
    ProHdrTblEntrSize = (unsigned int)e_hdr_ptr->e_phentsize;
    SecHdrTblEntrSize = (unsigned int)e_hdr_ptr->e_shentsize;
    
    /* 定出节名表所在的节在节头表中对应的表项的文件偏移。*/
    SecNamStrTblFileOffset = SecHdrFileOffset + NamStrSecTblIndex * 40;
    
    if ( lseek(fd, (off_t)SecNamStrTblFileOffset, SEEK_SET) !=
        SecNamStrTblFileOffset || SecNamStrTblFileOffset == 0 ) {
        fprintf(stderr,
                "lseek to Section Table Entry for Section Name String Table error.\n");
        close(fd); exit(1);
    }
    if ( read(fd, buf, (size_t)SecHdrTblEntrSize) != (ssize_t)SecHdrTblEntrSize ) {
        fprintf(stderr, "read error\n");
        close(fd); exit(1);
    }
    
    s_hdr_ptr = (myElf32_Shdr *)buf;
    SecNamStrTblFileOffset = (unsigned int)s_hdr_ptr->sh_offset;
    
    /* 读取节名表，并缓存在一个缓冲区中。*/
    if ( lseek(fd, (off_t)SecNamStrTblFileOffset, SEEK_SET) !=
        SecNamStrTblFileOffset || SecNamStrTblFileOffset == 0 ) {
        fprintf(stderr, "lseek to Section Name String Table error.\n");
        close(fd); exit(1);
    }
    if ( read(fd, SecNameStrTable, (size_t)s_hdr_ptr->sh_size) !=
        (ssize_t)s_hdr_ptr->sh_size ) {
        fprintf(stderr, "read error\n");
        close(fd); exit(1);
    }
    
    if ( lseek(fd, (off_t)SecHdrFileOffset, SEEK_SET) != SecHdrFileOffset ||
        SecHdrFileOffset == 0 ) {
        fprintf(stderr, "lseek to section header error.\n");
        close(fd); exit(1);
    }
    
    /* 记录符号表（即.dynsym节）在文件中的偏移，由它的字节长度和每个表项的
     长度算出符号表的表项数目。同时记下.dynstr节在文件中的偏移和字节长度。*/
    for (i = 0; i < (int)SecHdrTblEntrNum; i++) {
        if ( read(fd, buf, (size_t)SecHdrTblEntrSize) !=
            (ssize_t)SecHdrTblEntrSize ) {
            fprintf(stderr, "read error\n");
            close(fd); exit(1);
        }
        s_hdr_ptr = (myElf32_Shdr *)buf;
        /*if ( s_hdr_ptr->sh_type == 0x3 && s_hdr_ptr->sh_name == 0x11 ) {
         SecNamStrTblFileOffset = (unsigned int)s_hdr_ptr->sh_offset;
         }*/
        if ( strcmp(SecNameStrTable + s_hdr_ptr->sh_name, ".symtab") == 0 ) {
            DebugInfoFileOffset = (unsigned int)s_hdr_ptr->sh_offset;
            DebugInfoSymTblNum = (int)((s_hdr_ptr->sh_size)/(s_hdr_ptr->sh_entsize));
        }
        if ( strcmp(SecNameStrTable + s_hdr_ptr->sh_name, ".strtab") == 0 ) {
            DebugInfoStrTblFileOffset = (unsigned int)s_hdr_ptr->sh_offset;
            DebugInfoStrTblSize = (unsigned int)s_hdr_ptr->sh_size;
        }
        if ( strcmp(SecNameStrTable + s_hdr_ptr->sh_name, ".dynsym") == 0 ) {
            SymTblFileOffset = (unsigned int)s_hdr_ptr->sh_offset;
            SymTblNum = (int)((s_hdr_ptr->sh_size)/(s_hdr_ptr->sh_entsize));
        }
        if ( strcmp(SecNameStrTable + s_hdr_ptr->sh_name, ".dynstr") == 0 ) {
            SymNamStrTblFileOffset = (unsigned int)s_hdr_ptr->sh_offset;
            SymNamStrTblSize = (unsigned int)s_hdr_ptr->sh_size;
        }
        if ( strcmp(SecNameStrTable + s_hdr_ptr->sh_name, ".hash") == 0 ) {
            HashOffset = (unsigned int)s_hdr_ptr->sh_offset;
            HashTblNum = (int)((s_hdr_ptr->sh_size)/(s_hdr_ptr->sh_entsize));
        }
    }
    
    if ( lseek(fd, (off_t)SecHdrFileOffset, SEEK_SET) != SecHdrFileOffset ) {
        fprintf(stderr, "lseek to section header error.\n");
        close(fd); exit(1);
    }
    
    for (i = 0; i < (int)SecHdrTblEntrNum; i++) {
        if ( read(fd, buf, (size_t)SecHdrTblEntrSize) !=
            (ssize_t)SecHdrTblEntrSize ) {
            fprintf(stderr, "read error\n");
            close(fd); exit(1);
        }
        s_hdr_ptr = (myElf32_Shdr *)buf;
        fprintf(stdout, "Section %d:\n", i);
        SecNameIndex = (unsigned int)s_hdr_ptr->sh_name;
        
        fprintf(stdout, "(Section name (string tbl index))sh_name: 0x%08X -> %s\n",
                s_hdr_ptr->sh_name, SecNameStrTable + SecNameIndex);
        fprintf(stdout, "(Section type)sh_type: 0x%08X\n",
                s_hdr_ptr->sh_type);
        fprintf(stdout, "(Section flags)sh_flags: 0x%08X\n",
                s_hdr_ptr->sh_flags);
        fprintf(stdout, "(Section virtual addr at execution)sh_addr: 0x%08X\n",
                s_hdr_ptr->sh_addr);
        fprintf(stdout, "(Section file offset)sh_offset: 0x%08X\n",
                s_hdr_ptr->sh_offset);
        fprintf(stdout, "(Section size in bytes)sh_size: 0x%08X\n",
                s_hdr_ptr->sh_size);
        fprintf(stdout, "(Link to another section)sh_link: 0x%08X\n",
                s_hdr_ptr->sh_link);
        fprintf(stdout, "(Additional section information)sh_info: 0x%08X\n",
                s_hdr_ptr->sh_info);
        fprintf(stdout, "(Section alignment)sh_addralign: 0x%08X\n",
                s_hdr_ptr->sh_addralign);
        fprintf(stdout, "(Entry size if section holds table)sh_entsize: 0x%08X\n",
                s_hdr_ptr->sh_entsize);
    }
    
    fprintf(stdout,
            "************************************************************************\n");
    /* 读取 .dynstr 节的内容，并缓存在一个缓冲区中。*/
    if ( lseek(fd, (off_t)SymNamStrTblFileOffset, SEEK_SET) !=
        SymNamStrTblFileOffset || SymNamStrTblFileOffset == 0 ) {
        fprintf(stderr, "lseek to Dynamical symbol name string error.\n");
        close(fd); exit(1);
    }
    read(fd, SymNamStrTable, (size_t)(SymNamStrTblSize + 1));
    if ( lseek(fd, (off_t)SymTblFileOffset, SEEK_SET) != SymTblFileOffset ||
        SymTblFileOffset == 0 ) {
        fprintf(stderr, "lseek to Dynamical symbol Table error.\n");
        close(fd); exit(1);
    }
    for (i = 0; i < SymTblNum; i++) {
        read(fd, SymTblEntry, (size_t)16);
        symptr = (myElf32_Sym *)SymTblEntry;
        fprintf(stdout, "Symbol ID: %d\n", i);
        fprintf(stdout, "symptr->st_name:%i\n",
                symptr->st_name);
        fprintf(stdout, "Symbol_index_and_name: 0x%08X -> %s\n",
                symptr->st_name, SymNamStrTable + symptr->st_name);
        fprintf(stdout, "Symbol_value: 0x%08X\n", symptr->st_value);
        fprintf(stdout, "Symbol_size: 0x%08X\n", symptr->st_size);
        fprintf(stdout, "Symbol_type_and_binding: 0x%02X\n", symptr->st_info);
        fprintf(stdout, "Section_index: 0x%04X\n", symptr->st_shndx);
        fprintf(stdout,
                "--------------------------------------------------------\n");
    }
    
    fprintf(stdout,
            "************************************************************************\n");
    
    if ( lseek(fd, (off_t)HashOffset, SEEK_SET) != HashOffset ||
        HashOffset == 0 ) {
        fprintf(stderr, "lseek to hash table error.\n");
        close(fd); exit(-1);
    }
    for (i = 0; i < HashTblNum; i++) {
        
        
        fprintf(stdout, "Hash Table ID: %d\n", i);
        read(fd, SymTblEntry, (size_t)4);
        HashSymPtr = (myElf32_Syminfo *)SymTblEntry;
        fprintf(stdout, "Direct_bindings, symbol_bound_to: 0x%04X\n",
                HashSymPtr->si_boundto);
        fprintf(stdout, "Per_symbol_flags: 0x%04X\n", HashSymPtr->si_flags);
        fprintf(stdout,
                "--------------------------------------------------------\n");
        
        //记录nbucket & nchain
        if(i==0){
            nbucket = HashSymPtr->si_boundto;
        }else if(i==1){
            nchain = HashSymPtr->si_boundto;
        }
    }
    
    hash_size = HashTblNum * 4;
    bucket_off = HashOffset + 2*4;
    chain_off = bucket_off + nbucket*4;
    
    fprintf(stdout, "\nhash offset:0x%04X, hash size:0x%04X\n",
            HashOffset, hash_size);
    fprintf(stdout, "nbucket:%i, nchain:%i\n",
            nbucket, nchain);
    fprintf(stdout, "bucket offset:0x%04X, chain offset:0x%04X\n",
            bucket_off, chain_off);
    
    
    // 检索符号表搜索要修改的符号。
    char *src_symbol = argv[2];
    char *tar_symbol = argv[3];
    
    // 基本输入验证
    if (strcmp(src_symbol, tar_symbol)==0) {
        fprintf(stdout, "The symbols are same! Nothing change!\n");
        exit(-1);
    }
    
    if (strlen(src_symbol) != strlen(tar_symbol)) {
        fprintf(stdout, "The symbols must be the same length!\n");
        exit(-1);
    }
    
    // 获取符号的index，并修改符号对应的字符串
    int symbol_id = getSymbolIndexAndModifySymbol(fd
                                      , src_symbol
                                      , tar_symbol
                                      , SymTblFileOffset
                                      , SymTblNum
                                      , SymNamStrTable
                                      , SymNamStrTblFileOffset);
    if(symbol_id!=-1){
        fprintf(stdout, "symbol_id:%04X\n",symbol_id);
    }
    else{
        fprintf(stdout, "symbol not found!\n");
        close(fd); exit(-1);
    }
    
    // 计算目标字符串的hash
    int hash = ELFHash(argv[3],nbucket);
    fprintf(stdout, "target str hash:%i\n", hash);
    
    // 计算addr_1
    Elf32_Addr addr_1 = bucket_off + hash * 4;
    fprintf(stdout, "addr_1:%04X\n",addr_1);
    
    // 获取addr_1的值
    Elf32_Half addr_1_value = readValueFromFile(fd, addr_1);
    fprintf(stdout, "0x%04X value: 0x%04X\n",addr_1, addr_1_value);
    
    // 如果目标字符串计算出来的hash与addr_1_value相同，则不作修改
    if(addr_1_value == symbol_id){
        fprintf(stdout, "The hash of symbols are same! Nothing change!\n");
        exit(0);
    }
    
    // 将INDEX写入addr_1
    writeValueToFile(fd,addr_1,symbol_id);
    fprintf(stdout, "0x%04X value change to: 0x%04X\n",addr_1, readValueFromFile(fd, addr_1));
    
    // 根据INDEX计算addr_2
    Elf32_Addr addr_2 = chain_off + symbol_id * 4;
    fprintf(stdout, "addr_2:%04X\n",addr_2);
    
    // 获取addr_2的值
    Elf32_Half addr_2_value = readValueFromFile(fd, addr_2);
    fprintf(stdout, "0x%04X value: 0x%04X\n",addr_2, addr_2_value);
    
 
    // 将addr_1_value写入addr_2
    writeValueToFile(fd,addr_2,addr_1_value);
    fprintf(stdout, "0x%04X value change to: 0x%04X\n",addr_2, readValueFromFile(fd, addr_2));
    
    // 在hash中查找INDEX
    Elf32_Off result_offset = searchValueFromFileBetweenOffset(fd, symbol_id, bucket_off, HashOffset+hash_size);
    int search_flag = 0;
    if(result_offset!=0x0000){
        // 若找到的是我们修改的地址，则继续查找
        if(result_offset == addr_1){
            result_offset += 0x4;
            result_offset = searchValueFromFileBetweenOffset(fd, symbol_id, result_offset, HashOffset+hash_size);
            if(result_offset!=0x0000){
                search_flag = 1;
                fprintf(stdout, "value found in hash, offset:0x%04X\n",result_offset);
            }
            else{
                search_flag = 0;
                fprintf(stdout, "value not found!\n");
            }
        }
        else{
            search_flag = 1;
            fprintf(stdout, "value found in hash, offset:0x%04X\n",result_offset);
        }
    }
    else{
        search_flag = 0;
        fprintf(stdout, "value not found!\n");
    }
    
    // 若在hash找到相关地址，则写入addr_2_value
    if (search_flag == 1) {
        // 将addr_2_value写入result_offset
        writeValueToFile(fd,result_offset,addr_2_value);
        fprintf(stdout, "0x%04X value change to: 0x%04X\n",result_offset, readValueFromFile(fd, result_offset));
    }

    
    /*
    // 搜索hash测试：
    Elf32_Off result_offset = searchValueFromFileBetweenOffset(fd, 0x100, bucket_off, HashOffset+hash_size);
    if(result_offset!=0x0000){
        fprintf(stdout, "value found! offset:0x%04X\n",
                result_offset);
    }
    else{
        fprintf(stdout, "value not found!\n");
    }
    */

    /*
    // 读取和写入hash测试：
    Elf32_Off target_offset = 0xC1DC;
    

    Elf32_Half target_value = readValueFromFile(fd, target_offset);
    fprintf(stdout, "0x%04X value: 0x%04X\n",target_offset, target_value);
    
    writeValueToFile(fd,target_offset,0xEA);
    
    target_value = readValueFromFile(fd, target_offset);
    fprintf(stdout, "0x%04X value: 0x%04X\n",target_offset, target_value);
    */
    
    
    close(fd);
    return 0;
}

Elf32_Half readValueFromFile(int fd,Elf32_Off target_offset){
    if ( lseek(fd, (off_t)target_offset, SEEK_SET) != target_offset ||
        target_offset == 0 ) {
        fprintf(stderr, "lseek to 0x%04X error.\n", target_offset);
        close(fd); exit(-1);
    }
    
    unsigned char SymTblEntry[16];
    read(fd, SymTblEntry, (size_t)4);
    myElf32_Syminfo *tempSyminfo = (myElf32_Syminfo *)SymTblEntry;
    
    // 输出0x00EA,结果正确
    //fprintf(stdout, "0x%04X value: 0x%04X\n",target_offset,tempSyminfo->si_boundto);
    return tempSyminfo->si_boundto;
}

void writeValueToFile(int fd, Elf32_Off target_offset, int value){
    if ( lseek(fd, (off_t)target_offset, SEEK_SET) != target_offset ||
        target_offset == 0 ) {
        fprintf(stderr, "lseek to 0x%04X error.\n",target_offset);
        close(fd); exit(-1);
    }
    
    // eg:input 00EA, 0:EA, 1:00
    unsigned char MySymTblEntry[4];
    MySymTblEntry[0] = value & 0x00FF;  // 设置高位为0
    MySymTblEntry[1] = value>>2*4;      // 去除低位
    MySymTblEntry[2] = 0x00;
    MySymTblEntry[3] = 0x00;
    
    if ( write(fd, MySymTblEntry, (size_t)4) != (ssize_t)4 ) {
        fprintf(stderr, "write to 0x%04X error\n", target_offset);
        close(fd); exit(-1);
    }
}

Elf32_Off searchValueFromFileBetweenOffset(int fd, Elf32_Half value, Elf32_Off begin_offset, Elf32_Off end_offset){
    Elf32_Off result = 0x0000;
    
    while (begin_offset<end_offset) {
        
        Elf32_Half target_value = readValueFromFile(fd,begin_offset);
        if(value == target_value){
            // 设置result，退出循环
            result = begin_offset;
            break;
        }
        else{
            // 增加begin_offset
            begin_offset += 0x4;
        }
    }
    
    return result;
}

int getSymbolIndexAndModifySymbol(int fd
                                  , char *src_symbol
                                  , char *tar_symbol
                                  , unsigned int SymTblFileOffset
                                  , int SymTblNum
                                  , char SymNamStrTable[]
                                  , unsigned int SymNamStrTblFileOffset){
    
    /* 检索符号表搜索要修改的符号。*/
    int symbol_id = -1;
    
    if ( lseek(fd, (off_t)SymTblFileOffset, SEEK_SET) != SymTblFileOffset ) {
        fprintf(stderr, "lseek error.\n");
        close(fd); exit(-1);
    }
    
    int i=0;
    for (i = 0; i < SymTblNum; i++) {
        
        unsigned char SymTblEntry[16];
        read(fd, SymTblEntry, (size_t)16);
        myElf32_Sym  *symptr = (myElf32_Sym *)SymTblEntry;
        
        if(strcmp(src_symbol, SymNamStrTable + symptr->st_name)==0){
            symbol_id = i;
            fprintf(stdout, "Symbol ID: 0x%04X\n", i);
            fprintf(stdout, "Symbol_index_and_name: 0x%08X -> %s\n",symptr->st_name, SymNamStrTable + symptr->st_name);
            
            // 修改
            Elf32_Off string_offset = SymNamStrTblFileOffset + symptr->st_name;
            fprintf(stdout, "String Offset: 0x%08X \n",string_offset);
            
            
            if ( lseek(fd, (off_t)string_offset, SEEK_SET) != string_offset ) {
                fprintf(stderr, "lseek to string offset error.\n");
                close(fd); exit(-1);
            }
            
            int length = strlen(tar_symbol);
            if (write(fd, tar_symbol, (size_t)length) !=  (ssize_t)length)
            {
                printf("Error writing to the file.\n");
                exit(1);
            }
            
            break;
        }
        
    }
    
    
    return symbol_id;
}

// ELF Hash Function
static unsigned int ELFHash(char *str, unsigned int length){
    unsigned int hash = 0;
    unsigned int x = 0;
    
    while (*str)
    {
        hash = (hash << 4) + (*str++);//hash左移4位，把当前字符ASCII存入hash低四位。
        if ((x = hash & 0xF0000000L) != 0)
        {
            //如果最高的四位不为0，则说明字符多余7个，现在正在存第8个字符，如果不处理，再加下一个字符时，第一个字符会被移出，因此要有如下处理。
            //该处理，如果对于字符串(a-z 或者A-Z)就会仅仅影响5-8位，否则会影响5-31位，因为C语言使用的算数移位
            //因为1-4位刚刚存储了新加入到字符，所以不能>>28
            hash ^= (x >> 24);
            //上面这行代码并不会对X有影响，本身X和hash的高4位相同，下面这行代码&~即对28-31(高4位)位清零。
            hash &= ~x;
        }
    }
    //返回一个符号位为0的数，即丢弃最高位，以免函数外产生影响。(我们可以考虑，如果只有字符，符号位不可能为负)
    return hash % length;
}

/* EOF */
