/*
 * C语言文件: readsymbol.c
 *
 * 描述: 读取并打印so文件内的symbol
 *
 * 用法:
 *          readsymbol <lib***.so>
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
int indexOf(char *str1,char *str2);

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
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <object_file> \n", argv[0]);
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
//        fprintf(stdout, "Section %d:\n", i);
//        SecNameIndex = (unsigned int)s_hdr_ptr->sh_name;
//        
//        fprintf(stdout, "(Section name (string tbl index))sh_name: 0x%08X -> %s\n",
//                s_hdr_ptr->sh_name, SecNameStrTable + SecNameIndex);
//        fprintf(stdout, "(Section type)sh_type: 0x%08X\n",
//                s_hdr_ptr->sh_type);
//        fprintf(stdout, "(Section flags)sh_flags: 0x%08X\n",
//                s_hdr_ptr->sh_flags);
//        fprintf(stdout, "(Section virtual addr at execution)sh_addr: 0x%08X\n",
//                s_hdr_ptr->sh_addr);
//        fprintf(stdout, "(Section file offset)sh_offset: 0x%08X\n",
//                s_hdr_ptr->sh_offset);
//        fprintf(stdout, "(Section size in bytes)sh_size: 0x%08X\n",
//                s_hdr_ptr->sh_size);
//        fprintf(stdout, "(Link to another section)sh_link: 0x%08X\n",
//                s_hdr_ptr->sh_link);
//        fprintf(stdout, "(Additional section information)sh_info: 0x%08X\n",
//                s_hdr_ptr->sh_info);
//        fprintf(stdout, "(Section alignment)sh_addralign: 0x%08X\n",
//                s_hdr_ptr->sh_addralign);
//        fprintf(stdout, "(Entry size if section holds table)sh_entsize: 0x%08X\n",
//                s_hdr_ptr->sh_entsize);
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

        char *symbol_name = SymNamStrTable + symptr->st_name;
        if(indexOf(symbol_name,"Java_com")==0){
            fprintf(stdout, "%s\n", symbol_name);
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
    
    
    close(fd);
    return 0;
}

int indexOf(char *str1,char *str2)
{
    char *p=str1;
    int i=0;
    p=strstr(str1,str2);
    if(p==NULL)
        return -1;
    else{
        while(str1!=p)
        {
            str1++;
            i++;
        }
    }
    return i;
}
/* EOF */
