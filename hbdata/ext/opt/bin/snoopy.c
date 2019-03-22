typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef ushort sa_family_t;

typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef longlong __quad_t;

typedef __quad_t __off64_t;

typedef ulong size_t;

struct _IO_FILE {
    int _flags;
    char * _IO_read_ptr;
    char * _IO_read_end;
    char * _IO_read_base;
    char * _IO_write_base;
    char * _IO_write_ptr;
    char * _IO_write_end;
    char * _IO_buf_base;
    char * _IO_buf_end;
    char * _IO_save_base;
    char * _IO_backup_base;
    char * _IO_save_end;
    struct _IO_marker * _markers;
    struct _IO_FILE * _chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t * _lock;
    __off64_t _offset;
    void * __pad1;
    void * __pad2;
    void * __pad3;
    void * __pad4;
    size_t __pad5;
    int _mode;
    char _unused2[15];
};

struct _IO_marker {
    struct _IO_marker * _next;
    struct _IO_FILE * _sbuf;
    int _pos;
};

typedef struct stat stat, *Pstat;

typedef ulonglong __u_quad_t;

typedef __u_quad_t __dev_t;

typedef ulong __ino_t;

typedef uint __mode_t;

typedef uint __nlink_t;

typedef uint __uid_t;

typedef uint __gid_t;

typedef long __blksize_t;

typedef long __blkcnt_t;

typedef struct timespec timespec, *Ptimespec;

typedef long __time_t;

struct timespec {
    __time_t tv_sec;
    long tv_nsec;
};

struct stat {
    __dev_t st_dev;
    ushort __pad1;
    __ino_t st_ino;
    __mode_t st_mode;
    __nlink_t st_nlink;
    __uid_t st_uid;
    __gid_t st_gid;
    __dev_t st_rdev;
    ushort __pad2;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    ulong __unused4;
    ulong __unused5;
};

typedef void * __gnuc_va_list;

typedef struct tm tm, *Ptm;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long tm_gmtoff;
    char * tm_zone;
};

typedef __time_t time_t;

typedef struct _IO_FILE FILE;

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

typedef uint __socklen_t;

typedef __socklen_t socklen_t;

typedef struct __sigset_t __sigset_t, *P__sigset_t;

typedef struct __sigset_t sigset_t;

struct __sigset_t {
    ulong __val[128];
};

typedef int __ssize_t;

typedef __ssize_t ssize_t;

typedef int __pid_t;

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

struct evp_pkey_ctx_st {
};

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct __pthread_internal_slist __pthread_internal_slist, *P__pthread_internal_slist;

struct __pthread_internal_slist {
    struct __pthread_internal_slist * __next;
};

typedef union pthread_mutex_t pthread_mutex_t, *Ppthread_mutex_t;

typedef struct __pthread_mutex_s __pthread_mutex_s, *P__pthread_mutex_s;

typedef union _union_13 _union_13, *P_union_13;

typedef struct __pthread_internal_slist __pthread_slist_t;

union _union_13 {
    int __spins;
    __pthread_slist_t __list;
};

struct __pthread_mutex_s {
    int __lock;
    uint __count;
    int __owner;
    int __kind;
    uint __nusers;
    union _union_13 field_0x14;
};

union pthread_mutex_t {
    struct __pthread_mutex_s __data;
    char __size[24];
    long __align;
};

typedef union pthread_mutexattr_t pthread_mutexattr_t, *Ppthread_mutexattr_t;

union pthread_mutexattr_t {
    char __size[4];
    int __align;
};

typedef ulong pthread_t;

typedef uint pthread_key_t;

typedef union pthread_attr_t pthread_attr_t, *Ppthread_attr_t;

union pthread_attr_t {
    char __size[36];
    long __align;
};

typedef enum Elf_ProgramHeaderType {
    PT_DYNAMIC=2,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_RELRO=1685382482,
    PT_GNU_STACK=1685382481,
    PT_INTERP=3,
    PT_LOAD=1,
    PT_NOTE=4,
    PT_NULL=0,
    PT_PHDR=6,
    PT_SHLIB=5,
    PT_TLS=7
} Elf_ProgramHeaderType;

typedef struct Elf32_Rela Elf32_Rela, *PElf32_Rela;

struct Elf32_Rela {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
    dword r_addend; // a constant addend used to compute the relocatable field value
};

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

typedef enum Elf_SectionHeaderType {
    SHT_CHECKSUM=1879048184,
    SHT_DYNAMIC=6,
    SHT_DYNSYM=11,
    SHT_FINI_ARRAY=15,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191,
    SHT_GROUP=17,
    SHT_HASH=5,
    SHT_INIT_ARRAY=14,
    SHT_NOBITS=8,
    SHT_NOTE=7,
    SHT_NULL=0,
    SHT_PREINIT_ARRAY=16,
    SHT_PROGBITS=1,
    SHT_REL=9,
    SHT_RELA=4,
    SHT_SHLIB=10,
    SHT_STRTAB=3,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_syminfo=1879048188,
    SHT_SYMTAB=2,
    SHT_SYMTAB_SHNDX=18
} Elf_SectionHeaderType;

struct Elf32_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType sh_type;
    dword sh_flags;
    dword sh_addr;
    dword sh_offset;
    dword sh_size;
    dword sh_link;
    dword sh_info;
    dword sh_addralign;
    dword sh_entsize;
};

typedef struct Elf32_Phdr Elf32_Phdr, *PElf32_Phdr;

struct Elf32_Phdr {
    enum Elf_ProgramHeaderType p_type;
    dword p_offset;
    dword p_vaddr;
    dword p_paddr;
    dword p_filesz;
    dword p_memsz;
    dword p_flags;
    dword p_align;
};

typedef enum Elf32_DynTag {
    DT_AUDIT=1879047932,
    DT_AUXILIARY=2147483645,
    DT_BIND_NOW=24,
    DT_CHECKSUM=1879047672,
    DT_CONFIG=1879047930,
    DT_DEBUG=21,
    DT_DEPAUDIT=1879047931,
    DT_ENCODING=32,
    DT_FEATURE_1=1879047676,
    DT_FILTER=2147483647,
    DT_FINI=13,
    DT_FINI_ARRAY=26,
    DT_FINI_ARRAYSZ=28,
    DT_FLAGS=30,
    DT_FLAGS_1=1879048187,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_HASH=1879047925,
    DT_GNU_LIBLIST=1879047929,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_GNU_PRELINKED=1879047669,
    DT_HASH=4,
    DT_INIT=12,
    DT_INIT_ARRAY=25,
    DT_INIT_ARRAYSZ=27,
    DT_JMPREL=23,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_MOVETAB=1879047934,
    DT_NEEDED=1,
    DT_NULL=0,
    DT_PLTGOT=3,
    DT_PLTPAD=1879047933,
    DT_PLTPADSZ=1879047673,
    DT_PLTREL=20,
    DT_PLTRELSZ=2,
    DT_POSFLAG_1=1879047677,
    DT_PREINIT_ARRAYSZ=33,
    DT_REL=17,
    DT_RELA=7,
    DT_RELACOUNT=1879048185,
    DT_RELAENT=9,
    DT_RELASZ=8,
    DT_RELCOUNT=1879048186,
    DT_RELENT=19,
    DT_RELSZ=18,
    DT_RPATH=15,
    DT_RUNPATH=29,
    DT_SONAME=14,
    DT_STRSZ=10,
    DT_STRTAB=5,
    DT_SYMBOLIC=16,
    DT_SYMENT=11,
    DT_SYMINENT=1879047679,
    DT_SYMINFO=1879047935,
    DT_SYMINSZ=1879047678,
    DT_SYMTAB=6,
    DT_TEXTREL=22,
    DT_TLSDESC_GOT=1879047927,
    DT_TLSDESC_PLT=1879047926,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_VERSYM=1879048176
} Elf32_DynTag;

typedef struct Elf32_Dyn Elf32_Dyn, *PElf32_Dyn;

struct Elf32_Dyn {
    enum Elf32_DynTag d_tag;
    dword d_val;
};

typedef struct Elf32_Sym Elf32_Sym, *PElf32_Sym;

struct Elf32_Sym {
    dword st_name;
    dword st_value;
    dword st_size;
    byte st_info;
    byte st_other;
    word st_shndx;
};

typedef struct Elf32_Ehdr Elf32_Ehdr, *PElf32_Ehdr;

struct Elf32_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_pad[9];
    word e_type;
    word e_machine;
    dword e_version;
    dword e_entry;
    dword e_phoff;
    dword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};




// WARNING: Control flow encountered bad instruction data

int _init(EVP_PKEY_CTX *ctx)

{
  out(0x2f,(char)ctx);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Unable to track spacebase fully for stack

void netmgr_ndtostr(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void * pthread_getspecific(pthread_key_t __key)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  void *pvVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__key - 0x30;
  cVar1 = *(char *)((__key & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__key & 0xffff0000 |
                    (uint)CONCAT11((char)((__key & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pvVar5 = (void *)(*pcVar2)();
  return pvVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

long fpathconf(int __fd,int __name)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  long lVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  lVar5 = (*pcVar2)();
  return lVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int mknod(char *__path,__mode_t __mode,__dev_t __dev)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__path - 0x30;
  cVar1 = *(char *)(((uint)__path & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__path & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__path & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void iofunc_attr_init(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void resmgr_handler(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void thread_pool_create(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  void *pvVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__dest - 0x30;
  cVar1 = *(char *)(((uint)__dest & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__dest & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__dest & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pvVar5 = (void *)(*pcVar2)();
  return pvVar5;
}



// WARNING: Unable to track spacebase fully for stack

void iofunc_ocb_detach(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void resmgr_attach(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void iofunc_mmap(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

ssize_t readlink(char *__path,char *__buf,size_t __len)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  ssize_t sVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__path - 0x30;
  cVar1 = *(char *)(((uint)__path & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__path & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__path & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  sVar5 = (*pcVar2)();
  return sVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void * malloc(size_t __size)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  void *pvVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__size - 0x30;
  cVar1 = *(char *)((__size & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__size & 0xffff0000 |
                    (uint)CONCAT11((char)((__size & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pvVar5 = (void *)(*pcVar2)();
  return pvVar5;
}



// WARNING: Unable to track spacebase fully for stack

void resmgr_msgread(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int vsnprintf(char *__s,size_t __maxlen,char *__format,__gnuc_va_list __arg)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s - 0x30;
  cVar1 = *(char *)(((uint)__s & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int rmdir(char *__path)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__path - 0x30;
  cVar1 = *(char *)(((uint)__path & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__path & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__path & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void readcond(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int setgroups(size_t __n,__gid_t *__groups)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__n - 0x30;
  cVar1 = *(char *)((__n & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__n & 0xffff0000 |
                    (uint)CONCAT11((char)((__n & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void __stackavail(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

__off_t lseek(int __fd,__off_t __offset,int __whence)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  __off_t _Var5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  _Var5 = (*pcVar2)();
  return _Var5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int sigaddset(sigset_t *__set,int __signo)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__set - 0x30;
  cVar1 = *(char *)(((uint)__set & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__set & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__set & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void resmgr_block(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

long strtol(char *__nptr,char **__endptr,int __base)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  long lVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__nptr - 0x30;
  cVar1 = *(char *)(((uint)__nptr & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__nptr & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__nptr & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  lVar5 = (*pcVar2)();
  return lVar5;
}



// WARNING: Unable to track spacebase fully for stack

void MsgSendPulse(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int rename(char *__old,char *__new)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__old - 0x30;
  cVar1 = *(char *)(((uint)__old & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__old & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__old & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

char * strrchr(char *__s,int __c)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  char *pcVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s - 0x30;
  cVar1 = *(char *)(((uint)__s & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pcVar5 = (char *)(*pcVar2)();
  return pcVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void * calloc(size_t __nmemb,size_t __size)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  void *pvVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__nmemb - 0x30;
  cVar1 = *(char *)((__nmemb & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__nmemb & 0xffff0000 |
                    (uint)CONCAT11((char)((__nmemb & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pvVar5 = (void *)(*pcVar2)();
  return pvVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int _connect(int __fd,sockaddr *__addr,socklen_t __len)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

ssize_t write(int __fd,void *__buf,size_t __n)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  ssize_t sVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  sVar5 = (*pcVar2)();
  return sVar5;
}



// WARNING: Unable to track spacebase fully for stack

void thread_pool_destroy(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int fdatasync(int __fildes)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fildes - 0x30;
  cVar1 = *(char *)((__fildes & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fildes & 0xffff0000U |
                    (uint)CONCAT11((char)((__fildes & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int fstat(int __fd,stat *__buf)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int fprintf(FILE *__stream,char *__format,...)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__stream - 0x30;
  cVar1 = *(char *)(((uint)__stream & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__stream & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__stream & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void iofunc_attr_lock(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_key_create(pthread_key_t *__key,void (*__destr_function)(void *))

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__key - 0x30;
  cVar1 = *(char *)(((uint)__key & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__key & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__key & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void __get_errno_ptr(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void devctl(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void iofunc_attr_unlock(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  ssize_t sVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  sVar5 = (*pcVar2)();
  return sVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_attr_setstacksize(pthread_attr_t *__attr,size_t __stacksize)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__attr - 0x30;
  cVar1 = *(char *)(((uint)__attr & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__attr & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__attr & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int unlink(char *__name)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__name - 0x30;
  cVar1 = *(char *)(((uint)__name & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__name & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__name & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void procmgr_daemon(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void * realloc(void *__ptr,size_t __size)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  void *pvVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__ptr - 0x30;
  cVar1 = *(char *)(((uint)__ptr & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__ptr & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__ptr & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pvVar5 = (void *)(*pcVar2)();
  return pvVar5;
}



// WARNING: Unable to track spacebase fully for stack

void resmgr_unblock(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void _writex(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int sigfillset(sigset_t *__set)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__set - 0x30;
  cVar1 = *(char *)(((uint)__set & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__set & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__set & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void iofunc_ocb_attach(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void iofdinfo(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void iofunc_close_dup_default(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

char * strdup(char *__s)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  char *pcVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s - 0x30;
  cVar1 = *(char *)(((uint)__s & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pcVar5 = (char *)(*pcVar2)();
  return pcVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int symlink(char *__from,char *__to)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__from - 0x30;
  cVar1 = *(char *)(((uint)__from & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__from & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__from & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void _init_libc(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

FILE * fopen(char *__filename,char *__modes)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  FILE *pFVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__filename - 0x30;
  cVar1 = *(char *)(((uint)__filename & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__filename & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__filename & 0xffffff00) >> 8) + cVar1,bVar3)) + 2)
  ;
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pFVar5 = (FILE *)(*pcVar2)();
  return pFVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int getopt(int ___argc,char **___argv,char *__shortopts)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)___argc - 0x30;
  cVar1 = *(char *)((___argc & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((___argc & 0xffff0000U |
                    (uint)CONCAT11((char)((___argc & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  void *pvVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s - 0x30;
  cVar1 = *(char *)(((uint)__s & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pvVar5 = (void *)(*pcVar2)();
  return pvVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

time_t time(time_t *__timer)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  time_t tVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__timer - 0x30;
  cVar1 = *(char *)(((uint)__timer & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__timer & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__timer & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  tVar5 = (*pcVar2)();
  return tVar5;
}



// WARNING: Unable to track spacebase fully for stack

void MsgSendv(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int seteuid(__uid_t __uid)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__uid - 0x30;
  cVar1 = *(char *)((__uid & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__uid & 0xffff0000 |
                    (uint)CONCAT11((char)((__uid & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int strcmp(char *__s1,char *__s2)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s1 - 0x30;
  cVar1 = *(char *)(((uint)__s1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s1 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_mutex_unlock(pthread_mutex_t *__mutex)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__mutex - 0x30;
  cVar1 = *(char *)(((uint)__mutex & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__mutex & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__mutex & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int dup(int __fd)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void ConnectServerInfo(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void resmgr_context_free(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int sprintf(char *__s,char *__format,...)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s - 0x30;
  cVar1 = *(char *)(((uint)__s & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int atexit(void (*__func)(int,void *))

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__func - 0x30;
  cVar1 = *(char *)(((uint)__func & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__func & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__func & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void resmgr_detach(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void SignalWaitinfo(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void dispatch_create(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int fsync(int __fd)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void strnicmp(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int fputc(int __c,FILE *__stream)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__c - 0x30;
  cVar1 = *(char *)((__c & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__c & 0xffff0000U |
                    (uint)CONCAT11((char)((__c & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

ssize_t pread(int __fd,void *__buf,size_t __nbytes,__off_t __offset)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  ssize_t sVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  sVar5 = (*pcVar2)();
  return sVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

pthread_t pthread_self(void)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint in_EAX;
  uint *puVar4;
  pthread_t pVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)in_EAX - 0x30;
  cVar1 = *(char *)((in_EAX & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((in_EAX & 0xffff0000 |
                    (uint)CONCAT11((char)((in_EAX & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pVar5 = (*pcVar2)();
  return pVar5;
}



// WARNING: Unable to track spacebase fully for stack

void MsgInfo(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

tm * localtime_r(time_t *__timer,tm *__tp)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  tm *ptVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__timer - 0x30;
  cVar1 = *(char *)(((uint)__timer & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__timer & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__timer & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  ptVar5 = (tm *)(*pcVar2)();
  return ptVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

size_t strftime(char *__s,size_t __maxsize,char *__format,tm *__tp)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  size_t sVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s - 0x30;
  cVar1 = *(char *)(((uint)__s & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  sVar5 = (*pcVar2)();
  return sVar5;
}



// WARNING: Unable to track spacebase fully for stack

void iofunc_power_default(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void resmgr_msgwrite(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void flink(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_mutex_lock(pthread_mutex_t *__mutex)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__mutex - 0x30;
  cVar1 = *(char *)(((uint)__mutex & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__mutex & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__mutex & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void thread_pool_start(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void exit(int __status)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)__status - 0x30;
  cVar1 = *(char *)((__status & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__status & 0xffff0000U |
                    (uint)CONCAT11((char)((__status & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void _readx(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_mutex_init(pthread_mutex_t *__mutex,pthread_mutexattr_t *__mutexattr)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__mutex - 0x30;
  cVar1 = *(char *)(((uint)__mutex & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__mutex & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__mutex & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

size_t strlen(char *__s)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  size_t sVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s - 0x30;
  cVar1 = *(char *)(((uint)__s & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  sVar5 = (*pcVar2)();
  return sVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int open(char *__file,int __oflag,...)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__file - 0x30;
  cVar1 = *(char *)(((uint)__file & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__file & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__file & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void sopenfd(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack

void futime(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

char * strchr(char *__s,int __c)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  char *pcVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s - 0x30;
  cVar1 = *(char *)(((uint)__s & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  pcVar5 = (char *)(*pcVar2)();
  return pcVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int setegid(__gid_t __gid)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__gid - 0x30;
  cVar1 = *(char *)((__gid & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__gid & 0xffff0000 |
                    (uint)CONCAT11((char)((__gid & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_attr_setdetachstate(pthread_attr_t *__attr,int __detachstate)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__attr - 0x30;
  cVar1 = *(char *)(((uint)__attr & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__attr & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__attr & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int fcntl(int __fd,int __cmd,...)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void _resmgr_ocb(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

ssize_t pwrite(int __fd,void *__buf,size_t __n,__off_t __offset)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  ssize_t sVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  sVar5 = (*pcVar2)();
  return sVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int close(int __fd)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__fd - 0x30;
  cVar1 = *(char *)((__fd & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__fd & 0xffff0000U |
                    (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int vfprintf(FILE *__s,char *__format,__gnuc_va_list __arg)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__s - 0x30;
  cVar1 = *(char *)(((uint)__s & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__s & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack

void iofunc_client_info(uint uParm1)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_setspecific(pthread_key_t __key,void *__pointer)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__key - 0x30;
  cVar1 = *(char *)((__key & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__key & 0xffff0000 |
                    (uint)CONCAT11((char)((__key & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void free(void *__ptr)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)__ptr - 0x30;
  cVar1 = *(char *)(((uint)__ptr & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)__ptr & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__ptr & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int sigprocmask(int __how,sigset_t *__set,sigset_t *__oset)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint *puVar4;
  int iVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)__how - 0x30;
  cVar1 = *(char *)((__how & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__how & 0xffff0000U |
                    (uint)CONCAT11((char)((__how & 0xffffff00U) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  iVar5 = (*pcVar2)();
  return iVar5;
}



// WARNING: Control flow encountered bad instruction data

void __stdcall entry(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void main(uint uParm1,int iParm2,undefined4 uParm3)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  code *UNRECOVERED_JUMPTABLE;
  uint unaff_ESI;
  byte *unaff_EDI;
  byte in_CF;
  
  *unaff_EDI = (byte)((uint)uParm3 >> 8);
  bVar2 = (byte)uParm1;
  bVar1 = 9 < ((byte)unaff_ESI & 0xf) || ((bVar2 & 0xf) - in_CF & 0x10) != 0;
  bVar3 = (byte)unaff_ESI + bVar1 * -6;
  bVar3 = bVar3 + (0x9f < bVar3 |
                  (bVar2 < 0xe0 || (byte)(bVar2 + 0x20) < in_CF) | bVar1 * (bVar3 < 6)) * -0x60;
  bVar1 = 9 < (bVar3 & 0xf) || bVar1;
  bVar3 = bVar3 + bVar1 * -6;
                    // WARNING: Could not recover jumptable at 0x08044ece. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)
            (unaff_ESI & 0xffffff00 |
             (uint)(byte)(bVar3 + (0x9f < bVar3 |
                                  *(byte *)(uParm1 & 0xffffff00 |
                                           (uint)(byte)((bVar2 + 0x20) - in_CF)) < *unaff_EDI |
                                  bVar1 * (bVar3 < 6)) * -0x60),&stack0x00000000 + iParm2);
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x080452c0) overlaps instruction at (ram,0x080452bf)
// 

char * __sdivsi3_i4(int param_1,undefined4 param_2,int param_3)

{
  undefined uVar1;
  char cVar2;
  uint *puVar3;
  uint *puVar4;
  char *pcVar5;
  ushort unaff_SI;
  undefined *unaff_EDI;
  
  puVar3 = (uint *)(param_1 + -0x2d455af0);
  if (param_3 != 1 && ((uint)puVar3 | *puVar3) == 0x10000f0) {
    LOCK();
    puVar4 = (uint *)(((uint)puVar3 | *puVar3) + 2);
    pcVar5 = (char *)((uint)puVar4 | *puVar4);
    cVar2 = (char)pcVar5;
    *pcVar5 = *pcVar5 + cVar2;
    *pcVar5 = *pcVar5 + cVar2;
    *pcVar5 = *pcVar5 + cVar2;
    if (param_3 + -2 == 0 || *pcVar5 == 0) {
      return pcVar5 + 0x186049d1;
    }
    uVar1 = in((unaff_SI & (ushort)puVar3 & (ushort)puVar4) * 0x2f);
    *unaff_EDI = uVar1;
    out(0x2f,cVar2);
    if ((char)((byte)(param_3 + -2) & unaff_EDI[-0xf]) < 1) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



int __set_fpscr(int iParm1)

{
  return iParm1 + 0x186049d1;
}



// WARNING: Control flow encountered bad instruction data

void _fini(undefined uParm1)

{
  out(0x2f,uParm1);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


