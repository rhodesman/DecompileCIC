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

typedef struct _IO_FILE FILE;

typedef int __ssize_t;

typedef __ssize_t ssize_t;

typedef int __pid_t;

typedef long __time_t;

typedef long __suseconds_t;

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

struct evp_pkey_ctx_st {
};

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

typedef void * __gnuc_va_list;

typedef struct timeval timeval, *Ptimeval;

struct timeval {
    __time_t tv_sec;
    __suseconds_t tv_usec;
};

typedef long __fd_mask;

typedef struct fd_set fd_set, *Pfd_set;

struct fd_set {
    __fd_mask fds_bits[128];
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

typedef struct Elf32_Rela Elf32_Rela, *PElf32_Rela;

struct Elf32_Rela {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
    dword r_addend; // a constant addend used to compute the relocatable field value
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

typedef ulonglong uintmax_t;




// WARNING: Control flow encountered bad instruction data

int _init(EVP_PKEY_CTX *ctx)

{
  out(0x2f,(char)ctx);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

char * strcpy(char *__dest,char *__src)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  code *pcVar4;
  byte bVar5;
  char cVar6;
  uint uVar7;
  uint *puVar8;
  uint uVar9;
  char *pcVar10;
  uint *unaff_EBX;
  undefined4 *puVar11;
  undefined4 *puVar12;
  undefined4 *unaff_EBP;
  undefined auStack4351 [32];
  undefined auStack4319 [1076];
  undefined auStack3243 [32];
  undefined auStack3211 [1037];
  undefined auStack2174 [32];
  undefined auStack2142 [1037];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar5 = (char)__dest - 0x30;
  uVar7 = (uint)__dest & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__dest & 0xffffff00) >> 8) +
                         *(char *)(((uint)__dest & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar11 = (undefined4 *)(puVar3 + (uVar1 - 4));
  puVar11 = (undefined4 *)(puVar3 + (uVar1 - 4));
  *(undefined4 **)(puVar3 + (uVar1 - 4)) = unaff_EBP;
  cVar6 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *unaff_EBP;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x24)) = puVar3 + (uVar1 - 4);
  *(byte *)puVar8 = *(byte *)puVar8 << 4;
  bVar5 = (byte)puVar8;
  *(byte *)puVar8 = *(byte *)puVar8 | bVar5;
  *(byte *)puVar8 = *(byte *)puVar8 + bVar5;
  *(byte *)(puVar8 + (int)__src * 2) = *(byte *)(puVar8 + (int)__src * 2) + bVar5;
  uVar9 = (uint)puVar8 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)puVar8 >> 8) + *(char *)(uVar7 + 4),bVar5);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar9 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar9 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar11 = (undefined4 *)(puVar2 + (uVar7 - 0x42d));
  puVar12 = (undefined4 *)(puVar2 + (uVar7 - 0x42d));
  *(undefined **)(puVar2 + (uVar7 - 0x42d)) = puVar3 + (uVar1 - 4);
  cVar6 = '\a';
  do {
    puVar11 = puVar11 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar11;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + (uVar7 - 0x44d)) = puVar2 + (uVar7 - 0x42d);
  bVar5 = (char)puVar8 + 8;
  uVar1 = (uint)puVar8 & 0xffffff00;
  pcVar10 = (char *)(uVar1 | (uint)bVar5);
  *pcVar10 = *pcVar10 + bVar5;
  bVar5 = (char)puVar8 - 0x28;
  uVar9 = (uint)puVar8 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)bVar5) + 2),bVar5);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar9 + 4) + (uVar7 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar9 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar11 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  puVar11 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  *(undefined **)(puVar3 + (uVar1 - 0x42d)) = puVar2 + (uVar7 - 0x42d);
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x44d)) = puVar3 + (uVar1 - 0x42d);
  puVar11 = (undefined4 *)(puVar3 + (uVar1 - 0x85a));
  puVar12 = (undefined4 *)(puVar3 + (uVar1 - 0x85a));
  *(undefined **)(puVar3 + (uVar1 - 0x85a)) = puVar3 + (uVar1 - 0x42d);
  cVar6 = '\a';
  do {
    puVar11 = puVar11 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar11;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x87a)) = puVar3 + (uVar1 - 0x85a);
  cVar6 = (char)puVar8;
  *(char *)puVar8 = *(char *)puVar8 - cVar6;
  *(char *)puVar8 = *(char *)puVar8 + cVar6;
  uVar9 = (uint)puVar8 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) +
                         *(char *)(((uint)puVar8 & 0xffffff00 | (uint)(byte)(cVar6 - 0x30U)) + 2),
                         cVar6 - 0x30U);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar9 + 4) + (uVar1 - 0x85a);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar9 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar11 = (undefined4 *)(puVar2 + uVar7 + -0x454);
  *(undefined **)(puVar2 + uVar7 + -0x454) = puVar3 + (uVar1 - 0x85a);
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + uVar7 + -0x474) = puVar2 + uVar7 + -0x454;
  pcVar4 = (code *)swi(3);
  pcVar10 = (char *)(*pcVar4)();
  return pcVar10;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

char * getenv(char *__name)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  code *pcVar4;
  byte bVar5;
  char cVar6;
  uint uVar7;
  uint *puVar8;
  uint uVar9;
  char *pcVar10;
  uint *unaff_EBX;
  undefined4 *puVar11;
  undefined4 *puVar12;
  undefined4 *unaff_EBP;
  undefined auStack2213 [32];
  undefined auStack2181 [1076];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar5 = (char)__name - 0x30;
  uVar7 = (uint)__name & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__name & 0xffffff00) >> 8) +
                         *(char *)(((uint)__name & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar2 = &stack0x00000000 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar11 = (undefined4 *)(puVar2 + (uVar1 - 4));
  puVar11 = (undefined4 *)(puVar2 + (uVar1 - 4));
  *(undefined4 **)(puVar2 + (uVar1 - 4)) = unaff_EBP;
  cVar6 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *unaff_EBP;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + (uVar1 - 0x24)) = puVar2 + (uVar1 - 4);
  puVar11 = (undefined4 *)(puVar2 + (uVar1 - 0x431));
  puVar12 = (undefined4 *)(puVar2 + (uVar1 - 0x431));
  *(undefined **)(puVar2 + (uVar1 - 0x431)) = puVar2 + (uVar1 - 4);
  cVar6 = '\a';
  do {
    puVar11 = puVar11 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar11;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + (uVar1 - 0x451)) = puVar2 + (uVar1 - 0x431);
  cVar6 = (char)puVar8;
  *(char *)puVar8 = *(char *)puVar8 - cVar6;
  *(char *)puVar8 = *(char *)puVar8 + cVar6;
  uVar9 = (uint)puVar8 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) +
                         *(char *)(((uint)puVar8 & 0xffffff00 | (uint)(byte)(cVar6 - 0x30U)) + 2),
                         cVar6 - 0x30U);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar9 + 4) + (uVar1 - 0x431);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar9 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar11 = (undefined4 *)(puVar3 + (uVar7 - 0x454));
  *(undefined **)(puVar3 + (uVar7 - 0x454)) = puVar2 + (uVar1 - 0x431);
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar7 - 0x474)) = puVar3 + (uVar7 - 0x454);
  pcVar4 = (code *)swi(3);
  pcVar10 = (char *)(*pcVar4)();
  return pcVar10;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  uint uVar1;
  undefined *puVar2;
  char cVar3;
  code *pcVar4;
  byte bVar5;
  uint uVar6;
  uint *puVar7;
  void *pvVar8;
  uint *unaff_EBX;
  undefined4 *puVar9;
  undefined4 *unaff_EBP;
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar5 = (char)__dest - 0x30;
  uVar6 = (uint)__dest & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__dest & 0xffffff00) >> 8) +
                         *(char *)(((uint)__dest & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar2 = &stack0x00000000 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  puVar9 = (undefined4 *)(puVar2 + (uVar1 - 4));
  *(undefined4 **)(puVar2 + (uVar1 - 4)) = unaff_EBP;
  cVar3 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar9 = puVar9 + -1;
    *puVar9 = *unaff_EBP;
    cVar3 = cVar3 + -1;
  } while (0 < cVar3);
  *(undefined **)(puVar2 + (uVar1 - 0x24)) = puVar2 + (uVar1 - 4);
  pcVar4 = (code *)swi(3);
  pvVar8 = (void *)(*pcVar4)();
  return pvVar8;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

void perror(char *__s)

{
  undefined uVar1;
  uint uVar2;
  undefined *puVar3;
  undefined *puVar4;
  int iVar5;
  byte bVar6;
  byte bVar7;
  char cVar8;
  byte *pbVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint *puVar13;
  int in_ECX;
  int extraout_ECX;
  int in_EDX;
  int extraout_EDX;
  uint *unaff_EBX;
  undefined4 *puVar14;
  undefined4 *puVar15;
  undefined *puVar16;
  undefined *puVar17;
  undefined4 *unaff_EBP;
  undefined4 *puVar18;
  undefined4 unaff_ESI;
  undefined *unaff_EDI;
  undefined auStack5381 [4];
  undefined auStack5377 [4];
  undefined auStack5373 [4];
  undefined auStack5369 [4];
  undefined auStack5365 [4];
  undefined auStack5361 [4];
  undefined auStack5357 [4];
  undefined auStack5353 [4];
  undefined auStack5349 [1033];
  undefined auStack4316 [32];
  undefined auStack4284 [4];
  undefined auStack4280 [4];
  undefined auStack4276 [1033];
  undefined auStack3243 [32];
  undefined auStack3211 [1037];
  undefined auStack2174 [32];
  undefined auStack2142 [1037];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar6 = (char)__s - 0x30;
  uVar11 = (uint)__s & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) +
                          *(char *)(((uint)__s & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar2 & 1) != 0);
  puVar4 = &stack0x00000000 + *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar11 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  puVar14 = (undefined4 *)(puVar4 + (uVar2 - 4));
  puVar14 = (undefined4 *)(puVar4 + (uVar2 - 4));
  *(undefined4 **)(puVar4 + (uVar2 - 4)) = unaff_EBP;
  cVar8 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *unaff_EBP;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(undefined **)(puVar4 + (uVar2 - 0x24)) = puVar4 + (uVar2 - 4);
  *(char *)puVar13 = *(char *)puVar13 << 1;
  bVar6 = (char)puVar13 + 8;
  uVar11 = (uint)puVar13 & 0xffffff00;
  pbVar9 = (byte *)(uVar11 | (uint)bVar6);
  *pbVar9 = *pbVar9 ^ bVar6;
  *pbVar9 = *pbVar9 + bVar6;
  bVar6 = (char)puVar13 - 0x28;
  uVar10 = (uint)puVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)bVar6) + 2),bVar6);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar4 + *(int *)(uVar10 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar10 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  puVar14 = (undefined4 *)(puVar3 + (uVar11 - 0x42d));
  puVar15 = (undefined4 *)(puVar3 + (uVar11 - 0x42d));
  *(undefined **)(puVar3 + (uVar11 - 0x42d)) = puVar4 + (uVar2 - 4);
  cVar8 = '\a';
  do {
    puVar14 = puVar14 + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *puVar14;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(undefined **)(puVar3 + (uVar11 - 0x44d)) = puVar3 + (uVar11 - 0x42d);
  bVar6 = (byte)puVar13;
  uVar10 = (uint)CONCAT11(bVar6 / 0x30,bVar6) & 0xffffff00;
  uVar2 = (uint)puVar13 & 0xffff0000 | uVar10;
  bVar7 = (bVar6 & 0x30) + 8;
  _bVar7 = (char *)(uVar2 | (uint)bVar7);
  *_bVar7 = *_bVar7 + bVar7;
  bVar6 = (bVar6 & 0x30) - 0x28;
  uVar10 = (uint)puVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar10 >> 8) + *(char *)((uVar2 | (uint)bVar6) + 2),bVar6);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar2 & 1) != 0);
  puVar4 = puVar3 + *(int *)(uVar10 + 4) + (uVar11 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar10 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  puVar14 = (undefined4 *)(puVar4 + (uVar2 - 0x42d));
  puVar14 = (undefined4 *)(puVar4 + (uVar2 - 0x42d));
  *(undefined **)(puVar4 + (uVar2 - 0x42d)) = puVar3 + (uVar11 - 0x42d);
  cVar8 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *puVar15;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(undefined **)(puVar4 + (uVar2 - 0x44d)) = puVar4 + (uVar2 - 0x42d);
  uVar11 = (uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8);
  _bVar7 = (char *)(uVar11 - 1);
  cVar8 = (char)_bVar7;
  *_bVar7 = *_bVar7 + cVar8;
  _bVar7[in_EDX * 8] = _bVar7[in_EDX * 8] + cVar8;
  uVar10 = (uint)_bVar7 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)_bVar7 >> 8) + *(char *)(uVar11 + 1),cVar8);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar4 + *(int *)(uVar10 + 4) + (uVar2 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar10 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  puVar14 = (undefined4 *)(puVar3 + uVar11 + -0x42d);
  puVar15 = (undefined4 *)(puVar3 + uVar11 + -0x42d);
  *(undefined **)(puVar3 + uVar11 + -0x42d) = puVar4 + (uVar2 - 0x42d);
  cVar8 = '\a';
  do {
    puVar14 = puVar14 + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *puVar14;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(undefined **)(puVar3 + uVar11 + -0x44d) = puVar3 + uVar11 + -0x42d;
  bVar6 = (char)puVar13 + 8;
  _bVar7 = (char *)((uint)puVar13 & 0xffffff00 | (uint)bVar6);
  *(undefined **)(puVar3 + uVar11 + -0x85a) = puVar3 + uVar11 + -0x856;
  *_bVar7 = *_bVar7 + bVar6;
  _bVar7[in_EDX * 8] = _bVar7[in_EDX * 8] + bVar6;
  uVar12 = (uint)puVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + _bVar7[2],bVar6);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar10 = (uint)((uVar2 & 1) != 0);
  puVar4 = puVar3 + *(int *)(uVar12 + 4) + uVar11 + -0x85a;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar12 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  uVar2 = *puVar13;
  puVar14 = (undefined4 *)(puVar4 + uVar10 + -4);
  puVar14 = (undefined4 *)(puVar4 + uVar10 + -4);
  puVar18 = (undefined4 *)(puVar4 + uVar10 + -4);
  *(undefined **)(puVar4 + uVar10 + -4) = puVar3 + uVar11 + -0x42d;
  cVar8 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *puVar15;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(undefined **)(puVar4 + uVar10 + -0x24) = puVar4 + uVar10 + -4;
  puVar16 = puVar4 + uVar10 + -0x42d;
  if (in_ECX + -1 == 0 || uVar2 == 0) {
    bVar6 = (char)puVar13 + 8;
    _bVar7 = (char *)((uint)puVar13 & 0xffffff00 | (uint)bVar6);
    *(char **)(puVar4 + uVar10 + -0x431) = _bVar7;
    *(int *)(puVar4 + uVar10 + -0x435) = in_ECX + -1;
    *(int *)(puVar4 + uVar10 + -0x439) = in_EDX;
    *(uint **)(puVar4 + uVar10 + -0x43d) = unaff_EBX;
    *(undefined **)(puVar4 + uVar10 + -0x441) = puVar4 + uVar10 + -0x42d;
    *(undefined **)(puVar4 + uVar10 + -0x445) = puVar4 + uVar10 + -4;
    *(undefined4 *)(puVar4 + uVar10 + -0x449) = unaff_ESI;
    *(undefined **)(puVar4 + uVar10 + -0x44d) = unaff_EDI;
    *_bVar7 = *_bVar7 + bVar6;
    _bVar7[in_EDX * 8] = _bVar7[in_EDX * 8] + bVar6;
    uVar11 = (uint)puVar13 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + _bVar7[2],bVar6);
    uVar2 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar2 = (uint)((uVar2 & 1) != 0);
    iVar5 = (int)(puVar4 + *(int *)(uVar11 + 4) + uVar10 + -0x44d);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar13 = (uint *)(uVar11 + 2);
    *puVar13 = *puVar13 | (uint)puVar13;
    puVar14 = (undefined4 *)(iVar5 + uVar2 + -4);
    puVar18 = (undefined4 *)(iVar5 + uVar2 + -4);
    *(undefined **)(iVar5 + uVar2 + -4) = puVar4 + uVar10 + -4;
    cVar8 = '\a';
    do {
      puVar14 = puVar14 + -1;
      puVar14 = puVar14 + -1;
      *puVar14 = *puVar14;
      cVar8 = cVar8 + -1;
    } while (0 < cVar8);
    *(uint *)(iVar5 + uVar2 + -0x24) = iVar5 + uVar2 + -4;
    cVar8 = in(0x30);
    bVar6 = cVar8 + 8;
    _bVar7 = (char *)((uint)puVar13 & 0xffffff00 | (uint)bVar6);
    uVar1 = in((short)in_EDX);
    *unaff_EDI = uVar1;
    *_bVar7 = *_bVar7 + bVar6;
    _bVar7[in_EDX * 8] = _bVar7[in_EDX * 8] + bVar6;
    uVar10 = (uint)puVar13 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + _bVar7[2],bVar6);
    uVar11 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = (undefined *)
              (iVar5 + uVar2 + -0x42d + *(int *)(uVar10 + 4) + (uint)((uVar11 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar13 = (uint *)(uVar10 + 2);
  }
  *puVar13 = *puVar13 | (uint)puVar13;
  puVar14 = (undefined4 *)(puVar16 + -4);
  puVar14 = (undefined4 *)(puVar16 + -4);
  *(undefined4 **)(puVar16 + -4) = puVar18;
  cVar8 = '\a';
  do {
    puVar18 = puVar18 + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *puVar18;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(undefined **)(puVar16 + -0x24) = puVar16 + -4;
  puVar17 = puVar16 + -0x431;
  *(undefined4 *)(puVar16 + -0x431) = 0x8040b15;
  _bVar7 = (char *)func_0x800c0f45();
  cVar8 = (char)_bVar7;
  *_bVar7 = *_bVar7 + cVar8;
  _bVar7[extraout_EDX * 8] = _bVar7[extraout_EDX * 8] + cVar8;
  uVar11 = (uint)_bVar7 & 0xffff0000 | (uint)CONCAT11((char)((uint)_bVar7 >> 8) + _bVar7[2],cVar8);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar2 & 1) != 0);
  puVar4 = puVar17 + *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar11 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  puVar14 = (undefined4 *)(puVar4 + (uVar2 - 4));
  puVar15 = (undefined4 *)(puVar4 + (uVar2 - 4));
  *(undefined **)(puVar4 + (uVar2 - 4)) = puVar16 + -4;
  cVar8 = '\a';
  do {
    puVar14 = puVar14 + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *puVar14;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(undefined **)(puVar4 + (uVar2 - 0x24)) = puVar4 + (uVar2 - 4);
  bVar6 = in((short)extraout_EDX);
  uVar11 = (uint)puVar13 & 0xffffff00;
  _bVar7 = (char *)(uVar11 | (uint)bVar6);
  _bVar7[extraout_ECX] = _bVar7[extraout_ECX] ^ bVar6;
  *_bVar7 = *_bVar7 + bVar6;
  uVar10 = (uint)puVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)(byte)(bVar6 - 0x30)) + 2)
                          ,bVar6 - 0x30);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar4 + *(int *)(uVar10 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar10 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  puVar14 = (undefined4 *)(puVar3 + (uVar11 - 0x42d));
  puVar14 = (undefined4 *)(puVar3 + (uVar11 - 0x42d));
  *(undefined **)(puVar3 + (uVar11 - 0x42d)) = puVar4 + (uVar2 - 4);
  cVar8 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *puVar15;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(undefined **)(puVar3 + (uVar11 - 0x44d)) = puVar3 + (uVar11 - 0x42d);
  LOCK();
  bVar6 = (byte)puVar13;
  *(byte *)((int)puVar13 + extraout_ECX) = *(byte *)((int)puVar13 + extraout_ECX) ^ bVar6;
  *(byte *)puVar13 = *(char *)puVar13 + bVar6;
  *(byte *)(puVar13 + extraout_EDX * 2) = *(char *)(puVar13 + extraout_EDX * 2) + bVar6;
  uVar10 = (uint)puVar13 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)puVar13 >> 8) + *(char *)(uVar10 + 4),bVar6);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar2 & 1) != 0);
  puVar4 = puVar3 + *(int *)(uVar10 + 4) + (uVar11 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar10 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  puVar14 = (undefined4 *)(puVar4 + (uVar2 - 0x42d));
  *(undefined **)(puVar4 + (uVar2 - 0x42d)) = puVar3 + (uVar11 - 0x42d);
  cVar8 = '\a';
  do {
    puVar14 = puVar14 + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *puVar14;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(undefined **)(puVar4 + (uVar2 - 0x44d)) = puVar4 + (uVar2 - 0x42d);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

void * malloc(size_t __size)

{
  undefined uVar1;
  undefined *puVar2;
  undefined *puVar3;
  byte bVar4;
  byte bVar5;
  char cVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint *puVar11;
  int in_ECX;
  int extraout_ECX;
  int in_EDX;
  int extraout_EDX;
  uint *unaff_EBX;
  undefined4 *puVar12;
  undefined4 *puVar13;
  undefined *puVar14;
  undefined *puVar15;
  undefined4 *unaff_EBP;
  undefined4 *puVar16;
  undefined4 unaff_ESI;
  undefined *unaff_EDI;
  undefined auStack5381 [1033];
  undefined auStack4348 [32];
  undefined auStack4316 [4];
  undefined auStack4312 [4];
  undefined auStack4308 [4];
  undefined auStack4304 [4];
  undefined auStack4300 [4];
  undefined auStack4296 [4];
  undefined auStack4292 [4];
  undefined auStack4288 [4];
  undefined auStack4284 [4];
  undefined auStack4280 [1033];
  undefined auStack3247 [32];
  undefined auStack3215 [4];
  undefined auStack3211 [4];
  undefined auStack3207 [1033];
  undefined auStack2174 [32];
  undefined auStack2142 [1037];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar4 = (char)__size - 0x30;
  uVar7 = __size & 0xffff0000 |
          (uint)CONCAT11((char)((__size & 0xffffff00) >> 8) +
                         *(char *)((__size & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar7 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar3 + (uVar9 - 4));
  puVar12 = (undefined4 *)(puVar3 + (uVar9 - 4));
  *(undefined4 **)(puVar3 + (uVar9 - 4)) = unaff_EBP;
  cVar6 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *unaff_EBP;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar9 - 0x24)) = puVar3 + (uVar9 - 4);
  bVar4 = (byte)puVar11;
  uVar8 = (uint)CONCAT11(bVar4 / 0x30,bVar4) & 0xffffff00;
  uVar7 = (uint)puVar11 & 0xffff0000 | uVar8;
  bVar5 = (bVar4 & 0x30) + 8;
  _bVar5 = (char *)(uVar7 | (uint)bVar5);
  *_bVar5 = *_bVar5 + bVar5;
  bVar4 = (bVar4 & 0x30) - 0x28;
  uVar8 = (uint)puVar11 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar8 >> 8) + *(char *)((uVar7 | (uint)bVar4) + 2),bVar4);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar8 + 4) + (uVar9 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar8 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar2 + (uVar7 - 0x42d));
  puVar13 = (undefined4 *)(puVar2 + (uVar7 - 0x42d));
  *(undefined **)(puVar2 + (uVar7 - 0x42d)) = puVar3 + (uVar9 - 4);
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + (uVar7 - 0x44d)) = puVar2 + (uVar7 - 0x42d);
  uVar9 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  _bVar5 = (char *)(uVar9 - 1);
  cVar6 = (char)_bVar5;
  *_bVar5 = *_bVar5 + cVar6;
  _bVar5[in_EDX * 8] = _bVar5[in_EDX * 8] + cVar6;
  uVar8 = (uint)_bVar5 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)_bVar5 >> 8) + *(char *)(uVar9 + 1),cVar6);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar8 + 4) + (uVar7 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar8 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar3 + (uVar9 - 0x42d));
  puVar12 = (undefined4 *)(puVar3 + (uVar9 - 0x42d));
  *(undefined **)(puVar3 + (uVar9 - 0x42d)) = puVar2 + (uVar7 - 0x42d);
  cVar6 = '\a';
  do {
    puVar13 = puVar13 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar13;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar9 - 0x44d)) = puVar3 + (uVar9 - 0x42d);
  bVar4 = (char)puVar11 + 8;
  _bVar5 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar4);
  *(undefined **)(puVar3 + (uVar9 - 0x85a)) = puVar3 + (uVar9 - 0x856);
  *_bVar5 = *_bVar5 + bVar4;
  _bVar5[in_EDX * 8] = _bVar5[in_EDX * 8] + bVar4;
  uVar10 = (uint)puVar11 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + _bVar5[2],bVar4);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar8 = (uint)((uVar7 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar10 + 4) + (uVar9 - 0x85a);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  uVar7 = *puVar11;
  puVar12 = (undefined4 *)(puVar2 + uVar8 + -4);
  puVar13 = (undefined4 *)(puVar2 + uVar8 + -4);
  puVar16 = (undefined4 *)(puVar2 + uVar8 + -4);
  *(undefined **)(puVar2 + uVar8 + -4) = puVar3 + (uVar9 - 0x42d);
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + uVar8 + -0x24) = puVar2 + uVar8 + -4;
  puVar14 = puVar2 + uVar8 + -0x42d;
  if (in_ECX + -1 == 0 || uVar7 == 0) {
    bVar4 = (char)puVar11 + 8;
    _bVar5 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar4);
    *(char **)(puVar2 + uVar8 + -0x431) = _bVar5;
    *(int *)(puVar2 + uVar8 + -0x435) = in_ECX + -1;
    *(int *)(puVar2 + uVar8 + -0x439) = in_EDX;
    *(uint **)(puVar2 + uVar8 + -0x43d) = unaff_EBX;
    *(undefined **)(puVar2 + uVar8 + -0x441) = puVar2 + uVar8 + -0x42d;
    *(undefined **)(puVar2 + uVar8 + -0x445) = puVar2 + uVar8 + -4;
    *(undefined4 *)(puVar2 + uVar8 + -0x449) = unaff_ESI;
    *(undefined **)(puVar2 + uVar8 + -0x44d) = unaff_EDI;
    *_bVar5 = *_bVar5 + bVar4;
    _bVar5[in_EDX * 8] = _bVar5[in_EDX * 8] + bVar4;
    uVar7 = (uint)puVar11 & 0xffff0000 |
            (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + _bVar5[2],bVar4);
    uVar9 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar9 = (uint)((uVar9 & 1) != 0);
    puVar3 = puVar2 + *(int *)(uVar7 + 4) + uVar8 + -0x44d;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar7 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    puVar12 = (undefined4 *)(puVar3 + uVar9 + -4);
    puVar16 = (undefined4 *)(puVar3 + uVar9 + -4);
    *(undefined **)(puVar3 + uVar9 + -4) = puVar2 + uVar8 + -4;
    cVar6 = '\a';
    do {
      puVar13 = puVar13 + -1;
      puVar12 = puVar12 + -1;
      *puVar12 = *puVar13;
      cVar6 = cVar6 + -1;
    } while (0 < cVar6);
    *(undefined **)(puVar3 + uVar9 + -0x24) = puVar3 + uVar9 + -4;
    cVar6 = in(0x30);
    bVar4 = cVar6 + 8;
    _bVar5 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar4);
    uVar1 = in((short)in_EDX);
    *unaff_EDI = uVar1;
    *_bVar5 = *_bVar5 + bVar4;
    _bVar5[in_EDX * 8] = _bVar5[in_EDX * 8] + bVar4;
    uVar8 = (uint)puVar11 & 0xffff0000 |
            (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + _bVar5[2],bVar4);
    uVar7 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar14 = puVar3 + (uint)((uVar7 & 1) != 0) + *(int *)(uVar8 + 4) + uVar9 + -0x42d;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar8 + 2);
  }
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar14 + -4);
  puVar12 = (undefined4 *)(puVar14 + -4);
  *(undefined4 **)(puVar14 + -4) = puVar16;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar14 + -0x24) = puVar14 + -4;
  puVar15 = puVar14 + -0x431;
  *(undefined4 *)(puVar14 + -0x431) = 0x8040b15;
  _bVar5 = (char *)func_0x800c0f45();
  cVar6 = (char)_bVar5;
  *_bVar5 = *_bVar5 + cVar6;
  _bVar5[extraout_EDX * 8] = _bVar5[extraout_EDX * 8] + cVar6;
  uVar7 = (uint)_bVar5 & 0xffff0000 | (uint)CONCAT11((char)((uint)_bVar5 >> 8) + _bVar5[2],cVar6);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar3 = puVar15 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar7 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar3 + (uVar9 - 4));
  puVar13 = (undefined4 *)(puVar3 + (uVar9 - 4));
  *(undefined **)(puVar3 + (uVar9 - 4)) = puVar14 + -4;
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar9 - 0x24)) = puVar3 + (uVar9 - 4);
  bVar4 = in((short)extraout_EDX);
  uVar7 = (uint)puVar11 & 0xffffff00;
  _bVar5 = (char *)(uVar7 | (uint)bVar4);
  _bVar5[extraout_ECX] = _bVar5[extraout_ECX] ^ bVar4;
  *_bVar5 = *_bVar5 + bVar4;
  uVar8 = (uint)puVar11 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar7 >> 8) + *(char *)((uVar7 | (uint)(byte)(bVar4 - 0x30)) + 2),
                         bVar4 - 0x30);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar8 + 4) + (uVar9 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar8 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar2 + (uVar7 - 0x42d));
  puVar12 = (undefined4 *)(puVar2 + (uVar7 - 0x42d));
  *(undefined **)(puVar2 + (uVar7 - 0x42d)) = puVar3 + (uVar9 - 4);
  cVar6 = '\a';
  do {
    puVar13 = puVar13 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar13;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + (uVar7 - 0x44d)) = puVar2 + (uVar7 - 0x42d);
  LOCK();
  bVar4 = (byte)puVar11;
  *(byte *)((int)puVar11 + extraout_ECX) = *(byte *)((int)puVar11 + extraout_ECX) ^ bVar4;
  *(byte *)puVar11 = *(char *)puVar11 + bVar4;
  *(byte *)(puVar11 + extraout_EDX * 2) = *(char *)(puVar11 + extraout_EDX * 2) + bVar4;
  uVar8 = (uint)puVar11 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)(uVar8 + 4),bVar4);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar8 + 4) + (uVar7 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar8 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar3 + (uVar9 - 0x42d));
  *(undefined **)(puVar3 + (uVar9 - 0x42d)) = puVar2 + (uVar7 - 0x42d);
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar9 - 0x44d)) = puVar3 + (uVar9 - 0x42d);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

int vsnprintf(char *__s,size_t __maxlen,char *__format,__gnuc_va_list __arg)

{
  undefined uVar1;
  uint uVar2;
  undefined *puVar3;
  undefined *puVar4;
  byte bVar5;
  char cVar6;
  uint uVar7;
  char *pcVar8;
  uint uVar9;
  uint uVar10;
  uint *puVar11;
  int extraout_ECX;
  int extraout_EDX;
  uint *unaff_EBX;
  undefined4 *puVar12;
  undefined4 *puVar13;
  undefined *puVar14;
  undefined *puVar15;
  undefined4 *unaff_EBP;
  undefined4 *puVar16;
  undefined4 unaff_ESI;
  undefined *unaff_EDI;
  undefined auStack4312 [1033];
  undefined auStack3279 [32];
  undefined auStack3247 [4];
  undefined auStack3243 [4];
  undefined auStack3239 [4];
  undefined auStack3235 [4];
  undefined auStack3231 [4];
  undefined auStack3227 [4];
  undefined auStack3223 [4];
  undefined auStack3219 [4];
  undefined auStack3215 [4];
  undefined auStack3211 [1033];
  undefined auStack2178 [32];
  undefined auStack2146 [4];
  undefined auStack2142 [4];
  undefined auStack2138 [1033];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar5 = (char)__s - 0x30;
  uVar7 = (uint)__s & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) +
                         *(char *)(((uint)__s & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar2 & 1) != 0);
  puVar4 = &stack0x00000000 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar7 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar4 + (uVar2 - 4));
  puVar12 = (undefined4 *)(puVar4 + (uVar2 - 4));
  *(undefined4 **)(puVar4 + (uVar2 - 4)) = unaff_EBP;
  cVar6 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *unaff_EBP;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar4 + (uVar2 - 0x24)) = puVar4 + (uVar2 - 4);
  uVar7 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  pcVar8 = (char *)(uVar7 - 1);
  cVar6 = (char)pcVar8;
  *pcVar8 = *pcVar8 + cVar6;
  pcVar8[__maxlen * 8] = pcVar8[__maxlen * 8] + cVar6;
  uVar9 = (uint)pcVar8 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)pcVar8 >> 8) + *(char *)(uVar7 + 1),cVar6);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar3 = puVar4 + *(int *)(uVar9 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar9 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar3 + (uVar7 - 0x42d));
  puVar13 = (undefined4 *)(puVar3 + (uVar7 - 0x42d));
  *(undefined **)(puVar3 + (uVar7 - 0x42d)) = puVar4 + (uVar2 - 4);
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar7 - 0x44d)) = puVar3 + (uVar7 - 0x42d);
  bVar5 = (char)puVar11 + 8;
  pcVar8 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar5);
  *(undefined **)(puVar3 + (uVar7 - 0x85a)) = puVar3 + (uVar7 - 0x856);
  *pcVar8 = *pcVar8 + bVar5;
  pcVar8[__maxlen * 8] = pcVar8[__maxlen * 8] + bVar5;
  uVar10 = (uint)puVar11 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + pcVar8[2],bVar5);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar2 & 1) != 0);
  puVar4 = puVar3 + *(int *)(uVar10 + 4) + (uVar7 - 0x85a);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  uVar2 = *puVar11;
  puVar12 = (undefined4 *)(puVar4 + (uVar9 - 4));
  puVar12 = (undefined4 *)(puVar4 + (uVar9 - 4));
  puVar16 = (undefined4 *)(puVar4 + (uVar9 - 4));
  *(undefined **)(puVar4 + (uVar9 - 4)) = puVar3 + (uVar7 - 0x42d);
  cVar6 = '\a';
  do {
    puVar13 = puVar13 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar13;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar4 + (uVar9 - 0x24)) = puVar4 + (uVar9 - 4);
  puVar14 = puVar4 + (uVar9 - 0x42d);
  if (__format + -1 == (char *)0x0 || uVar2 == 0) {
    bVar5 = (char)puVar11 + 8;
    pcVar8 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar5);
    *(char **)(puVar4 + (uVar9 - 0x431)) = pcVar8;
    *(char **)(puVar4 + (uVar9 - 0x435)) = __format + -1;
    *(size_t *)(puVar4 + (uVar9 - 0x439)) = __maxlen;
    *(uint **)(puVar4 + (uVar9 - 0x43d)) = unaff_EBX;
    *(undefined **)(puVar4 + (uVar9 - 0x441)) = puVar4 + (uVar9 - 0x42d);
    *(undefined **)(puVar4 + (uVar9 - 0x445)) = puVar4 + (uVar9 - 4);
    *(undefined4 *)(puVar4 + (uVar9 - 0x449)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar9 - 0x44d)) = unaff_EDI;
    *pcVar8 = *pcVar8 + bVar5;
    pcVar8[__maxlen * 8] = pcVar8[__maxlen * 8] + bVar5;
    uVar7 = (uint)puVar11 & 0xffff0000 |
            (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + pcVar8[2],bVar5);
    uVar2 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar2 = (uint)((uVar2 & 1) != 0);
    puVar3 = puVar4 + *(int *)(uVar7 + 4) + (uVar9 - 0x44d);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar7 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    puVar12 = (undefined4 *)(puVar3 + uVar2 + -4);
    puVar16 = (undefined4 *)(puVar3 + uVar2 + -4);
    *(undefined **)(puVar3 + uVar2 + -4) = puVar4 + (uVar9 - 4);
    cVar6 = '\a';
    do {
      puVar12 = puVar12 + -1;
      puVar12 = puVar12 + -1;
      *puVar12 = *puVar12;
      cVar6 = cVar6 + -1;
    } while (0 < cVar6);
    *(undefined **)(puVar3 + uVar2 + -0x24) = puVar3 + uVar2 + -4;
    cVar6 = in(0x30);
    bVar5 = cVar6 + 8;
    pcVar8 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar5);
    uVar1 = in((short)__maxlen);
    *unaff_EDI = uVar1;
    *pcVar8 = *pcVar8 + bVar5;
    pcVar8[__maxlen * 8] = pcVar8[__maxlen * 8] + bVar5;
    uVar9 = (uint)puVar11 & 0xffff0000 |
            (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + pcVar8[2],bVar5);
    uVar7 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar14 = puVar3 + (uint)((uVar7 & 1) != 0) + *(int *)(uVar9 + 4) + uVar2 + -0x42d;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar9 + 2);
  }
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar14 + -4);
  puVar12 = (undefined4 *)(puVar14 + -4);
  *(undefined4 **)(puVar14 + -4) = puVar16;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar14 + -0x24) = puVar14 + -4;
  puVar15 = puVar14 + -0x431;
  *(undefined4 *)(puVar14 + -0x431) = 0x8040b15;
  pcVar8 = (char *)func_0x800c0f45();
  cVar6 = (char)pcVar8;
  *pcVar8 = *pcVar8 + cVar6;
  pcVar8[extraout_EDX * 8] = pcVar8[extraout_EDX * 8] + cVar6;
  uVar7 = (uint)pcVar8 & 0xffff0000 | (uint)CONCAT11((char)((uint)pcVar8 >> 8) + pcVar8[2],cVar6);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar2 & 1) != 0);
  puVar4 = puVar15 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar7 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar4 + (uVar2 - 4));
  puVar13 = (undefined4 *)(puVar4 + (uVar2 - 4));
  *(undefined **)(puVar4 + (uVar2 - 4)) = puVar14 + -4;
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar4 + (uVar2 - 0x24)) = puVar4 + (uVar2 - 4);
  bVar5 = in((short)extraout_EDX);
  uVar7 = (uint)puVar11 & 0xffffff00;
  pcVar8 = (char *)(uVar7 | (uint)bVar5);
  pcVar8[extraout_ECX] = pcVar8[extraout_ECX] ^ bVar5;
  *pcVar8 = *pcVar8 + bVar5;
  uVar9 = (uint)puVar11 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar7 >> 8) + *(char *)((uVar7 | (uint)(byte)(bVar5 - 0x30)) + 2),
                         bVar5 - 0x30);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar3 = puVar4 + *(int *)(uVar9 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar9 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar3 + (uVar7 - 0x42d));
  puVar12 = (undefined4 *)(puVar3 + (uVar7 - 0x42d));
  *(undefined **)(puVar3 + (uVar7 - 0x42d)) = puVar4 + (uVar2 - 4);
  cVar6 = '\a';
  do {
    puVar13 = puVar13 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar13;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar7 - 0x44d)) = puVar3 + (uVar7 - 0x42d);
  LOCK();
  bVar5 = (byte)puVar11;
  *(byte *)((int)puVar11 + extraout_ECX) = *(byte *)((int)puVar11 + extraout_ECX) ^ bVar5;
  *(byte *)puVar11 = *(char *)puVar11 + bVar5;
  *(byte *)(puVar11 + extraout_EDX * 2) = *(char *)(puVar11 + extraout_EDX * 2) + bVar5;
  uVar9 = (uint)puVar11 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)(uVar9 + 4),bVar5);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar2 & 1) != 0);
  puVar4 = puVar3 + *(int *)(uVar9 + 4) + (uVar7 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar9 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  puVar12 = (undefined4 *)(puVar4 + (uVar2 - 0x42d));
  *(undefined **)(puVar4 + (uVar2 - 0x42d)) = puVar3 + (uVar7 - 0x42d);
  cVar6 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar12 = puVar12 + -1;
    *puVar12 = *puVar12;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar4 + (uVar2 - 0x44d)) = puVar4 + (uVar2 - 0x42d);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int fprintf(FILE *__stream,char *__format,...)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  char cVar4;
  byte bVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  int in_ECX;
  uint *unaff_EBX;
  undefined4 *puVar9;
  undefined4 *unaff_EBP;
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar5 = (char)__stream - 0x30;
  uVar6 = (uint)__stream & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__stream & 0xffffff00) >> 8) +
                         *(char *)(((uint)__stream & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar2 = &stack0x00000000 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  puVar9 = (undefined4 *)(puVar2 + (uVar1 - 4));
  puVar9 = (undefined4 *)(puVar2 + (uVar1 - 4));
  *(undefined4 **)(puVar2 + (uVar1 - 4)) = unaff_EBP;
  cVar4 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar9 = puVar9 + -1;
    *puVar9 = *unaff_EBP;
    cVar4 = cVar4 + -1;
  } while (0 < cVar4);
  *(undefined **)(puVar2 + (uVar1 - 0x24)) = puVar2 + (uVar1 - 4);
  LOCK();
  bVar5 = (byte)puVar7;
  *(byte *)((int)puVar7 + in_ECX) = *(byte *)((int)puVar7 + in_ECX) ^ bVar5;
  *(byte *)puVar7 = *(char *)puVar7 + bVar5;
  *(byte *)(puVar7 + (int)__format * 2) = *(char *)(puVar7 + (int)__format * 2) + bVar5;
  uVar8 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)puVar7 >> 8) + *(char *)(uVar6 + 4),bVar5);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar6 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar8 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar8 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  puVar9 = (undefined4 *)(puVar3 + (uVar6 - 0x42d));
  *(undefined **)(puVar3 + (uVar6 - 0x42d)) = puVar2 + (uVar1 - 4);
  cVar4 = '\a';
  do {
    puVar9 = puVar9 + -1;
    puVar9 = puVar9 + -1;
    *puVar9 = *puVar9;
    cVar4 = cVar4 + -1;
  } while (0 < cVar4);
  *(undefined **)(puVar3 + (uVar6 - 0x44d)) = puVar3 + (uVar6 - 0x42d);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

char * strncat(char *__dest,char *__src,size_t __n)

{
  uint uVar1;
  undefined *puVar2;
  char cVar3;
  code *pcVar4;
  byte bVar5;
  uint uVar6;
  uint *puVar7;
  char *pcVar8;
  uint uVar9;
  undefined *puVar10;
  uint *unaff_EBX;
  undefined4 *puVar11;
  undefined4 *puVar12;
  undefined4 *unaff_EBP;
  undefined auStack2174 [32];
  undefined auStack2142 [1037];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar5 = (char)__dest - 0x30;
  uVar6 = (uint)__dest & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__dest & 0xffffff00) >> 8) +
                         *(char *)(((uint)__dest & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar10 = &stack0x00000000 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  puVar11 = (undefined4 *)(puVar10 + (uVar1 - 4));
  puVar11 = (undefined4 *)(puVar10 + (uVar1 - 4));
  *(undefined4 **)(puVar10 + (uVar1 - 4)) = unaff_EBP;
  cVar3 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *unaff_EBP;
    cVar3 = cVar3 + -1;
  } while (0 < cVar3);
  *(undefined **)(puVar10 + (uVar1 - 0x24)) = puVar10 + (uVar1 - 4);
  *(byte *)((int)puVar7 + __n) = *(byte *)((int)puVar7 + __n) ^ (byte)puVar7;
  pcVar8 = (char *)((uint)puVar7 & 0xffff00ff);
  *pcVar8 = *pcVar8 + (char)pcVar8;
  bVar5 = (char)pcVar8 - 0x30;
  uVar9 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11(*(undefined *)(((uint)puVar7 & 0xffff0000 | (uint)bVar5) + 2),bVar5);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar6 & 1) != 0);
  puVar2 = puVar10 + *(int *)(uVar9 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar9 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  puVar11 = (undefined4 *)(puVar2 + (uVar6 - 0x42d));
  puVar12 = (undefined4 *)(puVar2 + (uVar6 - 0x42d));
  *(undefined **)(puVar2 + (uVar6 - 0x42d)) = puVar10 + (uVar1 - 4);
  cVar3 = '\a';
  do {
    puVar11 = puVar11 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar11;
    cVar3 = cVar3 + -1;
  } while (0 < cVar3);
  *(undefined **)(puVar2 + (uVar6 - 0x44d)) = puVar2 + (uVar6 - 0x42d);
  *(char *)__n = *(char *)__n + (char)((uint)__src >> 8);
  bVar5 = (char)puVar7 + 8;
  puVar10 = (undefined *)((uint)puVar7 & 0xffffff00 | (uint)bVar5);
  *puVar10 = *puVar10;
  puVar10[(int)__src * 8] = puVar10[(int)__src * 8] + bVar5;
  uVar9 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + puVar10[2],bVar5);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar10 = puVar2 + *(int *)(uVar9 + 4) + (uVar6 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar9 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  puVar11 = (undefined4 *)(puVar10 + (uVar1 - 0x42d));
  *(undefined **)(puVar10 + (uVar1 - 0x42d)) = puVar2 + (uVar6 - 0x42d);
  cVar3 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar12;
    cVar3 = cVar3 + -1;
  } while (0 < cVar3);
  *(undefined **)(puVar10 + (uVar1 - 0x44d)) = puVar10 + (uVar1 - 0x42d);
  pcVar4 = (code *)swi(3);
  pcVar8 = (char *)(*pcVar4)((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 0x39));
  return pcVar8;
}



// WARNING: Unable to track spacebase fully for stack

void SchedGet(uint uParm1,int iParm2,char *pcParm3)

{
  uint uVar1;
  undefined *puVar2;
  char cVar3;
  code *pcVar4;
  byte bVar5;
  uint uVar6;
  uint *puVar7;
  undefined *puVar8;
  uint uVar9;
  uint *unaff_EBX;
  undefined4 *puVar10;
  undefined4 *unaff_EBP;
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar5 = (char)uParm1 - 0x30;
  uVar6 = uParm1 & 0xffff0000 |
          (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                         *(char *)((uParm1 & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar2 = &stack0x00000000 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  puVar10 = (undefined4 *)(puVar2 + (uVar1 - 4));
  puVar10 = (undefined4 *)(puVar2 + (uVar1 - 4));
  *(undefined4 **)(puVar2 + (uVar1 - 4)) = unaff_EBP;
  cVar3 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar10 = puVar10 + -1;
    *puVar10 = *unaff_EBP;
    cVar3 = cVar3 + -1;
  } while (0 < cVar3);
  *(undefined **)(puVar2 + (uVar1 - 0x24)) = puVar2 + (uVar1 - 4);
  *pcParm3 = *pcParm3 + (char)((uint)iParm2 >> 8);
  bVar5 = (char)puVar7 + 8;
  puVar8 = (undefined *)((uint)puVar7 & 0xffffff00 | (uint)bVar5);
  *puVar8 = *puVar8;
  puVar8[iParm2 * 8] = puVar8[iParm2 * 8] + bVar5;
  uVar9 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + puVar8[2],bVar5);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar6 & 1) != 0);
  puVar8 = puVar2 + *(int *)(uVar9 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar9 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  puVar10 = (undefined4 *)(puVar8 + (uVar6 - 0x42d));
  *(undefined **)(puVar8 + (uVar6 - 0x42d)) = puVar2 + (uVar1 - 4);
  cVar3 = '\a';
  do {
    puVar10 = puVar10 + -1;
    puVar10 = puVar10 + -1;
    *puVar10 = *puVar10;
    cVar3 = cVar3 + -1;
  } while (0 < cVar3);
  *(undefined **)(puVar8 + (uVar6 - 0x44d)) = puVar8 + (uVar6 - 0x42d);
  pcVar4 = (code *)swi(3);
  (*pcVar4)((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 0x39));
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  byte bVar7;
  byte bVar8;
  uint uVar9;
  uint *puVar10;
  uint uVar11;
  char *pcVar12;
  int *piVar13;
  byte bVar14;
  uint *unaff_EBX;
  undefined4 *puVar15;
  undefined4 *puVar16;
  int iVar17;
  undefined4 *unaff_EBP;
  undefined auStack4312 [32];
  undefined auStack4280 [1037];
  undefined auStack3243 [32];
  undefined auStack3211 [1037];
  undefined auStack2174 [32];
  undefined auStack2142 [1037];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar7 = (char)__s - 0x30;
  uVar9 = (uint)__s & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) +
                         *(char *)(((uint)__s & 0xffffff00 | (uint)bVar7) + 2),bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar9 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 4));
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 4));
  *(undefined4 **)(puVar3 + (uVar1 - 4)) = unaff_EBP;
  cVar6 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *unaff_EBP;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x24)) = puVar3 + (uVar1 - 4);
  bVar7 = in(0);
  pcVar12 = (char *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *pcVar12 = *pcVar12 + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)puVar10 >> 8) +
                          *(char *)(((uint)puVar10 & 0xffffff00 | (uint)(byte)(bVar7 - 0x30)) + 2),
                          bVar7 - 0x30);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar11 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar2 + (uVar9 - 0x42d));
  puVar16 = (undefined4 *)(puVar2 + (uVar9 - 0x42d));
  *(undefined **)(puVar2 + (uVar9 - 0x42d)) = puVar3 + (uVar1 - 4);
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + (uVar9 - 0x44d)) = puVar2 + (uVar9 - 0x42d);
  bVar14 = (byte)((uint)__c >> 8);
  *(byte *)__n = *(char *)__n + bVar14;
  bVar7 = (char)puVar10 + 8;
  pcVar12 = (char *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  LOCK();
  *pcVar12 = *pcVar12 + bVar7;
  pcVar12[__c * 8] = pcVar12[__c * 8] + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + pcVar12[2],bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar11 + 4) + (uVar9 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  *(undefined **)(puVar3 + (uVar1 - 0x42d)) = puVar2 + (uVar9 - 0x42d);
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x44d)) = puVar3 + (uVar1 - 0x42d);
  bVar7 = (char)puVar10 + 0x39;
  pcVar12 = (char *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *pcVar12 = *pcVar12 + bVar7;
  pcVar12[__c * 8] = pcVar12[__c * 8] + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + pcVar12[2],bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar11 + 4) + (uVar1 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar2 + uVar9 + -0x42d);
  puVar16 = (undefined4 *)(puVar2 + uVar9 + -0x42d);
  *(undefined **)(puVar2 + uVar9 + -0x42d) = puVar3 + (uVar1 - 0x42d);
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + uVar9 + -0x44d) = puVar2 + uVar9 + -0x42d;
  *(byte *)__n = *(char *)__n - bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar1 = (uint)puVar10 & 0xffffff00;
  *(byte *)__n = *(byte *)__n | bVar7;
  *(char *)(uVar1 | (uint)bVar7) = *(char *)(uVar1 | (uint)bVar7) + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)bVar7) + 2),bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar11 + 4) + uVar9 + -0x42d;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + uVar1 + -0x42d);
  puVar15 = (undefined4 *)(puVar3 + uVar1 + -0x42d);
  *(undefined **)(puVar3 + uVar1 + -0x42d) = puVar2 + uVar9 + -0x42d;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + uVar1 + -0x44d) = puVar3 + uVar1 + -0x42d;
  uVar9 = (uint)puVar10 & 0xffffff00;
  bVar7 = (char)puVar10 + -0x28 + (0xf7 < (byte)((char)puVar10 - 0x31U));
  *(char *)(uVar9 | (uint)bVar7) = *(char *)(uVar9 | (uint)bVar7) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)(byte)(bVar7 - 0x30)) + 2),
                          bVar7 - 0x30);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar5 = (int)(puVar3 + *(int *)(uVar11 + 4) + uVar1 + -0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar5 + uVar9 + -0x42d);
  puVar16 = (undefined4 *)(iVar5 + uVar9 + -0x42d);
  *(undefined **)(iVar5 + uVar9 + -0x42d) = puVar3 + uVar1 + -0x42d;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar9 + -0x44d) = iVar5 + uVar9 + -0x42d;
  *(byte *)__n = *(byte *)__n & bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar1 = (uint)puVar10 & 0xffffff00;
  *(byte *)__n = *(byte *)__n & bVar7;
  *(char *)(uVar1 | (uint)bVar7) = *(char *)(uVar1 | (uint)bVar7) + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)bVar7) + 2),bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  iVar4 = iVar5 + uVar9 + -0x42d + *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -0x42d);
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -0x42d);
  *(uint *)(iVar4 + uVar1 + -0x42d) = iVar5 + uVar9 + -0x42d;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar4 + uVar1 + -0x44d) = iVar4 + uVar1 + -0x42d;
  bVar8 = (byte)puVar10 & 0x31;
  uVar9 = (uint)puVar10 & 0xffffff00;
  bVar7 = bVar8 + 7;
  pcVar12 = (char *)(uVar9 | (uint)bVar7);
  *pcVar12 = *pcVar12 + bVar7;
  bVar8 = bVar8 - 0x29;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)bVar8) + 2),bVar8);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar5 = iVar4 + uVar1 + -0x42d + *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar5 + uVar9 + -0x42d);
  puVar16 = (undefined4 *)(iVar5 + uVar9 + -0x42d);
  *(uint *)(iVar5 + uVar9 + -0x42d) = iVar4 + uVar1 + -0x42d;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar9 + -0x44d) = iVar5 + uVar9 + -0x42d;
  *(byte *)__n = *(char *)__n - bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar1 = (uint)puVar10 & 0xffffff00;
  pcVar12 = (char *)(uVar1 | (uint)bVar7);
  *pcVar12 = *pcVar12 + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)bVar7) + 2),bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  iVar4 = iVar5 + uVar9 + -0x42d + *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -0x42d);
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -0x42d);
  *(uint *)(iVar4 + uVar1 + -0x42d) = iVar5 + uVar9 + -0x42d;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar4 + uVar1 + -0x44d) = iVar4 + uVar1 + -0x42d;
  bVar7 = (char)puVar10 - 0x29;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + __c * 2) = *(char *)(piVar13 + __c * 2) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar5 = iVar4 + uVar1 + -0x42d + *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar5 + uVar9 + -0x42c);
  puVar16 = (undefined4 *)(iVar5 + uVar9 + -0x42c);
  *(uint *)(iVar5 + uVar9 + -0x42c) = iVar4 + uVar1 + -0x42d;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar9 + -0x44c) = iVar5 + uVar9 + -0x42c;
  *(byte *)__n = *(byte *)__n ^ bVar14;
  bVar7 = (char)puVar10 + 8;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *(int **)(iVar5 + uVar9 + -0x859) = piVar13;
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + __c * 2) = *(char *)(piVar13 + __c * 2) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  iVar4 = iVar5 + uVar9 + -0x859 + *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -4);
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -4);
  *(uint *)(iVar4 + uVar1 + -4) = iVar5 + uVar9 + -0x42c;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar4 + uVar1 + -0x24) = iVar4 + uVar1 + -4;
  bVar7 = ((byte)puVar10 ^ 0x31) + 8;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  iVar17 = *(int *)(iVar4 + uVar1 + -0x42d);
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + __c * 2) = *(char *)(piVar13 + __c * 2) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar5 = iVar17 + *(int *)(uVar11 + 4);
  puVar15 = (undefined4 *)(iVar5 + uVar9);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  *(uint *)(iVar5 + uVar9) = iVar4 + uVar1 + -4;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar9 + -0x20) = iVar5 + uVar9;
  *(undefined4 *)(iVar5 + uVar9 + -0x42d) = 1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling

void MsgSendv(uint uParm1,int iParm2,byte *pbParm3)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  byte bVar7;
  byte bVar8;
  uint uVar9;
  uint *puVar10;
  char *pcVar11;
  uint uVar12;
  int *piVar13;
  byte bVar14;
  uint *unaff_EBX;
  undefined4 *puVar15;
  undefined4 *puVar16;
  int iVar17;
  undefined4 *unaff_EBP;
  undefined auStack4312 [32];
  undefined auStack4280 [1037];
  undefined auStack3243 [32];
  undefined auStack3211 [1037];
  undefined auStack2174 [32];
  undefined auStack2142 [1037];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar7 = (char)uParm1 - 0x30;
  uVar9 = uParm1 & 0xffff0000 |
          (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                         *(char *)((uParm1 & 0xffffff00 | (uint)bVar7) + 2),bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar9 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 4));
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 4));
  *(undefined4 **)(puVar3 + (uVar1 - 4)) = unaff_EBP;
  cVar6 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *unaff_EBP;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x24)) = puVar3 + (uVar1 - 4);
  bVar14 = (byte)((uint)iParm2 >> 8);
  *pbParm3 = *pbParm3 + bVar14;
  bVar7 = (char)puVar10 + 8;
  pcVar11 = (char *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  LOCK();
  *pcVar11 = *pcVar11 + bVar7;
  pcVar11[iParm2 * 8] = pcVar11[iParm2 * 8] + bVar7;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + pcVar11[2],bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar12 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar2 + (uVar9 - 0x42d));
  puVar16 = (undefined4 *)(puVar2 + (uVar9 - 0x42d));
  *(undefined **)(puVar2 + (uVar9 - 0x42d)) = puVar3 + (uVar1 - 4);
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + (uVar9 - 0x44d)) = puVar2 + (uVar9 - 0x42d);
  bVar7 = (char)puVar10 + 0x39;
  pcVar11 = (char *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *pcVar11 = *pcVar11 + bVar7;
  pcVar11[iParm2 * 8] = pcVar11[iParm2 * 8] + bVar7;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + pcVar11[2],bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar12 + 4) + (uVar9 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  *(undefined **)(puVar3 + (uVar1 - 0x42d)) = puVar2 + (uVar9 - 0x42d);
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x44d)) = puVar3 + (uVar1 - 0x42d);
  *pbParm3 = *pbParm3 - bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar9 = (uint)puVar10 & 0xffffff00;
  *pbParm3 = *pbParm3 | bVar7;
  *(char *)(uVar9 | (uint)bVar7) = *(char *)(uVar9 | (uint)bVar7) + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)bVar7) + 2),bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar12 + 4) + (uVar1 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar2 + uVar9 + -0x42d);
  puVar16 = (undefined4 *)(puVar2 + uVar9 + -0x42d);
  *(undefined **)(puVar2 + uVar9 + -0x42d) = puVar3 + (uVar1 - 0x42d);
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + uVar9 + -0x44d) = puVar2 + uVar9 + -0x42d;
  uVar1 = (uint)puVar10 & 0xffffff00;
  bVar7 = (char)puVar10 + -0x28 + (0xf7 < (byte)((char)puVar10 - 0x31U));
  *(char *)(uVar1 | (uint)bVar7) = *(char *)(uVar1 | (uint)bVar7) + bVar7;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)(byte)(bVar7 - 0x30)) + 2),
                          bVar7 - 0x30);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar12 + 4) + uVar9 + -0x42d;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + uVar1 + -0x42d);
  puVar15 = (undefined4 *)(puVar3 + uVar1 + -0x42d);
  *(undefined **)(puVar3 + uVar1 + -0x42d) = puVar2 + uVar9 + -0x42d;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + uVar1 + -0x44d) = puVar3 + uVar1 + -0x42d;
  *pbParm3 = *pbParm3 & bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar9 = (uint)puVar10 & 0xffffff00;
  *pbParm3 = *pbParm3 & bVar7;
  *(char *)(uVar9 | (uint)bVar7) = *(char *)(uVar9 | (uint)bVar7) + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)bVar7) + 2),bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar5 = (int)(puVar3 + *(int *)(uVar12 + 4) + uVar1 + -0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar5 + uVar9 + -0x42d);
  puVar16 = (undefined4 *)(iVar5 + uVar9 + -0x42d);
  *(undefined **)(iVar5 + uVar9 + -0x42d) = puVar3 + uVar1 + -0x42d;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar9 + -0x44d) = iVar5 + uVar9 + -0x42d;
  bVar8 = (byte)puVar10 & 0x31;
  uVar1 = (uint)puVar10 & 0xffffff00;
  bVar7 = bVar8 + 7;
  pcVar11 = (char *)(uVar1 | (uint)bVar7);
  *pcVar11 = *pcVar11 + bVar7;
  bVar8 = bVar8 - 0x29;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)bVar8) + 2),bVar8);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  iVar4 = iVar5 + uVar9 + -0x42d + *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -0x42d);
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -0x42d);
  *(uint *)(iVar4 + uVar1 + -0x42d) = iVar5 + uVar9 + -0x42d;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar4 + uVar1 + -0x44d) = iVar4 + uVar1 + -0x42d;
  *pbParm3 = *pbParm3 - bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar9 = (uint)puVar10 & 0xffffff00;
  pcVar11 = (char *)(uVar9 | (uint)bVar7);
  *pcVar11 = *pcVar11 + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)bVar7) + 2),bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar5 = iVar4 + uVar1 + -0x42d + *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar5 + uVar9 + -0x42d);
  puVar16 = (undefined4 *)(iVar5 + uVar9 + -0x42d);
  *(uint *)(iVar5 + uVar9 + -0x42d) = iVar4 + uVar1 + -0x42d;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar9 + -0x44d) = iVar5 + uVar9 + -0x42d;
  bVar7 = (char)puVar10 - 0x29;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + iParm2 * 2) = *(char *)(piVar13 + iParm2 * 2) + bVar7;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  iVar4 = iVar5 + uVar9 + -0x42d + *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -0x42c);
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -0x42c);
  *(uint *)(iVar4 + uVar1 + -0x42c) = iVar5 + uVar9 + -0x42d;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar4 + uVar1 + -0x44c) = iVar4 + uVar1 + -0x42c;
  *pbParm3 = *pbParm3 ^ bVar14;
  bVar7 = (char)puVar10 + 8;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *(int **)(iVar4 + uVar1 + -0x859) = piVar13;
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + iParm2 * 2) = *(char *)(piVar13 + iParm2 * 2) + bVar7;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar5 = iVar4 + uVar1 + -0x859 + *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar5 + uVar9 + -4);
  puVar16 = (undefined4 *)(iVar5 + uVar9 + -4);
  *(uint *)(iVar5 + uVar9 + -4) = iVar4 + uVar1 + -0x42c;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar9 + -0x24) = iVar5 + uVar9 + -4;
  bVar7 = ((byte)puVar10 ^ 0x31) + 8;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  iVar17 = *(int *)(iVar5 + uVar9 + -0x42d);
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + iParm2 * 2) = *(char *)(piVar13 + iParm2 * 2) + bVar7;
  uVar12 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  iVar4 = iVar17 + *(int *)(uVar12 + 4);
  puVar15 = (undefined4 *)(iVar4 + uVar1);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  *(uint *)(iVar4 + uVar1) = iVar5 + uVar9 + -4;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar4 + uVar1 + -0x20) = iVar4 + uVar1;
  *(undefined4 *)(iVar4 + uVar1 + -0x42d) = 1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

int fputc(int __c,FILE *__stream)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  byte bVar7;
  byte bVar8;
  uint uVar9;
  uint *puVar10;
  uint uVar11;
  char *pcVar12;
  int *piVar13;
  byte *in_ECX;
  byte bVar14;
  uint *unaff_EBX;
  undefined4 *puVar15;
  undefined4 *puVar16;
  int iVar17;
  undefined4 *unaff_EBP;
  undefined auStack4312 [32];
  undefined auStack4280 [1037];
  undefined auStack3243 [32];
  undefined auStack3211 [1037];
  undefined auStack2174 [32];
  undefined auStack2142 [1037];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar7 = (char)__c - 0x30;
  uVar9 = __c & 0xffff0000U |
          (uint)CONCAT11((char)((__c & 0xffffff00U) >> 8) +
                         *(char *)((__c & 0xffffff00U | (uint)bVar7) + 2),bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar9 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 4));
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 4));
  *(undefined4 **)(puVar3 + (uVar1 - 4)) = unaff_EBP;
  cVar6 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *unaff_EBP;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x24)) = puVar3 + (uVar1 - 4);
  uVar9 = (uint)puVar10 & 0xffffff00;
  bVar7 = (char)puVar10 + -0x28 + (0xf7 < (byte)((char)puVar10 - 0x31U));
  *(char *)(uVar9 | (uint)bVar7) = *(char *)(uVar9 | (uint)bVar7) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)(byte)(bVar7 - 0x30)) + 2),
                          bVar7 - 0x30);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar11 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar2 + (uVar9 - 0x42d));
  puVar16 = (undefined4 *)(puVar2 + (uVar9 - 0x42d));
  *(undefined **)(puVar2 + (uVar9 - 0x42d)) = puVar3 + (uVar1 - 4);
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + (uVar9 - 0x44d)) = puVar2 + (uVar9 - 0x42d);
  bVar14 = (byte)((uint)__stream >> 8);
  *in_ECX = *in_ECX & bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar1 = (uint)puVar10 & 0xffffff00;
  *in_ECX = *in_ECX & bVar7;
  *(char *)(uVar1 | (uint)bVar7) = *(char *)(uVar1 | (uint)bVar7) + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)bVar7) + 2),bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar11 + 4) + (uVar9 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  *(undefined **)(puVar3 + (uVar1 - 0x42d)) = puVar2 + (uVar9 - 0x42d);
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x44d)) = puVar3 + (uVar1 - 0x42d);
  bVar8 = (byte)puVar10 & 0x31;
  uVar9 = (uint)puVar10 & 0xffffff00;
  bVar7 = bVar8 + 7;
  pcVar12 = (char *)(uVar9 | (uint)bVar7);
  *pcVar12 = *pcVar12 + bVar7;
  bVar8 = bVar8 - 0x29;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)bVar8) + 2),bVar8);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar11 + 4) + (uVar1 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar2 + uVar9 + -0x42d);
  puVar16 = (undefined4 *)(puVar2 + uVar9 + -0x42d);
  *(undefined **)(puVar2 + uVar9 + -0x42d) = puVar3 + (uVar1 - 0x42d);
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + uVar9 + -0x44d) = puVar2 + uVar9 + -0x42d;
  *in_ECX = *in_ECX - bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar1 = (uint)puVar10 & 0xffffff00;
  pcVar12 = (char *)(uVar1 | (uint)bVar7);
  *pcVar12 = *pcVar12 + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)bVar7) + 2),bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar11 + 4) + uVar9 + -0x42d;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + uVar1 + -0x42d);
  puVar15 = (undefined4 *)(puVar3 + uVar1 + -0x42d);
  *(undefined **)(puVar3 + uVar1 + -0x42d) = puVar2 + uVar9 + -0x42d;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + uVar1 + -0x44d) = puVar3 + uVar1 + -0x42d;
  bVar7 = (char)puVar10 - 0x29;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + (int)__stream * 2) = *(char *)(piVar13 + (int)__stream * 2) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar5 = (int)(puVar3 + *(int *)(uVar11 + 4) + uVar1 + -0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar5 + uVar9 + -0x42c);
  puVar16 = (undefined4 *)(iVar5 + uVar9 + -0x42c);
  *(undefined **)(iVar5 + uVar9 + -0x42c) = puVar3 + uVar1 + -0x42d;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar9 + -0x44c) = iVar5 + uVar9 + -0x42c;
  *in_ECX = *in_ECX ^ bVar14;
  bVar7 = (char)puVar10 + 8;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *(int **)(iVar5 + uVar9 + -0x859) = piVar13;
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + (int)__stream * 2) = *(char *)(piVar13 + (int)__stream * 2) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  iVar4 = iVar5 + uVar9 + -0x859 + *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -4);
  puVar15 = (undefined4 *)(iVar4 + uVar1 + -4);
  *(uint *)(iVar4 + uVar1 + -4) = iVar5 + uVar9 + -0x42c;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar4 + uVar1 + -0x24) = iVar4 + uVar1 + -4;
  bVar7 = ((byte)puVar10 ^ 0x31) + 8;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  iVar17 = *(int *)(iVar4 + uVar1 + -0x42d);
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + (int)__stream * 2) = *(char *)(piVar13 + (int)__stream * 2) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar5 = iVar17 + *(int *)(uVar11 + 4);
  puVar15 = (undefined4 *)(iVar5 + uVar9);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  *(uint *)(iVar5 + uVar9) = iVar4 + uVar1 + -4;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar9 + -0x20) = iVar5 + uVar9;
  *(undefined4 *)(iVar5 + uVar9 + -0x42d) = 1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_mutex_lock(pthread_mutex_t *__mutex)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  byte bVar7;
  byte bVar8;
  uint uVar9;
  uint *puVar10;
  uint uVar11;
  char *pcVar12;
  int *piVar13;
  byte *in_ECX;
  byte bVar14;
  int in_EDX;
  uint *unaff_EBX;
  undefined4 *puVar15;
  undefined4 *puVar16;
  int iVar17;
  undefined4 *unaff_EBP;
  undefined auStack5348 [1037];
  undefined auStack4311 [32];
  undefined auStack4279 [1036];
  undefined auStack3243 [32];
  undefined auStack3211 [1037];
  undefined auStack2174 [32];
  undefined auStack2142 [1037];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar7 = (char)__mutex - 0x30;
  uVar9 = (uint)__mutex & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__mutex & 0xffffff00) >> 8) +
                         *(char *)(((uint)__mutex & 0xffffff00 | (uint)bVar7) + 2),bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar9 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 4));
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 4));
  *(undefined4 **)(puVar3 + (uVar1 - 4)) = unaff_EBP;
  cVar6 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *unaff_EBP;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x24)) = puVar3 + (uVar1 - 4);
  bVar14 = (byte)((uint)in_EDX >> 8);
  *in_ECX = *in_ECX & bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar9 = (uint)puVar10 & 0xffffff00;
  *in_ECX = *in_ECX & bVar7;
  *(char *)(uVar9 | (uint)bVar7) = *(char *)(uVar9 | (uint)bVar7) + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)bVar7) + 2),bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar11 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar2 + (uVar9 - 0x42d));
  puVar16 = (undefined4 *)(puVar2 + (uVar9 - 0x42d));
  *(undefined **)(puVar2 + (uVar9 - 0x42d)) = puVar3 + (uVar1 - 4);
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + (uVar9 - 0x44d)) = puVar2 + (uVar9 - 0x42d);
  bVar8 = (byte)puVar10 & 0x31;
  uVar1 = (uint)puVar10 & 0xffffff00;
  bVar7 = bVar8 + 7;
  pcVar12 = (char *)(uVar1 | (uint)bVar7);
  *pcVar12 = *pcVar12 + bVar7;
  bVar8 = bVar8 - 0x29;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)bVar8) + 2),bVar8);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar11 + 4) + (uVar9 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  puVar15 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  *(undefined **)(puVar3 + (uVar1 - 0x42d)) = puVar2 + (uVar9 - 0x42d);
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + (uVar1 - 0x44d)) = puVar3 + (uVar1 - 0x42d);
  *in_ECX = *in_ECX - bVar14;
  bVar7 = (char)puVar10 + 8;
  uVar9 = (uint)puVar10 & 0xffffff00;
  pcVar12 = (char *)(uVar9 | (uint)bVar7);
  *pcVar12 = *pcVar12 + bVar7;
  bVar7 = (char)puVar10 - 0x28;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)bVar7) + 2),bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar11 + 4) + (uVar1 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar2 + uVar9 + -0x42d);
  puVar16 = (undefined4 *)(puVar2 + uVar9 + -0x42d);
  *(undefined **)(puVar2 + uVar9 + -0x42d) = puVar3 + (uVar1 - 0x42d);
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar2 + uVar9 + -0x44d) = puVar2 + uVar9 + -0x42d;
  bVar7 = (char)puVar10 - 0x29;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + in_EDX * 2) = *(char *)(piVar13 + in_EDX * 2) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar11 + 4) + uVar9 + -0x42d;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(puVar3 + uVar1 + -0x42c);
  puVar15 = (undefined4 *)(puVar3 + uVar1 + -0x42c);
  *(undefined **)(puVar3 + uVar1 + -0x42c) = puVar2 + uVar9 + -0x42d;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(undefined **)(puVar3 + uVar1 + -0x44c) = puVar3 + uVar1 + -0x42c;
  *in_ECX = *in_ECX ^ bVar14;
  bVar7 = (char)puVar10 + 8;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  *(int **)(puVar3 + uVar1 + -0x859) = piVar13;
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + in_EDX * 2) = *(char *)(piVar13 + in_EDX * 2) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar4 = (int)(puVar3 + *(int *)(uVar11 + 4) + uVar1 + -0x859);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  puVar15 = (undefined4 *)(iVar4 + uVar9 + -4);
  puVar16 = (undefined4 *)(iVar4 + uVar9 + -4);
  *(undefined **)(iVar4 + uVar9 + -4) = puVar3 + uVar1 + -0x42c;
  cVar6 = '\a';
  do {
    puVar15 = puVar15 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar15;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar4 + uVar9 + -0x24) = iVar4 + uVar9 + -4;
  bVar7 = ((byte)puVar10 ^ 0x31) + 8;
  piVar13 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar7);
  iVar17 = *(int *)(iVar4 + uVar9 + -0x42d);
  *piVar13 = *piVar13 + (int)piVar13;
  *(byte *)(piVar13 + in_EDX * 2) = *(char *)(piVar13 + in_EDX * 2) + bVar7;
  uVar11 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)((int)piVar13 + 2),
                          bVar7);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  iVar5 = iVar17 + *(int *)(uVar11 + 4);
  puVar15 = (undefined4 *)(iVar5 + uVar1);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar11 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  *(uint *)(iVar5 + uVar1) = iVar4 + uVar9 + -4;
  cVar6 = '\a';
  do {
    puVar16 = puVar16 + -1;
    puVar15 = puVar15 + -1;
    *puVar15 = *puVar16;
    cVar6 = cVar6 + -1;
  } while (0 < cVar6);
  *(uint *)(iVar5 + uVar1 + -0x20) = iVar5 + uVar1;
  *(undefined4 *)(iVar5 + uVar1 + -0x42d) = 1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

void exit(int __status)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  char cVar5;
  byte bVar6;
  byte bVar7;
  uint uVar8;
  uint *puVar9;
  char *pcVar10;
  uint uVar11;
  int *piVar12;
  byte *in_ECX;
  int in_EDX;
  uint *unaff_EBX;
  undefined4 *puVar13;
  undefined4 *puVar14;
  int iVar15;
  undefined4 *unaff_EBP;
  undefined auStack5348 [1033];
  undefined auStack4315 [32];
  undefined auStack4283 [4];
  undefined auStack4279 [1037];
  undefined auStack3242 [32];
  undefined auStack3210 [1036];
  undefined auStack2174 [32];
  undefined auStack2142 [1037];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar6 = (char)__status - 0x30;
  uVar8 = __status & 0xffff0000U |
          (uint)CONCAT11((char)((__status & 0xffffff00U) >> 8) +
                         *(char *)((__status & 0xffffff00U | (uint)bVar6) + 2),bVar6);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar8 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar8 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  puVar13 = (undefined4 *)(puVar3 + (uVar1 - 4));
  puVar13 = (undefined4 *)(puVar3 + (uVar1 - 4));
  *(undefined4 **)(puVar3 + (uVar1 - 4)) = unaff_EBP;
  cVar5 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *unaff_EBP;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar3 + (uVar1 - 0x24)) = puVar3 + (uVar1 - 4);
  bVar7 = (byte)puVar9 & 0x31;
  uVar8 = (uint)puVar9 & 0xffffff00;
  bVar6 = bVar7 + 7;
  pcVar10 = (char *)(uVar8 | (uint)bVar6);
  *pcVar10 = *pcVar10 + bVar6;
  bVar7 = bVar7 - 0x29;
  uVar11 = (uint)puVar9 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar8 >> 8) + *(char *)((uVar8 | (uint)bVar7) + 2),bVar7);
  uVar8 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar8 = (uint)((uVar8 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar11 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar11 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  puVar13 = (undefined4 *)(puVar2 + (uVar8 - 0x42d));
  puVar14 = (undefined4 *)(puVar2 + (uVar8 - 0x42d));
  *(undefined **)(puVar2 + (uVar8 - 0x42d)) = puVar3 + (uVar1 - 4);
  cVar5 = '\a';
  do {
    puVar13 = puVar13 + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *puVar13;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar2 + (uVar8 - 0x44d)) = puVar2 + (uVar8 - 0x42d);
  bVar7 = (byte)((uint)in_EDX >> 8);
  *in_ECX = *in_ECX - bVar7;
  bVar6 = (char)puVar9 + 8;
  uVar1 = (uint)puVar9 & 0xffffff00;
  pcVar10 = (char *)(uVar1 | (uint)bVar6);
  *pcVar10 = *pcVar10 + bVar6;
  bVar6 = (char)puVar9 - 0x28;
  uVar11 = (uint)puVar9 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar1 >> 8) + *(char *)((uVar1 | (uint)bVar6) + 2),bVar6);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar11 + 4) + (uVar8 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar11 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  puVar13 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  puVar13 = (undefined4 *)(puVar3 + (uVar1 - 0x42d));
  *(undefined **)(puVar3 + (uVar1 - 0x42d)) = puVar2 + (uVar8 - 0x42d);
  cVar5 = '\a';
  do {
    puVar14 = puVar14 + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *puVar14;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar3 + (uVar1 - 0x44d)) = puVar3 + (uVar1 - 0x42d);
  bVar6 = (char)puVar9 - 0x29;
  piVar12 = (int *)((uint)puVar9 & 0xffffff00 | (uint)bVar6);
  *piVar12 = *piVar12 + (int)piVar12;
  *(byte *)(piVar12 + in_EDX * 2) = *(char *)(piVar12 + in_EDX * 2) + bVar6;
  uVar11 = (uint)puVar9 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar9 & 0xffffff00) >> 8) + *(char *)((int)piVar12 + 2),
                          bVar6);
  uVar8 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar8 = (uint)((uVar8 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar11 + 4) + (uVar1 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar11 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  puVar13 = (undefined4 *)(puVar2 + uVar8 + -0x42c);
  puVar14 = (undefined4 *)(puVar2 + uVar8 + -0x42c);
  *(undefined **)(puVar2 + uVar8 + -0x42c) = puVar3 + (uVar1 - 0x42d);
  cVar5 = '\a';
  do {
    puVar13 = puVar13 + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *puVar13;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar2 + uVar8 + -0x44c) = puVar2 + uVar8 + -0x42c;
  *in_ECX = *in_ECX ^ bVar7;
  bVar6 = (char)puVar9 + 8;
  piVar12 = (int *)((uint)puVar9 & 0xffffff00 | (uint)bVar6);
  *(int **)(puVar2 + uVar8 + -0x859) = piVar12;
  *piVar12 = *piVar12 + (int)piVar12;
  *(byte *)(piVar12 + in_EDX * 2) = *(char *)(piVar12 + in_EDX * 2) + bVar6;
  uVar11 = (uint)puVar9 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar9 & 0xffffff00) >> 8) + *(char *)((int)piVar12 + 2),
                          bVar6);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar11 + 4) + uVar8 + -0x859;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar11 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  puVar13 = (undefined4 *)(puVar3 + uVar1 + -4);
  puVar13 = (undefined4 *)(puVar3 + uVar1 + -4);
  *(undefined **)(puVar3 + uVar1 + -4) = puVar2 + uVar8 + -0x42c;
  cVar5 = '\a';
  do {
    puVar14 = puVar14 + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *puVar14;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar3 + uVar1 + -0x24) = puVar3 + uVar1 + -4;
  bVar6 = ((byte)puVar9 ^ 0x31) + 8;
  piVar12 = (int *)((uint)puVar9 & 0xffffff00 | (uint)bVar6);
  iVar15 = *(int *)(puVar3 + uVar1 + -0x42d);
  *piVar12 = *piVar12 + (int)piVar12;
  *(byte *)(piVar12 + in_EDX * 2) = *(char *)(piVar12 + in_EDX * 2) + bVar6;
  uVar11 = (uint)puVar9 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar9 & 0xffffff00) >> 8) + *(char *)((int)piVar12 + 2),
                          bVar6);
  uVar8 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar8 = (uint)((uVar8 & 1) != 0);
  iVar4 = iVar15 + *(int *)(uVar11 + 4);
  puVar13 = (undefined4 *)(iVar4 + uVar8);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar11 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  *(undefined **)(iVar4 + uVar8) = puVar3 + uVar1 + -4;
  cVar5 = '\a';
  do {
    puVar13 = puVar13 + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *puVar13;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(uint *)(iVar4 + uVar8 + -0x20) = iVar4 + uVar8;
  *(undefined4 *)(iVar4 + uVar8 + -0x42d) = 1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

size_t strlen(char *__s)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  char cVar5;
  byte bVar6;
  uint uVar7;
  uint *puVar8;
  char *pcVar9;
  uint uVar10;
  int *piVar11;
  byte *in_ECX;
  byte bVar12;
  int in_EDX;
  uint *unaff_EBX;
  undefined4 *puVar13;
  undefined4 *puVar14;
  int iVar15;
  undefined4 *unaff_EBP;
  undefined auStack4279 [1033];
  undefined auStack3246 [32];
  undefined auStack3214 [4];
  undefined auStack3210 [1037];
  undefined auStack2173 [32];
  undefined auStack2141 [1036];
  undefined auStack1105 [32];
  undefined auStack1073 [1037];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar6 = (char)__s - 0x30;
  uVar7 = (uint)__s & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) +
                         *(char *)(((uint)__s & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar13 = (undefined4 *)(puVar3 + (uVar1 - 4));
  puVar13 = (undefined4 *)(puVar3 + (uVar1 - 4));
  *(undefined4 **)(puVar3 + (uVar1 - 4)) = unaff_EBP;
  cVar5 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *unaff_EBP;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar3 + (uVar1 - 0x24)) = puVar3 + (uVar1 - 4);
  bVar12 = (byte)((uint)in_EDX >> 8);
  *in_ECX = *in_ECX - bVar12;
  bVar6 = (char)puVar8 + 8;
  uVar7 = (uint)puVar8 & 0xffffff00;
  pcVar9 = (char *)(uVar7 | (uint)bVar6);
  *pcVar9 = *pcVar9 + bVar6;
  bVar6 = (char)puVar8 - 0x28;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar7 >> 8) + *(char *)((uVar7 | (uint)bVar6) + 2),bVar6);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar10 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar13 = (undefined4 *)(puVar2 + (uVar7 - 0x42d));
  puVar14 = (undefined4 *)(puVar2 + (uVar7 - 0x42d));
  *(undefined **)(puVar2 + (uVar7 - 0x42d)) = puVar3 + (uVar1 - 4);
  cVar5 = '\a';
  do {
    puVar13 = puVar13 + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *puVar13;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar2 + (uVar7 - 0x44d)) = puVar2 + (uVar7 - 0x42d);
  bVar6 = (char)puVar8 - 0x29;
  piVar11 = (int *)((uint)puVar8 & 0xffffff00 | (uint)bVar6);
  *piVar11 = *piVar11 + (int)piVar11;
  *(byte *)(piVar11 + in_EDX * 2) = *(char *)(piVar11 + in_EDX * 2) + bVar6;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + *(char *)((int)piVar11 + 2),
                          bVar6);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar10 + 4) + (uVar7 - 0x42d);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar13 = (undefined4 *)(puVar3 + (uVar1 - 0x42c));
  puVar13 = (undefined4 *)(puVar3 + (uVar1 - 0x42c));
  *(undefined **)(puVar3 + (uVar1 - 0x42c)) = puVar2 + (uVar7 - 0x42d);
  cVar5 = '\a';
  do {
    puVar14 = puVar14 + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *puVar14;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar3 + (uVar1 - 0x44c)) = puVar3 + (uVar1 - 0x42c);
  *in_ECX = *in_ECX ^ bVar12;
  bVar6 = (char)puVar8 + 8;
  piVar11 = (int *)((uint)puVar8 & 0xffffff00 | (uint)bVar6);
  *(int **)(puVar3 + (uVar1 - 0x859)) = piVar11;
  *piVar11 = *piVar11 + (int)piVar11;
  *(byte *)(piVar11 + in_EDX * 2) = *(char *)(piVar11 + in_EDX * 2) + bVar6;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + *(char *)((int)piVar11 + 2),
                          bVar6);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar10 + 4) + (uVar1 - 0x859);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar13 = (undefined4 *)(puVar2 + uVar7 + -4);
  puVar14 = (undefined4 *)(puVar2 + uVar7 + -4);
  *(undefined **)(puVar2 + uVar7 + -4) = puVar3 + (uVar1 - 0x42c);
  cVar5 = '\a';
  do {
    puVar13 = puVar13 + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *puVar13;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar2 + uVar7 + -0x24) = puVar2 + uVar7 + -4;
  bVar6 = ((byte)puVar8 ^ 0x31) + 8;
  piVar11 = (int *)((uint)puVar8 & 0xffffff00 | (uint)bVar6);
  iVar15 = *(int *)(puVar2 + uVar7 + -0x42d);
  *piVar11 = *piVar11 + (int)piVar11;
  *(byte *)(piVar11 + in_EDX * 2) = *(char *)(piVar11 + in_EDX * 2) + bVar6;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + *(char *)((int)piVar11 + 2),
                          bVar6);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  iVar4 = iVar15 + *(int *)(uVar10 + 4);
  puVar13 = (undefined4 *)(iVar4 + uVar1);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(undefined **)(iVar4 + uVar1) = puVar2 + uVar7 + -4;
  cVar5 = '\a';
  do {
    puVar14 = puVar14 + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *puVar14;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(uint *)(iVar4 + uVar1 + -0x20) = iVar4 + uVar1;
  *(undefined4 *)(iVar4 + uVar1 + -0x42d) = 1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

int open(char *__file,int __oflag,...)

{
  uint uVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  char cVar5;
  byte bVar6;
  uint uVar7;
  uint *puVar8;
  int *piVar9;
  uint uVar10;
  byte *in_ECX;
  uint *unaff_EBX;
  undefined4 *puVar11;
  undefined4 *puVar12;
  int iVar13;
  undefined4 *unaff_EBP;
  undefined auStack3210 [1033];
  undefined auStack2177 [32];
  undefined auStack2145 [4];
  undefined auStack2141 [1037];
  undefined auStack1104 [32];
  undefined auStack1072 [1036];
  undefined auStack36 [32];
  undefined auStack4 [4];
  
  bVar6 = (char)__file - 0x30;
  uVar7 = (uint)__file & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__file & 0xffffff00) >> 8) +
                         *(char *)(((uint)__file & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar11 = (undefined4 *)(puVar3 + (uVar1 - 4));
  puVar11 = (undefined4 *)(puVar3 + (uVar1 - 4));
  *(undefined4 **)(puVar3 + (uVar1 - 4)) = unaff_EBP;
  cVar5 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *unaff_EBP;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar3 + (uVar1 - 0x24)) = puVar3 + (uVar1 - 4);
  bVar6 = (char)puVar8 - 0x29;
  piVar9 = (int *)((uint)puVar8 & 0xffffff00 | (uint)bVar6);
  *piVar9 = *piVar9 + (int)piVar9;
  *(byte *)(piVar9 + __oflag * 2) = *(char *)(piVar9 + __oflag * 2) + bVar6;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + *(char *)((int)piVar9 + 2),
                          bVar6);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar2 = puVar3 + *(int *)(uVar10 + 4) + (uVar1 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar11 = (undefined4 *)(puVar2 + (uVar7 - 0x42c));
  puVar12 = (undefined4 *)(puVar2 + (uVar7 - 0x42c));
  *(undefined **)(puVar2 + (uVar7 - 0x42c)) = puVar3 + (uVar1 - 4);
  cVar5 = '\a';
  do {
    puVar11 = puVar11 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar11;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar2 + (uVar7 - 0x44c)) = puVar2 + (uVar7 - 0x42c);
  *in_ECX = *in_ECX ^ (byte)((uint)__oflag >> 8);
  bVar6 = (char)puVar8 + 8;
  piVar9 = (int *)((uint)puVar8 & 0xffffff00 | (uint)bVar6);
  *(int **)(puVar2 + (uVar7 - 0x859)) = piVar9;
  *piVar9 = *piVar9 + (int)piVar9;
  *(byte *)(piVar9 + __oflag * 2) = *(char *)(piVar9 + __oflag * 2) + bVar6;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + *(char *)((int)piVar9 + 2),
                          bVar6);
  uVar1 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar1 = (uint)((uVar1 & 1) != 0);
  puVar3 = puVar2 + *(int *)(uVar10 + 4) + (uVar7 - 0x859);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  puVar11 = (undefined4 *)(puVar3 + (uVar1 - 4));
  puVar11 = (undefined4 *)(puVar3 + (uVar1 - 4));
  *(undefined **)(puVar3 + (uVar1 - 4)) = puVar2 + (uVar7 - 0x42c);
  cVar5 = '\a';
  do {
    puVar12 = puVar12 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar12;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(undefined **)(puVar3 + (uVar1 - 0x24)) = puVar3 + (uVar1 - 4);
  bVar6 = ((byte)puVar8 ^ 0x31) + 8;
  piVar9 = (int *)((uint)puVar8 & 0xffffff00 | (uint)bVar6);
  iVar13 = *(int *)(puVar3 + (uVar1 - 0x42d));
  *piVar9 = *piVar9 + (int)piVar9;
  *(byte *)(piVar9 + __oflag * 2) = *(char *)(piVar9 + __oflag * 2) + bVar6;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + *(char *)((int)piVar9 + 2),
                          bVar6);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  iVar4 = iVar13 + *(int *)(uVar10 + 4);
  puVar11 = (undefined4 *)(iVar4 + uVar7);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(undefined **)(iVar4 + uVar7) = puVar3 + (uVar1 - 4);
  cVar5 = '\a';
  do {
    puVar11 = puVar11 + -1;
    puVar11 = puVar11 + -1;
    *puVar11 = *puVar11;
    cVar5 = cVar5 + -1;
  } while (0 < cVar5);
  *(uint *)(iVar4 + uVar7 + -0x20) = iVar4 + uVar7;
  *(undefined4 *)(iVar4 + uVar7 + -0x42d) = 1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void __stdcall entry(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x08041304) overlaps instruction at (ram,0x08041303)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void main(undefined4 param_1,undefined4 param_2,uint param_3)

{
  undefined uVar1;
  byte *pbVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  byte *pbVar6;
  int iVar7;
  uint uVar8;
  byte bVar9;
  byte bVar10;
  undefined *puVar11;
  uint uVar12;
  uint *puVar13;
  byte bVar14;
  uint *unaff_EBX;
  uint uVar15;
  uint unaff_EBP;
  undefined6 *unaff_ESI;
  undefined6 *puVar16;
  int *unaff_EDI;
  undefined2 in_DS;
  bool bVar17;
  undefined2 in_stack_00000000;
  undefined in_stack_00000002;
  unkbyte9 in_stack_00000003;
  
  uVar4 = (uint)in_stack_00000003;
  while( true ) {
    puVar16 = unaff_ESI;
    uVar1 = *(undefined *)unaff_EDI;
    *(char *)unaff_EDI = (char)(param_3 >> 8);
    uVar12 = CONCAT13((char)uVar4,CONCAT12(in_stack_00000002,in_stack_00000000));
    uVar4 = uVar12 & 0xe0012f96;
    cVar3 = (char)uVar4;
    out(0x2f,cVar3);
    bVar17 = false;
    bVar9 = (byte)param_3 & *(byte *)(unaff_EDI + -0x11);
    param_3 = param_3 & 0xffff0000 | (uint)CONCAT11(uVar1,(byte)param_3) & 0xffffff00 | (uint)bVar9;
    if ((char)bVar9 < 1) break;
    pbVar6 = (byte *)(uVar4 + 4 + (int)puVar16);
    *pbVar6 = *pbVar6 | (byte)((uint)param_2 >> 8);
    pbVar6 = (byte *)(param_3 + 0x1e2c0804 + (int)puVar16);
    *pbVar6 = *pbVar6 | (byte)unaff_EBX;
    uVar12 = uVar12 & 0xe0012f00;
    in_stack_00000002 = (undefined)(uVar12 >> 0x10);
    uVar4 = uVar12 >> 0x18;
    unaff_ESI = (undefined6 *)(uVar12 | (uint)(byte)(cVar3 + 0x20U));
    in_stack_00000000 = in_DS;
    if (SCARRY1(cVar3 + 0x18,'\b') == (char)(cVar3 + 0x20U) < 0) {
      *(undefined2 *)puVar16 = in_DS;
      *(undefined *)unaff_EDI = *(undefined *)puVar16;
      unaff_EBX = (uint *)(int)*(undefined6 *)((int)puVar16 + 1);
      unaff_ESI = (undefined6 *)((int)puVar16 + 1);
      unaff_EDI = (int *)((int)unaff_EDI + 1);
      in_stack_00000000 = in_DS;
    }
  }
  if ((char)bVar9 < 1) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    *(byte *)(unaff_EBX + -0xb) = *(byte *)(unaff_EBX + -0xb) >> 1 | bVar17 << 7;
    puVar5 = (uint *)((uVar4 & 0xffff0000 | (uint)(byte)((char)uVar4 + (char)(uVar4 >> 8) * '\v')) +
                     1);
    *puVar5 = *puVar5 | (uint)puVar5;
    puVar13 = (uint *)((unkuint9)in_stack_00000003 >> 0x28);
    *(byte *)(puVar13 + -10) = *(byte *)(puVar13 + -10) >> 1;
    uVar4 = ((uint)puVar5 & 0xffff0000 |
             (uint)CONCAT11((byte)puVar5 / 0xb,(byte)puVar5) & 0xffffff00 | (uint)puVar5 & 0xb) + 1;
    *(byte *)(unaff_EBP + 0x5a) = *(byte *)(unaff_EBP + 0x5a) & 0xd0;
    uVar4 = uVar4 & 0xffff0000 | (uint)(byte)((char)uVar4 + (char)(uVar4 >> 8) * '\v');
    *puVar13 = *puVar13 >> 1 | (uint)((*puVar13 & 1) != 0) << 0x1f;
    puVar11 = (undefined *)((int)unaff_EDI + 1);
    pbVar6 = (byte *)((int)unaff_EDI + (uVar4 - 0x1e));
    *pbVar6 = *pbVar6 & 0x94;
    pbVar6 = (byte *)(uVar4 + 1 & 0xffffff00 | (uint)DAT_64037e44);
    *pbVar6 = *pbVar6 << 1 | (char)*pbVar6 < 0;
    iVar7 = in(0xb);
    puVar5 = (uint *)(iVar7 + 1);
    bVar9 = (byte)((uint)puVar5 >> 8);
    *(byte *)puVar5 = *(byte *)puVar5 | bVar9;
    *(uint *)((int)puVar13 + 0x400bd055) = *(uint *)((int)puVar13 + 0x400bd055) | (uint)puVar11;
    *puVar5 = *puVar5 | (uint)puVar5;
    *(byte *)(iVar7 + -0x2fad81bb) = bVar9;
    uVar4 = (uint)puVar5 | *(uint *)(iVar7 + 10);
    *(char *)(puVar13 + 0x145f9128) = *(char *)(puVar13 + 0x145f9128) + (char)uVar4;
    bVar9 = (char)((unkuint9)in_stack_00000003 >> 0x28) * 2;
    uVar12 = (uint)puVar11 & 0xffff0000 |
             (uint)CONCAT11((char)((uint)puVar11 >> 8) + (char)(uVar4 >> 8),(char)puVar11);
    pbVar6 = (byte *)((int)uVar4 >> 0x1f);
    bVar10 = (byte)(((uint)puVar13 & 0xffffff00) >> 8);
    bVar14 = bVar9 - bVar10;
    unaff_EBX = (uint *)((uint)puVar13 & 0xffffff00 | (uint)bVar14);
    puVar13 = (uint *)(uVar12 - 1);
    if (puVar13 == (uint *)0x0 || bVar14 != 0) break;
    *pbVar6 = *pbVar6 << 1 | (char)*pbVar6 < 0;
    iVar7 = in(0x5c);
    bVar17 = (*unaff_EBX & 1) != 0;
    *unaff_EBX = *unaff_EBX >> 1 | (uint)bVar17 << 0x1f;
    uVar4 = iVar7 + 1;
    pbVar6 = (byte *)((int)unaff_EDI * 9 + -0x78);
    bVar14 = (byte)(uVar4 >> 8);
    bVar9 = bVar14 + *pbVar6;
    uVar4 = uVar4 & 0xffff0000 | (uint)CONCAT11(bVar9 + bVar17,(char)uVar4) & 0xffffff00 |
            (uint)(byte)((char)uVar4 + -0x71 + (CARRY1(bVar14,*pbVar6) || CARRY1(bVar9,bVar17)));
    puVar13 = (uint *)(uVar12 + 0x59);
    bVar17 = CARRY4(unaff_EBP,*puVar13);
    unaff_EBP = unaff_EBP + *puVar13;
  }
  _DAT_08e20143 =
       _DAT_08e20143 + (ushort)(bVar9 < bVar10) * (((ushort)unaff_EBX & 3) - (_DAT_08e20143 & 3));
  puVar5 = (uint *)(((uint)pbVar6 ^ *(uint *)((int)unaff_EBX + -0x729ecd9b)) + 1);
  uVar4 = in(0x2b);
  uVar4 = uVar4 & *puVar13;
  if (uVar4 != 0) {
    uVar15 = ((int)unaff_EBX + 1U & (uint)&stack0x0000000b) << 1;
    bVar9 = (byte)(uVar4 >> 8);
    bVar10 = (byte)(uVar15 >> 8);
    bVar14 = (byte)uVar15;
    pbVar6 = (byte *)((uVar15 & 0xffff0000 | (uint)CONCAT11(bVar10 + bVar9,bVar14)) + 0x6d);
    uVar12 = (uint)CONCAT11((byte)((uint)puVar13 >> 8) ^ *(byte *)puVar5,
                            ((char)puVar13 + -0x32) -
                            (CARRY1(bVar9,*pbVar6) || CARRY1(bVar9 + *pbVar6,CARRY1(bVar10,bVar9))))
    ;
    uVar8 = (uint)puVar13 & 0xffff0000 | uVar12;
    bVar9 = (byte)(uVar12 >> 8);
    bVar10 = (byte)uVar4 + bVar9;
    uVar12 = (uint)CARRY1((byte)uVar4,bVar9);
    uVar4 = *puVar5;
    *puVar5 = (int)puVar5 + uVar12 + *puVar5;
    uVar8 = uVar8 | *(uint *)(uVar8 + 0x22);
    bVar17 = 9 < ((byte)uVar8 & 0xf) ||
             ((uVar4 & 0xfffffff) + ((uint)puVar5 & 0xfffffff) + uVar12 & 0x10000000) != 0;
    bVar9 = (byte)uVar8 + bVar17 * -6;
    pbVar2 = (byte *)(uVar8 & 0xffffff00 |
                     (uint)(byte)(bVar9 + (0x9f < bVar9 | bVar17 * (bVar9 < 6)) * -0x60));
    *(int *)(pbVar2 + 0x7f048d05) = *(int *)(pbVar2 + 0x7f048d05) + -1;
    *pbVar2 = *pbVar2 | (byte)(uVar8 >> 8);
    pbVar6 = (byte *)(unaff_EBP + 0xa006e1fb);
    bVar9 = *pbVar6;
    *pbVar6 = *pbVar6 + bVar10;
    bVar14 = bVar14 + (9 < (bVar14 & 0xf) || ((bVar9 & 0xf) + (bVar10 & 0xf) & 0x10) != 0) * -6;
    *unaff_EDI = *unaff_EDI >> 1;
    uVar12 = (uint)(CONCAT11((bVar14 & 0xf) / 0xb,bVar14) & 0xff0f) & 0xffffff00;
    uVar4 = uVar15 & 0xffff0000 | uVar12;
    puVar13 = (uint *)(uVar4 | (uint)bVar14 & 0xb);
    *puVar13 = *puVar13 | (uint)puVar13;
    pbVar6 = (byte *)(uVar4 | (uint)DAT_401de001);
    pbVar6[-0x12] = pbVar6[-0x12] | DAT_401de001;
    pbVar2[0x1401c61] = pbVar2[0x1401c61] + bVar10 + 1;
    *pbVar6 = *pbVar6 | (byte)(uVar12 >> 8);
    return;
  }
  return;
}



// WARNING: Control flow encountered bad instruction data

void __movstr_i4_even(int iParm1,undefined4 uParm2,undefined4 uParm3,int iParm4,uint *puParm5,
                     undefined4 uParm6,byte bParm7)

{
  ushort *puVar1;
  int *piVar2;
  byte *pbVar3;
  uint uVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  bool bVar9;
  bool bVar10;
  
  if ((byte)((byte)iParm1 | 0xa0) != 0) {
    uVar4 = *puParm5;
    *puParm5 = *puParm5 + (int)puParm5;
    bVar9 = 0xcc < bParm7 || CARRY1(bParm7 + 0x33,CARRY4(uVar4,(uint)puParm5));
    bVar6 = bParm7 + 0x33 + CARRY4(uVar4,(uint)puParm5);
    bVar7 = bVar6 + 0x10;
    bVar10 = 0xef < bVar6 || CARRY1(bVar7,bVar9);
    bVar7 = bVar7 + bVar9;
    out((short)puParm5,bVar7);
    puVar1 = (ushort *)(iParm1 + 0x62);
    pbVar3 = (byte *)(iParm1 + 99 + (int)puVar1 * 2);
    bVar6 = *pbVar3;
    bVar8 = (byte)((uint)puVar1 >> 8);
    bVar5 = *pbVar3 + bVar8;
    *pbVar3 = bVar5 + bVar10;
    *puVar1 = *puVar1 + (ushort)(CARRY1(bVar6,bVar8) || CARRY1(bVar5,bVar10)) *
                        (((ushort)bVar7 & 3) - (*puVar1 & 3));
    piVar2 = (int *)(iParm4 + (iParm1 + 2) * 8);
    *piVar2 = *piVar2 + (int)puVar1;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void __stdcall
__movstr_i4_odd(undefined4 uParm1,undefined4 uParm2,int iParm3,uint *puParm4,undefined4 uParm5,
               byte bParm6)

{
  ushort *puVar1;
  int *piVar2;
  byte *pbVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte in_CF;
  bool bVar8;
  bool bVar9;
  bool in_ZF;
  int in_stack_00000000;
  
  if (!in_ZF) {
    bVar8 = CARRY4(*puParm4,(uint)puParm4) || CARRY4(*puParm4 + (int)puParm4,(uint)in_CF);
    *puParm4 = *puParm4 + (int)puParm4 + (uint)in_CF;
    bVar9 = 0xcc < bParm6 || CARRY1(bParm6 + 0x33,bVar8);
    bVar5 = bParm6 + 0x33 + bVar8;
    bVar6 = bVar5 + 0x10;
    bVar8 = 0xef < bVar5 || CARRY1(bVar6,bVar9);
    bVar6 = bVar6 + bVar9;
    out((short)puParm4,bVar6);
    puVar1 = (ushort *)(in_stack_00000000 + 0x62);
    pbVar3 = (byte *)(in_stack_00000000 + 99 + (int)puVar1 * 2);
    bVar5 = *pbVar3;
    bVar7 = (byte)((uint)puVar1 >> 8);
    bVar4 = *pbVar3 + bVar7;
    *pbVar3 = bVar4 + bVar8;
    *puVar1 = *puVar1 + (ushort)(CARRY1(bVar5,bVar7) || CARRY1(bVar4,bVar8)) *
                        (((ushort)bVar6 & 3) - (*puVar1 & 3));
    piVar2 = (int *)(iParm3 + (in_stack_00000000 + 2) * 8);
    *piVar2 = *piVar2 + (int)puVar1;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void __movstrSI12_i4(undefined4 uParm1,char *pcParm2,int iParm3)

{
  *pcParm2 = *pcParm2 + (char)((uint)uParm1 >> 8) + pcParm2[iParm3];
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


