typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
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

typedef int __clockid_t;

typedef __clockid_t clockid_t;

typedef struct timeval timeval, *Ptimeval;

typedef long __suseconds_t;

struct timeval {
    __time_t tv_sec;
    __suseconds_t tv_usec;
};

typedef struct sigaction sigaction, *Psigaction;

typedef union _union_1048 _union_1048, *P_union_1048;

typedef struct siginfo siginfo, *Psiginfo;

typedef struct siginfo siginfo_t;

typedef struct __sigset_t __sigset_t, *P__sigset_t;

typedef void (* __sighandler_t)(int);

typedef union _union_1028 _union_1028, *P_union_1028;

typedef struct _struct_1029 _struct_1029, *P_struct_1029;

typedef struct _struct_1030 _struct_1030, *P_struct_1030;

typedef struct _struct_1031 _struct_1031, *P_struct_1031;

typedef struct _struct_1032 _struct_1032, *P_struct_1032;

typedef struct _struct_1033 _struct_1033, *P_struct_1033;

typedef struct _struct_1034 _struct_1034, *P_struct_1034;

typedef int __pid_t;

typedef union sigval sigval, *Psigval;

typedef union sigval sigval_t;

typedef long __clock_t;

struct _struct_1034 {
    long si_band;
    int si_fd;
};

struct __sigset_t {
    ulong __val[128];
};

struct _struct_1033 {
    void * si_addr;
};

union sigval {
    int sival_int;
    void * sival_ptr;
};

struct _struct_1032 {
    __pid_t si_pid;
    __uid_t si_uid;
    int si_status;
    __clock_t si_utime;
    __clock_t si_stime;
};

struct _struct_1031 {
    __pid_t si_pid;
    __uid_t si_uid;
    sigval_t si_sigval;
};

struct _struct_1029 {
    __pid_t si_pid;
    __uid_t si_uid;
};

struct _struct_1030 {
    int si_tid;
    int si_overrun;
    sigval_t si_sigval;
};

union _union_1028 {
    int _pad[125];
    struct _struct_1029 _kill;
    struct _struct_1030 _timer;
    struct _struct_1031 _rt;
    struct _struct_1032 _sigchld;
    struct _struct_1033 _sigfault;
    struct _struct_1034 _sigpoll;
};

struct siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    union _union_1028 _sifields;
};

union _union_1048 {
    __sighandler_t sa_handler;
    void (* sa_sigaction)(int, siginfo_t *, void *);
};

struct sigaction {
    union _union_1048 __sigaction_handler;
    struct __sigset_t sa_mask;
    int sa_flags;
    void (* sa_restorer)(void);
};

typedef union sem_t sem_t, *Psem_t;

union sem_t {
    char __size[16];
    long __align;
};

typedef struct _IO_FILE FILE;

typedef long __fd_mask;

typedef struct __sigset_t sigset_t;

typedef struct fd_set fd_set, *Pfd_set;

struct fd_set {
    __fd_mask fds_bits[128];
};

typedef int __ssize_t;

typedef __ssize_t ssize_t;

typedef struct sched_param sched_param, *Psched_param;

struct sched_param {
    int __sched_priority;
};

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

typedef union pthread_condattr_t pthread_condattr_t, *Ppthread_condattr_t;

union pthread_condattr_t {
    char __size[4];
    int __align;
};

typedef union pthread_mutexattr_t pthread_mutexattr_t, *Ppthread_mutexattr_t;

union pthread_mutexattr_t {
    char __size[4];
    int __align;
};

typedef union pthread_cond_t pthread_cond_t, *Ppthread_cond_t;

typedef struct _struct_16 _struct_16, *P_struct_16;

struct _struct_16 {
    int __lock;
    uint __futex;
    ulonglong __total_seq;
    ulonglong __wakeup_seq;
    ulonglong __woken_seq;
    void * __mutex;
    uint __nwaiters;
    uint __broadcast_seq;
};

union pthread_cond_t {
    struct _struct_16 __data;
    char __size[48];
    longlong __align;
};

typedef ulong pthread_t;

typedef uint pthread_key_t;

typedef union pthread_attr_t pthread_attr_t, *Ppthread_attr_t;

union pthread_attr_t {
    char __size[36];
    long __align;
};

typedef struct __dirstream __dirstream, *P__dirstream;

struct __dirstream {
};

typedef struct __dirstream DIR;

typedef struct dirent dirent, *Pdirent;

struct dirent {
    __ino_t d_ino;
    __off_t d_off;
    ushort d_reclen;
    uchar d_type;
    char d_name[256];
};

typedef struct nothrow_t nothrow_t, *Pnothrow_t;

struct nothrow_t { // PlaceHolder Structure
};

typedef int (* __compar_fn_t)(void *, void *);

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
// WARNING: Unknown calling convention yet parameter storage is locked

int _init(EVP_PKEY_CTX *ctx)

{
  out(0x2f,(char)ctx);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int printf(char *__format,...)

{
  undefined uVar1;
  int iVar2;
  undefined *puVar3;
  undefined *puVar4;
  code *pcVar5;
  byte bVar6;
  char cVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  ushort uVar11;
  uint *puVar12;
  uint uVar13;
  uint uVar14;
  byte *pbVar15;
  uint uVar16;
  uint uVar17;
  int iVar18;
  uint uVar19;
  int *piVar20;
  int iVar21;
  int iVar22;
  char *pcVar23;
  uint uVar24;
  byte bVar25;
  int in_ECX;
  byte bVar26;
  byte *in_EDX;
  byte *pbVar27;
  uint *unaff_EBX;
  int iVar28;
  undefined *puVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined4 *puVar32;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar33;
  byte in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack4 [4];
  
  bVar6 = (char)__format - 0x30;
  uVar16 = (uint)__format & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__format & 0xffffff00) >> 8) +
                          *(char *)(((uint)__format & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar18 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  pbVar15 = (byte *)(((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8)) ^ 0x79);
  bVar26 = (byte)unaff_EBX;
  *pbVar15 = *pbVar15 | bVar26;
  cVar7 = (char)pbVar15;
  *pbVar15 = *pbVar15 + cVar7;
  pbVar15[(int)in_EDX * 8] = pbVar15[(int)in_EDX * 8] + cVar7;
  uVar14 = (uint)puVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + pbVar15[2],cVar7);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar21 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar14 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar6 = (char)puVar12 + 8;
  uVar14 = (uint)puVar12 & 0xffffff00;
  pcVar23 = (char *)(uVar14 | (uint)bVar6);
  bVar8 = (byte)(uVar14 >> 8);
  *(byte *)((int)pcVar23 * 2) = *(byte *)((int)pcVar23 * 2) | bVar8;
  *pcVar23 = *pcVar23 + bVar6;
  bVar6 = (char)puVar12 - 0x28;
  uVar17 = (uint)puVar12 & 0xffff0000 |
           (uint)CONCAT11(bVar8 + *(char *)((uVar14 | (uint)bVar6) + 2),bVar6);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar22 = *(int *)(uVar17 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar17 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar6 = (char)puVar12 + 8;
  pbVar15 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)bVar6);
  *pbVar15 = *pbVar15 | (byte)((uint)in_EDX >> 8);
  *pbVar15 = *pbVar15 + bVar6;
  pbVar15[(int)in_EDX * 8] = pbVar15[(int)in_EDX * 8] + bVar6;
  uVar24 = (uint)puVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + pbVar15[2],bVar6);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar24 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar24 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  pcVar23 = (char *)(((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8)) + 1);
  bVar6 = (byte)((uint)unaff_EBX >> 8);
  if ((int)pcVar23 < 0) {
    *(byte *)((int)pcVar23 * 2) = *(byte *)((int)pcVar23 * 2) | bVar6;
    *pcVar23 = *pcVar23 + (char)pcVar23;
    pcVar23 = (char *)((uint)pcVar23 & 0xffffff00 | (uint)(byte)((char)pcVar23 - 0x30));
  }
  uVar13 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
  uVar24 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar24 = (uint)((uVar24 & 1) != 0);
  puVar3 = &stack0x00000000 +
           *(int *)(uVar13 + 4) +
           (uint)((uVar17 & 1) != 0) +
           iVar2 + (uint)((uVar14 & 1) != 0) +
                   iVar22 + (uint)((uVar16 & 1) != 0) + iVar21 + (uint)((uVar19 & 1) != 0) + iVar18;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  pbVar15 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
  bVar10 = (byte)in_ECX;
  if ((int)(puVar3 + uVar24 + 5) < 0) {
    *pbVar15 = *pbVar15 | bVar10;
    *pbVar15 = *pbVar15 + bVar8;
    pbVar15 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar16 = (uint)pbVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar15 >> 8) + pbVar15[2],(char)pbVar15);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar18 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar16 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  uVar14 = uVar16 - 1;
  bVar8 = (byte)in_EDX;
  if ((int)uVar14 < 0) {
    *(byte *)(uVar14 * 2) = *(byte *)(uVar14 * 2) | bVar8;
    pcVar23 = (char *)(uVar14 + (int)in_EDX * 8);
    *pcVar23 = *pcVar23 + (char)uVar14;
  }
  uVar14 = uVar14 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar14 >> 8) + *(char *)(uVar16 + 1),(char)uVar14);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar14 + 4) + (uint)((uVar19 & 1) != 0) + iVar18 + uVar24 + 5;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar14 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar9 = (char)puVar12 + 8;
  uVar19 = (uint)puVar12 & 0xffffff00;
  pbVar15 = (byte *)(uVar19 | (uint)bVar9);
  if ((int)(puVar3 + (uVar16 - 1)) < 0) {
    *pbVar15 = *pbVar15 | (byte)(uVar19 >> 8);
    *pbVar15 = *pbVar15 + bVar9;
    pbVar15 = (byte *)(uVar19 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar14 = (uint)pbVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar15 >> 8) + pbVar15[2],(char)pbVar15);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar19 = (uint)((uVar19 & 1) != 0);
  iVar18 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar14 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar9 = (char)puVar12 + 8;
  uVar14 = (uint)puVar12 & 0xffffff00 | (uint)bVar9;
  *(uint *)(puVar3 + iVar18 + (uVar16 - 1) + (uVar19 - 4)) = uVar14;
  bVar25 = (byte)((uint)in_ECX >> 8);
  if ((char)bVar9 < 0) {
    *(byte *)(uVar14 * 2) = *(byte *)(uVar14 * 2) | bVar25;
    pcVar23 = (char *)(uVar14 + (int)in_EDX * 8);
    *pcVar23 = *pcVar23 + bVar9;
  }
  uVar17 = (uint)puVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),bVar9);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  puVar3 = puVar3 + iVar18 + (uVar16 - 1) + *(int *)(uVar17 + 4) + (uVar19 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar17 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar9 = (char)puVar12 + 8;
  pbVar15 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)bVar9);
  *(undefined **)(puVar3 + uVar14 + -4) = puVar3 + uVar14;
  if ((char)bVar9 < 0) {
    *pbVar15 = *pbVar15 | bVar6;
    *pbVar15 = *pbVar15 + bVar9;
    pbVar15 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar16 = (uint)pbVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar15 >> 8) + pbVar15[2],(char)pbVar15);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar19 = (uint)((uVar19 & 1) != 0);
  iVar18 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar16 = *(uint *)(puVar3 + iVar18 + uVar14 + -4 + uVar19);
  if ((char)((char)puVar12 + '\b') < 0) {
    pbVar15 = (byte *)(uVar16 * 2 + -0x2ffc0000);
    *pbVar15 = *pbVar15 | (byte)uVar16;
  }
  uVar17 = uVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(byte)uVar16);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar21 = *(int *)(uVar17 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar17 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar9 = (char)puVar12 + 8;
  uVar17 = (uint)puVar12 & 0xffffff00 | (uint)bVar9;
  iVar28 = *(int *)(puVar3 + iVar18 + uVar14 + -4 + (uint)((uVar16 & 1) != 0) + iVar21 + uVar19 + 4)
  ;
  puVar29 = (undefined *)(iVar28 + 4);
  if (-1 < (char)bVar9) {
    uVar16 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar17 + 2),bVar9)
    ;
    uVar19 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar29 = (undefined *)(iVar28 + 4 + *(int *)(uVar16 + 4) + (uint)((uVar19 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar16 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar17 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar17 + 0x4000000) = *(byte *)(uVar17 + 0x4000000) | bVar8;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar29 + -4) = uVar17;
  *(int *)(puVar29 + -8) = in_ECX;
  *(byte **)(puVar29 + -0xc) = in_EDX;
  *(uint **)(puVar29 + -0x10) = unaff_EBX;
  *(undefined **)(puVar29 + -0x14) = puVar29;
  *(undefined4 **)(puVar29 + -0x18) = unaff_EBP;
  *(undefined **)(puVar29 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x20) = unaff_EDI;
  uVar19 = (uint)in_EDX & 0xffffff00 | (uint)(byte)(bVar8 + bVar10);
  iVar18 = uVar17 - *(int *)(uVar17 + 0x13);
  *(int *)(puVar29 + -0x24) = iVar18;
  *(int *)(puVar29 + -0x28) = in_ECX;
  *(uint *)(puVar29 + -0x2c) = uVar19;
  *(uint **)(puVar29 + -0x30) = unaff_EBX;
  *(undefined **)(puVar29 + -0x34) = puVar29 + -0x20;
  *(undefined4 **)(puVar29 + -0x38) = unaff_EBP;
  *(undefined **)(puVar29 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x40) = unaff_EDI;
  pbVar27 = (byte *)(uVar19 + in_ECX);
  pcVar23 = (char *)(iVar18 - *(int *)(iVar18 + 9));
  *pcVar23 = *pcVar23 + bVar6;
  pbVar15 = (byte *)(pcVar23 + in_ECX);
  *pbVar15 = *pbVar15 & (byte)pcVar23;
  bVar8 = *pbVar15;
  *(char **)(puVar29 + -0x44) = pcVar23;
  *(int *)(puVar29 + -0x48) = in_ECX;
  *(byte **)(puVar29 + -0x4c) = pbVar27;
  *(uint **)(puVar29 + -0x50) = unaff_EBX;
  *(undefined **)(puVar29 + -0x54) = puVar29 + -0x40;
  *(undefined4 **)(puVar29 + -0x58) = unaff_EBP;
  *(undefined **)(puVar29 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x60) = unaff_EDI;
  if ((char)bVar8 < 0) {
    pbVar15 = (byte *)((int)pcVar23 * 2 + -0x2ffc0000);
    *pbVar15 = *pbVar15 | bVar26;
  }
  uVar16 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(byte)pcVar23);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar19 = (uint)((uVar19 & 1) != 0);
  iVar18 = *(int *)(uVar16 + 4);
  puVar30 = puVar29 + iVar18 + -0x60 + uVar19;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar16 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
  if (-1 < (char)bVar8) {
    uVar14 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar16 + 2),bVar8)
    ;
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = puVar29 + iVar18 + -0x60 + (uint)((uVar16 & 1) != 0) + *(int *)(uVar14 + 4) + uVar19;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar14 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar16 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar16 + 0x4000000) = *(byte *)(uVar16 + 0x4000000) | bVar25;
  *pbVar27 = *pbVar27 << 1 | (char)*pbVar27 < 0;
  *(uint *)(puVar30 + -4) = uVar16;
  *(int *)(puVar30 + -8) = in_ECX;
  *(byte **)(puVar30 + -0xc) = pbVar27;
  *(uint **)(puVar30 + -0x10) = unaff_EBX;
  *(undefined **)(puVar30 + -0x14) = puVar30;
  *(undefined4 **)(puVar30 + -0x18) = unaff_EBP;
  *(undefined **)(puVar30 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x20) = unaff_EDI;
  uVar14 = (uint)pbVar27 & 0xffffff00 | (uint)(byte)((char)pbVar27 + bVar10);
  iVar18 = uVar16 - *(int *)(uVar16 + 0x13);
  *(int *)(puVar30 + -0x24) = iVar18;
  *(int *)(puVar30 + -0x28) = in_ECX;
  *(uint *)(puVar30 + -0x2c) = uVar14;
  *(uint **)(puVar30 + -0x30) = unaff_EBX;
  *(undefined **)(puVar30 + -0x34) = puVar30 + -0x20;
  *(undefined4 **)(puVar30 + -0x38) = unaff_EBP;
  *(undefined **)(puVar30 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x40) = unaff_EDI;
  uVar14 = uVar14 + in_ECX;
  pcVar23 = (char *)(iVar18 - *(int *)(iVar18 + 9));
  *pcVar23 = *pcVar23 + bVar6;
  bVar8 = (byte)pcVar23;
  pcVar23[in_ECX] = pcVar23[in_ECX] & bVar8;
  *(undefined4 *)(puVar30 + -0x44) = 0xb4080779;
  *pcVar23 = *pcVar23 + bVar8;
  pcVar23[uVar14 * 8] = pcVar23[uVar14 * 8] + bVar8;
  uVar16 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],bVar8);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar18 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
  puVar3 = unaff_EDI + 1;
  uVar1 = in((short)uVar14);
  *unaff_EDI = uVar1;
  if ((char)bVar8 < 0) {
    pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
    *pcVar23 = *pcVar23 + bVar8;
    pcVar23[uVar14 * 8] = pcVar23[uVar14 * 8] + bVar8;
  }
  uVar17 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar4 = puVar30 + *(int *)(uVar17 + 4) + (uint)((uVar19 & 1) != 0) + iVar18 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar17 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar19 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
  cVar7 = (char)uVar14;
  if (SCARRY1((char)puVar12,'\b')) {
    *(uint *)(puVar4 + (uVar16 - 4)) = uVar19;
    *(int *)(puVar4 + (uVar16 - 8)) = in_ECX;
    *(uint *)(puVar4 + (uVar16 - 0xc)) = uVar14;
    *(uint **)(puVar4 + (uVar16 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar16)) = puVar4 + uVar16;
    *(undefined4 **)(puVar4 + (uVar16 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar16 - 0x1c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar16 - 0x20)) = puVar3;
    uVar14 = uVar14 & 0xffffff00 | (uint)(byte)(cVar7 + bVar10);
    iVar18 = uVar19 - *(int *)(uVar19 + 0x13);
    *(int *)(puVar4 + (uVar16 - 0x24)) = iVar18;
    *(int *)(puVar4 + (uVar16 - 0x28)) = in_ECX;
    *(uint *)(puVar4 + (uVar16 - 0x2c)) = uVar14;
    *(uint **)(puVar4 + (uVar16 - 0x30)) = unaff_EBX;
    *(undefined **)(puVar4 + (uVar16 - 0x34)) = puVar4 + (uVar16 - 0x20);
    *(undefined4 **)(puVar4 + (uVar16 - 0x38)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar16 - 0x3c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar16 - 0x40)) = puVar3;
    uVar14 = uVar14 + in_ECX;
    piVar20 = (int *)(iVar18 - *(int *)(iVar18 + 9));
    *(byte *)piVar20 = *(byte *)piVar20 + bVar6;
    *(byte *)((int)piVar20 + in_ECX) = *(byte *)((int)piVar20 + in_ECX) & (byte)piVar20;
  }
  else {
    uVar19 = (uint)CONCAT11((byte)(((uint)puVar12 & 0xffffff00) >> 8) | bVar10,bVar8);
    pcVar23 = (char *)((uint)puVar12 & 0xffff0000 | uVar19);
    *pcVar23 = *pcVar23 + bVar8;
    pcVar23[uVar14 * 8] = pcVar23[uVar14 * 8] + bVar8;
    uVar17 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11((char)(uVar19 >> 8) + pcVar23[2],bVar8);
    uVar19 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar19 = (uint)((uVar19 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar17 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar17 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar16 = (uint)puVar12 & 0xffffff00;
    uVar17 = uVar16 | (uint)bVar8;
    if (bVar8 == 0) {
      *(uint *)(puVar4 + (uVar19 - 4)) = uVar17;
      *(int *)(puVar4 + (uVar19 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar19 - 0xc)) = uVar14;
      *(uint **)(puVar4 + (uVar19 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar19)) = puVar4 + uVar19;
      *(undefined4 **)(puVar4 + (uVar19 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar19 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar19 - 0x20)) = puVar3;
      iVar18 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar4 + (uVar19 - 0x24)) = iVar18;
      *(int *)(puVar4 + (uVar19 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar19 - 0x2c)) = uVar14 & 0xffffff00 | (uint)(byte)(cVar7 + bVar10);
      *(uint **)(puVar4 + (uVar19 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar19 - 0x34)) = puVar4 + (uVar19 - 0x20);
      *(undefined4 **)(puVar4 + (uVar19 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar19 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar19 - 0x40)) = puVar3;
      bVar26 = cVar7 + bVar10 + bVar10;
      pcVar23 = (char *)(iVar18 - *(int *)(iVar18 + 9));
      *pcVar23 = *pcVar23 + bVar6;
      pcVar23[in_ECX] = pcVar23[in_ECX] & (byte)pcVar23;
      goto code_r0x080422ec;
    }
    bVar8 = bVar8 | bVar26;
    pcVar23 = (char *)(uVar16 | (uint)bVar8);
    *pcVar23 = *pcVar23 + bVar8;
    pcVar23[uVar14 * 8] = pcVar23[uVar14 * 8] + bVar8;
    uVar17 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11((char)(uVar16 >> 8) + pcVar23[2],bVar8);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar16 = (uint)((uVar16 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar17 + 4) + uVar19 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar17 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar19 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if ((char)bVar8 < 0) {
      *(uint *)(puVar4 + (uVar16 - 4)) = uVar19;
      *(int *)(puVar4 + (uVar16 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar16 - 0xc)) = uVar14;
      *(uint **)(puVar4 + (uVar16 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar16 - 0x14)) = puVar4 + uVar16;
      *(undefined4 **)(puVar4 + (uVar16 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar16 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar16 - 0x20)) = puVar3;
      iVar18 = uVar19 - *(int *)(uVar19 + 0x13);
      *(int *)(puVar4 + (uVar16 - 0x24)) = iVar18;
      *(int *)(puVar4 + (uVar16 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar16 - 0x2c)) = uVar14 & 0xffffff00 | (uint)(byte)(cVar7 + bVar10);
      *(uint **)(puVar4 + (uVar16 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar16 - 0x34)) = puVar4 + (uVar16 - 0x20);
      *(undefined4 **)(puVar4 + (uVar16 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar16 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar16 - 0x40)) = puVar3;
      pcVar23 = (char *)(iVar18 - *(int *)(iVar18 + 9));
      *pcVar23 = *pcVar23 + bVar6;
      pcVar23[in_ECX] = pcVar23[in_ECX] & (byte)pcVar23;
      return;
    }
    uVar19 = (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8),bVar8);
    pcVar23 = (char *)((uint)puVar12 & 0xffff0000 | uVar19);
    *pcVar23 = *pcVar23 + bVar8;
    pcVar23[uVar14 * 8] = pcVar23[uVar14 * 8] + bVar8;
    uVar17 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11((char)(uVar19 >> 8) + pcVar23[2],bVar8);
    uVar19 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar19 = (uint)((uVar19 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar17 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar17 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar16 = (uint)puVar12 & 0xffffff00;
    uVar17 = uVar16 | (uint)bVar8;
    if (SCARRY1((char)puVar12,'\b') != (char)bVar8 < 0) {
      *(uint *)(puVar4 + (uVar19 - 4)) = uVar17;
      *(int *)(puVar4 + (uVar19 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar19 - 0xc)) = uVar14;
      *(uint **)(puVar4 + (uVar19 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar19 - 0x14)) = puVar4 + uVar19;
      *(undefined4 **)(puVar4 + (uVar19 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar19 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar19 - 0x20)) = puVar3;
      uVar16 = uVar14 & 0xffffff00 | (uint)(byte)(cVar7 + bVar10);
      iVar18 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar4 + (uVar19 - 0x24)) = iVar18;
      *(int *)(puVar4 + (uVar19 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar19 - 0x2c)) = uVar16;
      *(uint **)(puVar4 + (uVar19 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar19 - 0x34)) = puVar4 + (uVar19 - 0x20);
      *(undefined4 **)(puVar4 + (uVar19 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar19 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar19 - 0x40)) = puVar3;
      pbVar27 = (byte *)(uVar16 + in_ECX);
      pcVar23 = (char *)(iVar18 - *(int *)(iVar18 + 9));
      *pcVar23 = *pcVar23 + bVar6;
      pbVar15 = (byte *)(pcVar23 + in_ECX);
      bVar8 = (byte)pcVar23;
      *pbVar15 = *pbVar15 & bVar8;
      if ((char)*pbVar15 < 0) {
        pcVar23[in_ECX] = pcVar23[in_ECX] | bVar25;
        *pcVar23 = *pcVar23 + bVar8;
        pcVar23 = (char *)((uint)pcVar23 & 0xffffff00 | (uint)(byte)(bVar8 - 0x30));
      }
      uVar14 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
      bVar33 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar16 = (uint)bVar33;
      puVar4 = puVar4 + *(int *)(uVar14 + 4) + (uVar19 - 0x40);
      cVar7 = (char)puVar4 + bVar33;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar14 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      if ((char)bVar8 < 0) {
        puVar4[uVar16] = puVar4[uVar16] | bVar6;
        *(undefined **)(puVar4 + uVar16) = puVar4 + *(int *)(puVar4 + uVar16) + uVar16;
        puVar4[(int)pbVar27 * 8 + uVar16] = puVar4[(int)pbVar27 * 8 + uVar16] + cVar7;
      }
      uVar16 = (uint)(puVar4 + uVar16) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar4 + uVar16) >> 8) + puVar4[uVar16 + 2],cVar7);
      uVar19 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar19 = (uint)((uVar19 & 1) != 0);
      iVar18 = ((uint)puVar12 & 0xffffff00 | (uint)bVar8) + *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      uVar11 = (ushort)puVar12 & 0xff00 | (ushort)bVar8;
      iVar21 = (int)(short)uVar11;
      if ((char)bVar8 < 0) {
        *(byte *)(in_ECX + iVar21) = *(byte *)(in_ECX + iVar21) | bVar8;
        pcVar23 = (char *)(iVar21 + (int)pbVar27 * 8);
        *pcVar23 = *pcVar23 + bVar8;
      }
      iVar22 = CONCAT22((short)uVar11 >> 0xf,
                        CONCAT11((char)((uint)iVar21 >> 8) + *(char *)(iVar21 + 2),bVar8));
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar22 + 4);
      uVar14 = (uint)((uVar16 & 1) != 0);
      uVar16 = *puVar12;
      iVar21 = iVar18 + uVar19 + *puVar12;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar22 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar9 = (byte)puVar12;
      bVar8 = bVar9 + 8;
      pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
      *(uint *)(iVar21 + uVar14 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar9,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar8 < 0) * 0x80 |
           (uint)(bVar8 == 0) * 0x40 |
           (uint)(((iVar18 + uVar19 & 0xfffffff) + (uVar16 & 0xfffffff) + uVar14 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar9) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if ((char)bVar8 < 0) {
        pcVar23[1] = pcVar23[1] | (byte)pbVar27;
        *pcVar23 = *pcVar23 + bVar8;
        pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)(bVar9 - 0x28));
      }
      uVar16 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
      uVar19 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar18 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = DAT_5c080779;
      piVar20 = (int *)((uint)puVar12 & 0xffffff00 | (uint)DAT_5c080779);
      *piVar20 = *piVar20 + (int)piVar20;
      *(byte *)(piVar20 + (int)pbVar27 * 2) = *(char *)(piVar20 + (int)pbVar27 * 2) + bVar8;
      uVar17 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)((int)piVar20 + 2),bVar8);
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar22 = *(int *)(uVar17 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar17 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
      _DAT_03ffffc1 = unaff_EDI + 2;
      *puVar3 = *unaff_ESI;
      if ((char)bVar8 < 0) {
        pcVar23[1] = pcVar23[1] | bVar25;
        *pcVar23 = *pcVar23 + bVar8;
        pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
      }
      uVar24 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar2 = *(int *)(uVar24 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar24 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      uVar24 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
      *(byte *)(in_ECX + uVar24) = *(byte *)(in_ECX + uVar24) | (byte)((uint)pbVar27 >> 8);
      pcVar23 = (char *)(uVar24 + (int)pbVar27 * 8);
      *pcVar23 = *pcVar23 + bVar8;
      uVar13 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar24 + 2),
                              bVar8);
      uVar24 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar24 = (uint)((uVar24 & 1) != 0);
      iVar18 = iVar21 + uVar14 + iVar18 + (uint)((uVar19 & 1) != 0) + iVar22 +
               (uint)((uVar16 & 1) != 0) + iVar2 + (uint)((uVar17 & 1) != 0) + -2 +
               *(int *)(uVar13 + 4);
      puVar31 = (undefined *)(iVar18 + uVar24);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_03ffffc5 = unaff_ESI + 2;
      uVar19 = (uint)puVar12 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (-1 < (char)((char)puVar12 + '\b')) {
        uVar16 = (uint)puVar12 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)(uVar19 + 2),unaff_ESI[1]);
        uVar19 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar31 = (undefined *)(iVar18 + uVar24 + *(int *)(uVar16 + 4) + (uint)((uVar19 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar12 = (uint *)(uVar16 + 2);
        *puVar12 = *puVar12 | (uint)puVar12;
        uVar19 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      }
      *(byte *)(uVar19 + 0x4000001) = *(byte *)(uVar19 + 0x4000001) | (byte)uVar19;
      *pbVar27 = *pbVar27 << 1 | (char)*pbVar27 < 0;
      *(uint *)(puVar31 + -4) = uVar19;
      *(int *)(puVar31 + -8) = in_ECX;
      *(byte **)(puVar31 + -0xc) = pbVar27;
      *(uint **)(puVar31 + -0x10) = unaff_EBX;
      *(undefined **)(puVar31 + -0x14) = puVar31;
      *(undefined4 **)(puVar31 + -0x18) = unaff_EBP;
      *(undefined **)(puVar31 + -0x1c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x20) = _DAT_03ffffc1;
      uVar16 = (uint)pbVar27 & 0xffffff00 | (uint)(byte)((byte)pbVar27 + bVar10);
      iVar18 = uVar19 - *(int *)(uVar19 + 0x13);
      *(int *)(puVar31 + -0x24) = iVar18;
      *(int *)(puVar31 + -0x28) = in_ECX;
      *(uint *)(puVar31 + -0x2c) = uVar16;
      *(uint **)(puVar31 + -0x30) = unaff_EBX;
      *(undefined **)(puVar31 + -0x34) = puVar31 + -0x20;
      *(undefined4 **)(puVar31 + -0x38) = unaff_EBP;
      *(undefined **)(puVar31 + -0x3c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x40) = _DAT_03ffffc1;
      pbVar27 = (byte *)(uVar16 + in_ECX);
      pcVar23 = (char *)(iVar18 - *(int *)(iVar18 + 9));
      *pcVar23 = *pcVar23 + bVar6;
      pcVar23[in_ECX] = pcVar23[in_ECX] & (byte)pcVar23;
      iVar18 = CONCAT31((int3)((uint)pcVar23 >> 8),0x79);
      pbVar15 = (byte *)(in_ECX + -0x2ffc0000 + iVar18);
      *pbVar15 = *pbVar15 | bVar10;
      uVar16 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + *(char *)(iVar18 + 2),0x79);
      uVar19 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar19 = (uint)((uVar19 & 1) != 0);
      puVar3 = puVar31 + *(int *)(uVar16 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      uVar16 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar12 + '\b');
      *(byte *)(uVar16 + 0x4000001) = *(byte *)(uVar16 + 0x4000001) | bVar26;
      *pbVar27 = *pbVar27 << 1 | (char)*pbVar27 < 0;
      *(uint *)(puVar3 + uVar19) = uVar16;
      *(int *)(puVar3 + (uVar19 - 4)) = in_ECX;
      *(byte **)(puVar3 + (uVar19 - 8)) = pbVar27;
      *(uint **)(puVar3 + (uVar19 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar19 - 0x10)) = puVar3 + uVar19 + 4;
      *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar19)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar19 - 0x18)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar19 - 0x1c)) = _DAT_03ffffc1;
      uVar14 = (uint)pbVar27 & 0xffffff00 | (uint)(byte)((char)pbVar27 + bVar10);
      iVar18 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar3 + (uVar19 - 0x20)) = iVar18;
      *(int *)(puVar3 + (uVar19 - 0x24)) = in_ECX;
      *(uint *)(puVar3 + (uVar19 - 0x28)) = uVar14;
      *(uint **)(puVar3 + (uVar19 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar19 - 0x30)) = puVar3 + (uVar19 - 0x1c);
      *(undefined4 **)(puVar3 + (uVar19 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar19 - 0x38)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar19 - 0x3c)) = _DAT_03ffffc1;
      _DAT_03fffff5 = (byte *)(uVar14 + in_ECX);
      pcVar23 = (char *)(iVar18 - *(int *)(iVar18 + 9));
      *pcVar23 = *pcVar23 + bVar6;
      pcVar23[in_ECX] = pcVar23[in_ECX] & (byte)pcVar23;
      _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
      (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      piVar20 = (int *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
      *piVar20 = *piVar20 + (int)piVar20;
      *(byte *)(piVar20 + (int)_DAT_03fffff5 * 2) =
           *(char *)(piVar20 + (int)_DAT_03fffff5 * 2) + bVar8;
      cVar7 = *(char *)((int)piVar20 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + cVar7,bVar8)) +
                        2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_03fffffd = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      *(char *)(in_ECX + 7) = *(char *)(in_ECX + 7) >> 8;
      *_DAT_03fffff5 = *_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
      _DAT_03ffffed = 0x4000001;
      _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar10);
      _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
      _DAT_03ffffcd = &DAT_03ffffe1;
      iVar18 = _DAT_03ffffd5 + in_ECX;
      pcVar23 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
      _DAT_03ffffc9 = unaff_EBP;
      _DAT_03ffffd1 = unaff_EBX;
      _DAT_03ffffd9 = in_ECX;
      _DAT_03ffffe1 = _DAT_03ffffc1;
      _DAT_03ffffe5 = _DAT_03ffffc5;
      _DAT_03ffffe9 = unaff_EBP;
      _DAT_03fffff1 = unaff_EBX;
      _DAT_03fffff9 = in_ECX;
      *pcVar23 = *pcVar23 + bVar6;
      pcVar23[in_ECX] = pcVar23[in_ECX] & (byte)pcVar23;
      bVar10 = (byte)pcVar23 | bVar10;
      piVar20 = (int *)((uint)pcVar23 & 0xffffff00 | (uint)bVar10);
      *piVar20 = *piVar20 + (int)piVar20;
      *(byte *)(piVar20 + iVar18 * 2) = *(char *)(piVar20 + iVar18 * 2) + bVar10;
      uVar16 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar23 & 0xffffff00) >> 8) +
                              *(char *)((int)piVar20 + 2),bVar10);
      uVar19 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar19 = (uint)((uVar19 & 1) != 0);
      iVar18 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      puVar32 = (undefined4 *)(iVar18 + uVar19 + 0x3ffffbd);
      *(undefined4 **)(iVar18 + uVar19 + 0x3ffffbd) = unaff_EBP;
      cVar7 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar32 = puVar32 + -1;
        *puVar32 = *unaff_EBP;
        cVar7 = cVar7 + -1;
      } while (0 < cVar7);
      *(uint *)(iVar18 + uVar19 + 0x3ffff9d) = iVar18 + uVar19 + 0x3ffffbd;
      uVar16 = (uint)CONCAT11(bVar6 / 1,bVar6) & 0xffffff00;
      uVar19 = (uint)puVar12 & 0xffff0000 | uVar16;
      pcVar23 = (char *)(uVar19 | (uint)bVar6 & 0xffffff01);
      cVar7 = (char)((uint)bVar6 & 0xffffff01);
      *pcVar23 = *pcVar23 + cVar7;
      bVar6 = cVar7 - 0x30;
      cVar7 = *(char *)((uVar19 | (uint)bVar6) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar16 >> 8) + cVar7,bVar6)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      pcVar5 = (code *)swi(3);
      iVar18 = (*pcVar5)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
      return iVar18;
    }
    bVar8 = bVar8 | (byte)(uVar14 >> 8);
    pcVar23 = (char *)(uVar16 | (uint)bVar8);
    *pcVar23 = *pcVar23 + bVar8;
    pcVar23[uVar14 * 8] = pcVar23[uVar14 * 8] + bVar8;
    cVar7 = pcVar23[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                       (uint)CONCAT11((char)(uVar16 >> 8) + cVar7,bVar8)) + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
    *pcVar23 = *pcVar23 + bVar8;
    pcVar23[uVar14 * 8] = pcVar23[uVar14 * 8] + bVar8;
    cVar7 = pcVar23[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                       (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + cVar7,bVar8)) + 2)
    ;
    *puVar12 = *puVar12 | (uint)puVar12;
    piVar20 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
  }
  bVar26 = (byte)uVar14;
  *(byte *)piVar20 = *(byte *)piVar20 | bVar10;
  *piVar20 = *piVar20 + (int)piVar20;
  *(byte *)(piVar20 + uVar14 * 2) = *(byte *)(piVar20 + uVar14 * 2) + (char)piVar20;
  bVar8 = *(byte *)((int)piVar20 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(((uint)piVar20 & 0xffff0000 |
                     (uint)CONCAT11((char)((uint)piVar20 >> 8) + bVar8,(char)piVar20)) + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
code_r0x080422ec:
  *(byte *)(in_ECX + 7) = bVar6;
  pcVar23[in_ECX] = pcVar23[in_ECX] | bVar26;
  *pcVar23 = *pcVar23 + (char)pcVar23;
  bVar6 = (char)pcVar23 - 0x30;
  cVar7 = *(char *)(((uint)pcVar23 & 0xffffff00 | (uint)bVar6) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(((uint)pcVar23 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar23 & 0xffffff00) >> 8) + cVar7,bVar6)) + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_attr_destroy(pthread_attr_t *__attr)

{
  undefined uVar1;
  int iVar2;
  undefined *puVar3;
  undefined *puVar4;
  code *pcVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  char cVar11;
  ushort uVar12;
  uint *puVar13;
  uint uVar14;
  byte *pbVar15;
  uint uVar16;
  int iVar17;
  uint uVar18;
  int *piVar19;
  int iVar20;
  int iVar21;
  char *pcVar22;
  uint uVar23;
  uint uVar24;
  byte bVar25;
  int in_ECX;
  byte *in_EDX;
  byte *pbVar26;
  uint uVar27;
  uint *unaff_EBX;
  int iVar28;
  undefined *puVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined4 *puVar32;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar33;
  byte in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack6 [4];
  undefined auStack2 [2];
  
  bVar6 = (char)__attr - 0x30;
  uVar16 = (uint)__attr & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__attr & 0xffffff00) >> 8) +
                          *(char *)(((uint)__attr & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar16 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  bVar6 = (char)puVar13 + 8;
  pbVar15 = (byte *)((uint)puVar13 & 0xffffff00 | (uint)bVar6);
  *pbVar15 = *pbVar15 | (byte)((uint)in_EDX >> 8);
  *pbVar15 = *pbVar15 + bVar6;
  pbVar15[(int)in_EDX * 8] = pbVar15[(int)in_EDX * 8] + bVar6;
  uVar27 = (uint)puVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + pbVar15[2],bVar6);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar20 = *(int *)(uVar27 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar27 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  pcVar22 = (char *)(((uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8)) + 1);
  bVar6 = (byte)((uint)unaff_EBX >> 8);
  if ((int)pcVar22 < 0) {
    *(byte *)((int)pcVar22 * 2) = *(byte *)((int)pcVar22 * 2) | bVar6;
    *pcVar22 = *pcVar22 + (char)pcVar22;
    pcVar22 = (char *)((uint)pcVar22 & 0xffffff00 | (uint)(byte)((char)pcVar22 - 0x30));
  }
  uVar14 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
  uVar27 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar27 = (uint)((uVar27 & 1) != 0);
  puVar3 = &stack0x00000000 +
           *(int *)(uVar14 + 4) +
           (uint)((uVar16 & 1) != 0) + iVar20 + (uint)((uVar18 & 1) != 0) + iVar17;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar14 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  bVar7 = (char)puVar13 + 8;
  pbVar15 = (byte *)((uint)puVar13 & 0xffffff00 | (uint)bVar7);
  bVar10 = (byte)in_ECX;
  if ((int)(puVar3 + uVar27 + 3) < 0) {
    *pbVar15 = *pbVar15 | bVar10;
    *pbVar15 = *pbVar15 + bVar7;
    pbVar15 = (byte *)((uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 - 0x28));
  }
  uVar16 = (uint)pbVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar15 >> 8) + pbVar15[2],(char)pbVar15);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar16 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  uVar16 = (uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8);
  uVar14 = uVar16 - 1;
  bVar7 = (byte)in_EDX;
  if ((int)uVar14 < 0) {
    *(byte *)(uVar14 * 2) = *(byte *)(uVar14 * 2) | bVar7;
    pcVar22 = (char *)(uVar14 + (int)in_EDX * 8);
    *pcVar22 = *pcVar22 + (char)uVar14;
  }
  uVar14 = uVar14 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar14 >> 8) + *(char *)(uVar16 + 1),(char)uVar14);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar14 + 4) + (uint)((uVar18 & 1) != 0) + iVar17 + uVar27 + 3;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar14 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  bVar8 = (char)puVar13 + 8;
  uVar18 = (uint)puVar13 & 0xffffff00;
  pbVar15 = (byte *)(uVar18 | (uint)bVar8);
  if ((int)(puVar3 + (uVar16 - 1)) < 0) {
    *pbVar15 = *pbVar15 | (byte)(uVar18 >> 8);
    *pbVar15 = *pbVar15 + bVar8;
    pbVar15 = (byte *)(uVar18 | (uint)(byte)((char)puVar13 - 0x28));
  }
  uVar27 = (uint)pbVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar15 >> 8) + pbVar15[2],(char)pbVar15);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = *(int *)(uVar27 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar27 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  bVar8 = (char)puVar13 + 8;
  uVar27 = (uint)puVar13 & 0xffffff00 | (uint)bVar8;
  *(uint *)(puVar3 + iVar17 + (uVar16 - 1) + (uVar18 - 4)) = uVar27;
  bVar25 = (byte)((uint)in_ECX >> 8);
  if ((char)bVar8 < 0) {
    *(byte *)(uVar27 * 2) = *(byte *)(uVar27 * 2) | bVar25;
    pcVar22 = (char *)(uVar27 + (int)in_EDX * 8);
    *pcVar22 = *pcVar22 + bVar8;
  }
  uVar14 = (uint)puVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + *(char *)(uVar27 + 2),bVar8);
  uVar27 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar27 = (uint)((uVar27 & 1) != 0);
  puVar3 = puVar3 + iVar17 + (uVar16 - 1) + *(int *)(uVar14 + 4) + (uVar18 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar14 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  bVar8 = (char)puVar13 + 8;
  pbVar15 = (byte *)((uint)puVar13 & 0xffffff00 | (uint)bVar8);
  *(undefined **)(puVar3 + uVar27 + -4) = puVar3 + uVar27;
  if ((char)bVar8 < 0) {
    *pbVar15 = *pbVar15 | bVar6;
    *pbVar15 = *pbVar15 + bVar8;
    pbVar15 = (byte *)((uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 - 0x28));
  }
  uVar16 = (uint)pbVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar15 >> 8) + pbVar15[2],(char)pbVar15);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar16 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  uVar16 = *(uint *)(puVar3 + iVar17 + uVar27 + -4 + uVar18);
  if ((char)((char)puVar13 + '\b') < 0) {
    pbVar15 = (byte *)(uVar16 * 2 + -0x2ffc0000);
    *pbVar15 = *pbVar15 | (byte)uVar16;
  }
  uVar14 = uVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(byte)uVar16);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar20 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar14 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  bVar8 = (char)puVar13 + 8;
  uVar14 = (uint)puVar13 & 0xffffff00 | (uint)bVar8;
  iVar28 = *(int *)(puVar3 + iVar17 + uVar27 + -4 + (uint)((uVar16 & 1) != 0) + iVar20 + uVar18 + 4)
  ;
  puVar29 = (undefined *)(iVar28 + 4);
  if (-1 < (char)bVar8) {
    uVar16 = (uint)puVar13 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),bVar8)
    ;
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar29 = (undefined *)(iVar28 + 4 + *(int *)(uVar16 + 4) + (uint)((uVar18 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar13 = (uint *)(uVar16 + 2);
    *puVar13 = *puVar13 | (uint)puVar13;
    uVar14 = (uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8);
  }
  *(byte *)(uVar14 + 0x4000000) = *(byte *)(uVar14 + 0x4000000) | bVar7;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar29 + -4) = uVar14;
  *(int *)(puVar29 + -8) = in_ECX;
  *(byte **)(puVar29 + -0xc) = in_EDX;
  *(uint **)(puVar29 + -0x10) = unaff_EBX;
  *(undefined **)(puVar29 + -0x14) = puVar29;
  *(undefined4 **)(puVar29 + -0x18) = unaff_EBP;
  *(undefined **)(puVar29 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x20) = unaff_EDI;
  uVar18 = (uint)in_EDX & 0xffffff00 | (uint)(byte)(bVar7 + bVar10);
  iVar17 = uVar14 - *(int *)(uVar14 + 0x13);
  *(int *)(puVar29 + -0x24) = iVar17;
  *(int *)(puVar29 + -0x28) = in_ECX;
  *(uint *)(puVar29 + -0x2c) = uVar18;
  *(uint **)(puVar29 + -0x30) = unaff_EBX;
  *(undefined **)(puVar29 + -0x34) = puVar29 + -0x20;
  *(undefined4 **)(puVar29 + -0x38) = unaff_EBP;
  *(undefined **)(puVar29 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x40) = unaff_EDI;
  pbVar26 = (byte *)(uVar18 + in_ECX);
  pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
  *pcVar22 = *pcVar22 + bVar6;
  pbVar15 = (byte *)(pcVar22 + in_ECX);
  *pbVar15 = *pbVar15 & (byte)pcVar22;
  bVar7 = *pbVar15;
  *(char **)(puVar29 + -0x44) = pcVar22;
  *(int *)(puVar29 + -0x48) = in_ECX;
  *(byte **)(puVar29 + -0x4c) = pbVar26;
  *(uint **)(puVar29 + -0x50) = unaff_EBX;
  *(undefined **)(puVar29 + -0x54) = puVar29 + -0x40;
  *(undefined4 **)(puVar29 + -0x58) = unaff_EBP;
  *(undefined **)(puVar29 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x60) = unaff_EDI;
  bVar8 = (byte)unaff_EBX;
  if ((char)bVar7 < 0) {
    pbVar15 = (byte *)((int)pcVar22 * 2 + -0x2ffc0000);
    *pbVar15 = *pbVar15 | bVar8;
  }
  uVar16 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(byte)pcVar22);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = *(int *)(uVar16 + 4);
  puVar30 = puVar29 + iVar17 + -0x60 + uVar18;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar16 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  bVar7 = (char)puVar13 + 8;
  uVar16 = (uint)puVar13 & 0xffffff00 | (uint)bVar7;
  if (-1 < (char)bVar7) {
    uVar27 = (uint)puVar13 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + *(char *)(uVar16 + 2),bVar7)
    ;
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = puVar29 + iVar17 + -0x60 + (uint)((uVar16 & 1) != 0) + *(int *)(uVar27 + 4) + uVar18;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar13 = (uint *)(uVar27 + 2);
    *puVar13 = *puVar13 | (uint)puVar13;
    uVar16 = (uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8);
  }
  *(byte *)(uVar16 + 0x4000000) = *(byte *)(uVar16 + 0x4000000) | bVar25;
  *pbVar26 = *pbVar26 << 1 | (char)*pbVar26 < 0;
  *(uint *)(puVar30 + -4) = uVar16;
  *(int *)(puVar30 + -8) = in_ECX;
  *(byte **)(puVar30 + -0xc) = pbVar26;
  *(uint **)(puVar30 + -0x10) = unaff_EBX;
  *(undefined **)(puVar30 + -0x14) = puVar30;
  *(undefined4 **)(puVar30 + -0x18) = unaff_EBP;
  *(undefined **)(puVar30 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x20) = unaff_EDI;
  uVar27 = (uint)pbVar26 & 0xffffff00 | (uint)(byte)((char)pbVar26 + bVar10);
  iVar17 = uVar16 - *(int *)(uVar16 + 0x13);
  *(int *)(puVar30 + -0x24) = iVar17;
  *(int *)(puVar30 + -0x28) = in_ECX;
  *(uint *)(puVar30 + -0x2c) = uVar27;
  *(uint **)(puVar30 + -0x30) = unaff_EBX;
  *(undefined **)(puVar30 + -0x34) = puVar30 + -0x20;
  *(undefined4 **)(puVar30 + -0x38) = unaff_EBP;
  *(undefined **)(puVar30 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x40) = unaff_EDI;
  uVar27 = uVar27 + in_ECX;
  pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
  *pcVar22 = *pcVar22 + bVar6;
  bVar7 = (byte)pcVar22;
  pcVar22[in_ECX] = pcVar22[in_ECX] & bVar7;
  *(undefined4 *)(puVar30 + -0x44) = 0xb4080779;
  *pcVar22 = *pcVar22 + bVar7;
  pcVar22[uVar27 * 8] = pcVar22[uVar27 * 8] + bVar7;
  uVar16 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],bVar7);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar16 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  bVar7 = (char)puVar13 + 8;
  pcVar22 = (char *)((uint)puVar13 & 0xffffff00 | (uint)bVar7);
  puVar3 = unaff_EDI + 1;
  uVar1 = in((short)uVar27);
  *unaff_EDI = uVar1;
  if ((char)bVar7 < 0) {
    pcVar22 = (char *)((uint)puVar13 & 0xffffff00 | (uint)bVar7);
    *pcVar22 = *pcVar22 + bVar7;
    pcVar22[uVar27 * 8] = pcVar22[uVar27 * 8] + bVar7;
  }
  uVar14 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar4 = puVar30 + *(int *)(uVar14 + 4) + (uint)((uVar18 & 1) != 0) + iVar17 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(uVar14 + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  bVar7 = (char)puVar13 + 8;
  uVar18 = (uint)puVar13 & 0xffffff00 | (uint)bVar7;
  cVar11 = (char)uVar27;
  if (SCARRY1((char)puVar13,'\b')) {
    *(uint *)(puVar4 + (uVar16 - 4)) = uVar18;
    *(int *)(puVar4 + (uVar16 - 8)) = in_ECX;
    *(uint *)(puVar4 + (uVar16 - 0xc)) = uVar27;
    *(uint **)(puVar4 + (uVar16 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar16)) = puVar4 + uVar16;
    *(undefined4 **)(puVar4 + (uVar16 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar16 - 0x1c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar16 - 0x20)) = puVar3;
    uVar27 = uVar27 & 0xffffff00 | (uint)(byte)(cVar11 + bVar10);
    iVar17 = uVar18 - *(int *)(uVar18 + 0x13);
    *(int *)(puVar4 + (uVar16 - 0x24)) = iVar17;
    *(int *)(puVar4 + (uVar16 - 0x28)) = in_ECX;
    *(uint *)(puVar4 + (uVar16 - 0x2c)) = uVar27;
    *(uint **)(puVar4 + (uVar16 - 0x30)) = unaff_EBX;
    *(undefined **)(puVar4 + (uVar16 - 0x34)) = puVar4 + (uVar16 - 0x20);
    *(undefined4 **)(puVar4 + (uVar16 - 0x38)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar16 - 0x3c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar16 - 0x40)) = puVar3;
    uVar27 = uVar27 + in_ECX;
    piVar19 = (int *)(iVar17 - *(int *)(iVar17 + 9));
    *(byte *)piVar19 = *(byte *)piVar19 + bVar6;
    *(byte *)((int)piVar19 + in_ECX) = *(byte *)((int)piVar19 + in_ECX) & (byte)piVar19;
  }
  else {
    uVar18 = (uint)CONCAT11((byte)(((uint)puVar13 & 0xffffff00) >> 8) | bVar10,bVar7);
    pcVar22 = (char *)((uint)puVar13 & 0xffff0000 | uVar18);
    *pcVar22 = *pcVar22 + bVar7;
    pcVar22[uVar27 * 8] = pcVar22[uVar27 * 8] + bVar7;
    uVar14 = (uint)puVar13 & 0xffff0000 | (uint)CONCAT11((char)(uVar18 >> 8) + pcVar22[2],bVar7);
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar18 = (uint)((uVar18 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar14 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar13 = (uint *)(uVar14 + 2);
    *puVar13 = *puVar13 | (uint)puVar13;
    bVar7 = (char)puVar13 + 8;
    uVar16 = (uint)puVar13 & 0xffffff00;
    uVar14 = uVar16 | (uint)bVar7;
    if (bVar7 == 0) {
      *(uint *)(puVar4 + (uVar18 - 4)) = uVar14;
      *(int *)(puVar4 + (uVar18 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar18 - 0xc)) = uVar27;
      *(uint **)(puVar4 + (uVar18 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar18)) = puVar4 + uVar18;
      *(undefined4 **)(puVar4 + (uVar18 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar18 - 0x20)) = puVar3;
      iVar17 = uVar14 - *(int *)(uVar14 + 0x13);
      *(int *)(puVar4 + (uVar18 - 0x24)) = iVar17;
      *(int *)(puVar4 + (uVar18 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar18 - 0x2c)) = uVar27 & 0xffffff00 | (uint)(byte)(cVar11 + bVar10);
      *(uint **)(puVar4 + (uVar18 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar18 - 0x34)) = puVar4 + (uVar18 - 0x20);
      *(undefined4 **)(puVar4 + (uVar18 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar18 - 0x40)) = puVar3;
      bVar8 = cVar11 + bVar10 + bVar10;
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + bVar6;
      pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
      goto code_r0x080422ec;
    }
    bVar7 = bVar7 | bVar8;
    pcVar22 = (char *)(uVar16 | (uint)bVar7);
    *pcVar22 = *pcVar22 + bVar7;
    pcVar22[uVar27 * 8] = pcVar22[uVar27 * 8] + bVar7;
    uVar14 = (uint)puVar13 & 0xffff0000 | (uint)CONCAT11((char)(uVar16 >> 8) + pcVar22[2],bVar7);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar16 = (uint)((uVar16 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar14 + 4) + uVar18 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar13 = (uint *)(uVar14 + 2);
    *puVar13 = *puVar13 | (uint)puVar13;
    bVar7 = (char)puVar13 + 8;
    uVar18 = (uint)puVar13 & 0xffffff00 | (uint)bVar7;
    if ((char)bVar7 < 0) {
      *(uint *)(puVar4 + (uVar16 - 4)) = uVar18;
      *(int *)(puVar4 + (uVar16 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar16 - 0xc)) = uVar27;
      *(uint **)(puVar4 + (uVar16 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar16 - 0x14)) = puVar4 + uVar16;
      *(undefined4 **)(puVar4 + (uVar16 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar16 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar16 - 0x20)) = puVar3;
      iVar17 = uVar18 - *(int *)(uVar18 + 0x13);
      *(int *)(puVar4 + (uVar16 - 0x24)) = iVar17;
      *(int *)(puVar4 + (uVar16 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar16 - 0x2c)) = uVar27 & 0xffffff00 | (uint)(byte)(cVar11 + bVar10);
      *(uint **)(puVar4 + (uVar16 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar16 - 0x34)) = puVar4 + (uVar16 - 0x20);
      *(undefined4 **)(puVar4 + (uVar16 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar16 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar16 - 0x40)) = puVar3;
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + bVar6;
      pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
      return;
    }
    uVar18 = (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8),bVar7);
    pcVar22 = (char *)((uint)puVar13 & 0xffff0000 | uVar18);
    *pcVar22 = *pcVar22 + bVar7;
    pcVar22[uVar27 * 8] = pcVar22[uVar27 * 8] + bVar7;
    uVar14 = (uint)puVar13 & 0xffff0000 | (uint)CONCAT11((char)(uVar18 >> 8) + pcVar22[2],bVar7);
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar18 = (uint)((uVar18 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar14 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar13 = (uint *)(uVar14 + 2);
    *puVar13 = *puVar13 | (uint)puVar13;
    bVar7 = (char)puVar13 + 8;
    uVar16 = (uint)puVar13 & 0xffffff00;
    uVar14 = uVar16 | (uint)bVar7;
    if (SCARRY1((char)puVar13,'\b') != (char)bVar7 < 0) {
      *(uint *)(puVar4 + (uVar18 - 4)) = uVar14;
      *(int *)(puVar4 + (uVar18 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar18 - 0xc)) = uVar27;
      *(uint **)(puVar4 + (uVar18 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar18 - 0x14)) = puVar4 + uVar18;
      *(undefined4 **)(puVar4 + (uVar18 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar18 - 0x20)) = puVar3;
      uVar16 = uVar27 & 0xffffff00 | (uint)(byte)(cVar11 + bVar10);
      iVar17 = uVar14 - *(int *)(uVar14 + 0x13);
      *(int *)(puVar4 + (uVar18 - 0x24)) = iVar17;
      *(int *)(puVar4 + (uVar18 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar18 - 0x2c)) = uVar16;
      *(uint **)(puVar4 + (uVar18 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar18 - 0x34)) = puVar4 + (uVar18 - 0x20);
      *(undefined4 **)(puVar4 + (uVar18 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar18 - 0x40)) = puVar3;
      pbVar26 = (byte *)(uVar16 + in_ECX);
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + bVar6;
      pbVar15 = (byte *)(pcVar22 + in_ECX);
      bVar7 = (byte)pcVar22;
      *pbVar15 = *pbVar15 & bVar7;
      if ((char)*pbVar15 < 0) {
        pcVar22[in_ECX] = pcVar22[in_ECX] | bVar25;
        *pcVar22 = *pcVar22 + bVar7;
        pcVar22 = (char *)((uint)pcVar22 & 0xffffff00 | (uint)(byte)(bVar7 - 0x30));
      }
      uVar27 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      bVar33 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar16 = (uint)bVar33;
      puVar4 = puVar4 + *(int *)(uVar27 + 4) + (uVar18 - 0x40);
      cVar11 = (char)puVar4 + bVar33;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(uVar27 + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      bVar7 = (char)puVar13 + 8;
      if ((char)bVar7 < 0) {
        puVar4[uVar16] = puVar4[uVar16] | bVar6;
        *(undefined **)(puVar4 + uVar16) = puVar4 + *(int *)(puVar4 + uVar16) + uVar16;
        puVar4[(int)pbVar26 * 8 + uVar16] = puVar4[(int)pbVar26 * 8 + uVar16] + cVar11;
      }
      uVar16 = (uint)(puVar4 + uVar16) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar4 + uVar16) >> 8) + puVar4[uVar16 + 2],cVar11);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      iVar17 = ((uint)puVar13 & 0xffffff00 | (uint)bVar7) + *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(uVar16 + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      bVar7 = (char)puVar13 + 8;
      uVar12 = (ushort)puVar13 & 0xff00 | (ushort)bVar7;
      iVar20 = (int)(short)uVar12;
      if ((char)bVar7 < 0) {
        *(byte *)(in_ECX + iVar20) = *(byte *)(in_ECX + iVar20) | bVar7;
        pcVar22 = (char *)(iVar20 + (int)pbVar26 * 8);
        *pcVar22 = *pcVar22 + bVar7;
      }
      iVar21 = CONCAT22((short)uVar12 >> 0xf,
                        CONCAT11((char)((uint)iVar20 >> 8) + *(char *)(iVar20 + 2),bVar7));
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(iVar21 + 4);
      uVar27 = (uint)((uVar16 & 1) != 0);
      uVar16 = *puVar13;
      iVar20 = iVar17 + uVar18 + *puVar13;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(iVar21 + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      bVar9 = (byte)puVar13;
      bVar7 = bVar9 + 8;
      pcVar22 = (char *)((uint)puVar13 & 0xffffff00 | (uint)bVar7);
      *(uint *)(iVar20 + uVar27 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar9,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar7 < 0) * 0x80 |
           (uint)(bVar7 == 0) * 0x40 |
           (uint)(((iVar17 + uVar18 & 0xfffffff) + (uVar16 & 0xfffffff) + uVar27 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar9) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if ((char)bVar7 < 0) {
        pcVar22[1] = pcVar22[1] | (byte)pbVar26;
        *pcVar22 = *pcVar22 + bVar7;
        pcVar22 = (char *)((uint)puVar13 & 0xffffff00 | (uint)(byte)(bVar9 - 0x28));
      }
      uVar16 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar17 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(uVar16 + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      bVar7 = DAT_5c080779;
      piVar19 = (int *)((uint)puVar13 & 0xffffff00 | (uint)DAT_5c080779);
      *piVar19 = *piVar19 + (int)piVar19;
      *(byte *)(piVar19 + (int)pbVar26 * 2) = *(char *)(piVar19 + (int)pbVar26 * 2) + bVar7;
      uVar14 = (uint)puVar13 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar13 >> 8) + *(char *)((int)piVar19 + 2),bVar7);
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar21 = *(int *)(uVar14 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(uVar14 + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      bVar7 = (char)puVar13 + 8;
      pcVar22 = (char *)((uint)puVar13 & 0xffffff00 | (uint)bVar7);
      _DAT_03ffffc1 = unaff_EDI + 2;
      *puVar3 = *unaff_ESI;
      if ((char)bVar7 < 0) {
        pcVar22[1] = pcVar22[1] | bVar25;
        *pcVar22 = *pcVar22 + bVar7;
        pcVar22 = (char *)((uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 - 0x28));
      }
      uVar23 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      uVar14 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar2 = *(int *)(uVar23 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(uVar23 + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      bVar7 = (char)puVar13 + 8;
      uVar23 = (uint)puVar13 & 0xffffff00 | (uint)bVar7;
      *(byte *)(in_ECX + uVar23) = *(byte *)(in_ECX + uVar23) | (byte)((uint)pbVar26 >> 8);
      pcVar22 = (char *)(uVar23 + (int)pbVar26 * 8);
      *pcVar22 = *pcVar22 + bVar7;
      uVar24 = (uint)puVar13 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + *(char *)(uVar23 + 2),
                              bVar7);
      uVar23 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar23 = (uint)((uVar23 & 1) != 0);
      iVar17 = iVar20 + uVar27 + iVar17 + (uint)((uVar18 & 1) != 0) + iVar21 +
               (uint)((uVar16 & 1) != 0) + iVar2 + (uint)((uVar14 & 1) != 0) + -2 +
               *(int *)(uVar24 + 4);
      puVar31 = (undefined *)(iVar17 + uVar23);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(uVar24 + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      _DAT_03ffffc5 = unaff_ESI + 2;
      uVar18 = (uint)puVar13 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (-1 < (char)((char)puVar13 + '\b')) {
        uVar16 = (uint)puVar13 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar13 >> 8) + *(char *)(uVar18 + 2),unaff_ESI[1]);
        uVar18 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar31 = (undefined *)(iVar17 + uVar23 + *(int *)(uVar16 + 4) + (uint)((uVar18 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar13 = (uint *)(uVar16 + 2);
        *puVar13 = *puVar13 | (uint)puVar13;
        uVar18 = (uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8);
      }
      *(byte *)(uVar18 + 0x4000001) = *(byte *)(uVar18 + 0x4000001) | (byte)uVar18;
      *pbVar26 = *pbVar26 << 1 | (char)*pbVar26 < 0;
      *(uint *)(puVar31 + -4) = uVar18;
      *(int *)(puVar31 + -8) = in_ECX;
      *(byte **)(puVar31 + -0xc) = pbVar26;
      *(uint **)(puVar31 + -0x10) = unaff_EBX;
      *(undefined **)(puVar31 + -0x14) = puVar31;
      *(undefined4 **)(puVar31 + -0x18) = unaff_EBP;
      *(undefined **)(puVar31 + -0x1c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x20) = _DAT_03ffffc1;
      uVar16 = (uint)pbVar26 & 0xffffff00 | (uint)(byte)((byte)pbVar26 + bVar10);
      iVar17 = uVar18 - *(int *)(uVar18 + 0x13);
      *(int *)(puVar31 + -0x24) = iVar17;
      *(int *)(puVar31 + -0x28) = in_ECX;
      *(uint *)(puVar31 + -0x2c) = uVar16;
      *(uint **)(puVar31 + -0x30) = unaff_EBX;
      *(undefined **)(puVar31 + -0x34) = puVar31 + -0x20;
      *(undefined4 **)(puVar31 + -0x38) = unaff_EBP;
      *(undefined **)(puVar31 + -0x3c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x40) = _DAT_03ffffc1;
      pbVar26 = (byte *)(uVar16 + in_ECX);
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + bVar6;
      pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
      iVar17 = CONCAT31((int3)((uint)pcVar22 >> 8),0x79);
      pbVar15 = (byte *)(in_ECX + -0x2ffc0000 + iVar17);
      *pbVar15 = *pbVar15 | bVar10;
      uVar16 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + *(char *)(iVar17 + 2),0x79);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      puVar3 = puVar31 + *(int *)(uVar16 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(uVar16 + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      uVar16 = (uint)puVar13 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar13 + '\b');
      *(byte *)(uVar16 + 0x4000001) = *(byte *)(uVar16 + 0x4000001) | bVar8;
      *pbVar26 = *pbVar26 << 1 | (char)*pbVar26 < 0;
      *(uint *)(puVar3 + uVar18) = uVar16;
      *(int *)(puVar3 + (uVar18 - 4)) = in_ECX;
      *(byte **)(puVar3 + (uVar18 - 8)) = pbVar26;
      *(uint **)(puVar3 + (uVar18 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar18 - 0x10)) = puVar3 + uVar18 + 4;
      *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar18)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar18 - 0x18)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar18 - 0x1c)) = _DAT_03ffffc1;
      uVar27 = (uint)pbVar26 & 0xffffff00 | (uint)(byte)((char)pbVar26 + bVar10);
      iVar17 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar3 + (uVar18 - 0x20)) = iVar17;
      *(int *)(puVar3 + (uVar18 - 0x24)) = in_ECX;
      *(uint *)(puVar3 + (uVar18 - 0x28)) = uVar27;
      *(uint **)(puVar3 + (uVar18 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar18 - 0x30)) = puVar3 + (uVar18 - 0x1c);
      *(undefined4 **)(puVar3 + (uVar18 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar18 - 0x38)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar18 - 0x3c)) = _DAT_03ffffc1;
      _DAT_03fffff5 = (byte *)(uVar27 + in_ECX);
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + bVar6;
      pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
      _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
      (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      bVar7 = (char)puVar13 + 8;
      piVar19 = (int *)((uint)puVar13 & 0xffffff00 | (uint)bVar7);
      *piVar19 = *piVar19 + (int)piVar19;
      *(byte *)(piVar19 + (int)_DAT_03fffff5 * 2) =
           *(char *)(piVar19 + (int)_DAT_03fffff5 * 2) + bVar7;
      cVar11 = *(char *)((int)piVar19 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(((uint)puVar13 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + cVar11,bVar7)) +
                        2);
      *puVar13 = *puVar13 | (uint)puVar13;
      _DAT_03fffffd = (uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8);
      *(char *)(in_ECX + 7) = *(char *)(in_ECX + 7) >> 8;
      *_DAT_03fffff5 = *_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
      _DAT_03ffffed = 0x4000001;
      _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar10);
      _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
      _DAT_03ffffcd = &DAT_03ffffe1;
      iVar17 = _DAT_03ffffd5 + in_ECX;
      pcVar22 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
      _DAT_03ffffc9 = unaff_EBP;
      _DAT_03ffffd1 = unaff_EBX;
      _DAT_03ffffd9 = in_ECX;
      _DAT_03ffffe1 = _DAT_03ffffc1;
      _DAT_03ffffe5 = _DAT_03ffffc5;
      _DAT_03ffffe9 = unaff_EBP;
      _DAT_03fffff1 = unaff_EBX;
      _DAT_03fffff9 = in_ECX;
      *pcVar22 = *pcVar22 + bVar6;
      pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
      bVar10 = (byte)pcVar22 | bVar10;
      piVar19 = (int *)((uint)pcVar22 & 0xffffff00 | (uint)bVar10);
      *piVar19 = *piVar19 + (int)piVar19;
      *(byte *)(piVar19 + iVar17 * 2) = *(char *)(piVar19 + iVar17 * 2) + bVar10;
      uVar16 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar22 & 0xffffff00) >> 8) +
                              *(char *)((int)piVar19 + 2),bVar10);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      iVar17 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(uVar16 + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      bVar6 = (char)puVar13 + 8;
      puVar32 = (undefined4 *)(iVar17 + uVar18 + 0x3ffffbd);
      *(undefined4 **)(iVar17 + uVar18 + 0x3ffffbd) = unaff_EBP;
      cVar11 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar32 = puVar32 + -1;
        *puVar32 = *unaff_EBP;
        cVar11 = cVar11 + -1;
      } while (0 < cVar11);
      *(uint *)(iVar17 + uVar18 + 0x3ffff9d) = iVar17 + uVar18 + 0x3ffffbd;
      uVar16 = (uint)CONCAT11(bVar6 / 1,bVar6) & 0xffffff00;
      uVar18 = (uint)puVar13 & 0xffff0000 | uVar16;
      pcVar22 = (char *)(uVar18 | (uint)bVar6 & 0xffffff01);
      cVar11 = (char)((uint)bVar6 & 0xffffff01);
      *pcVar22 = *pcVar22 + cVar11;
      bVar6 = cVar11 - 0x30;
      cVar11 = *(char *)((uVar18 | (uint)bVar6) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar13 = (uint *)(((uint)puVar13 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar16 >> 8) + cVar11,bVar6)) + 2);
      *puVar13 = *puVar13 | (uint)puVar13;
      pcVar5 = (code *)swi(3);
      iVar17 = (*pcVar5)((uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8));
      return iVar17;
    }
    bVar7 = bVar7 | (byte)(uVar27 >> 8);
    pcVar22 = (char *)(uVar16 | (uint)bVar7);
    *pcVar22 = *pcVar22 + bVar7;
    pcVar22[uVar27 * 8] = pcVar22[uVar27 * 8] + bVar7;
    cVar11 = pcVar22[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar13 = (uint *)(((uint)puVar13 & 0xffff0000 |
                       (uint)CONCAT11((char)(uVar16 >> 8) + cVar11,bVar7)) + 2);
    *puVar13 = *puVar13 | (uint)puVar13;
    bVar7 = (char)puVar13 + 8;
    pcVar22 = (char *)((uint)puVar13 & 0xffffff00 | (uint)bVar7);
    *pcVar22 = *pcVar22 + bVar7;
    pcVar22[uVar27 * 8] = pcVar22[uVar27 * 8] + bVar7;
    cVar11 = pcVar22[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar13 = (uint *)(((uint)puVar13 & 0xffff0000 |
                       (uint)CONCAT11((char)(((uint)puVar13 & 0xffffff00) >> 8) + cVar11,bVar7)) + 2
                      );
    *puVar13 = *puVar13 | (uint)puVar13;
    piVar19 = (int *)((uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8));
  }
  bVar8 = (byte)uVar27;
  *(byte *)piVar19 = *(byte *)piVar19 | bVar10;
  *piVar19 = *piVar19 + (int)piVar19;
  *(byte *)(piVar19 + uVar27 * 2) = *(byte *)(piVar19 + uVar27 * 2) + (char)piVar19;
  bVar7 = *(byte *)((int)piVar19 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(((uint)piVar19 & 0xffff0000 |
                     (uint)CONCAT11((char)((uint)piVar19 >> 8) + bVar7,(char)piVar19)) + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
  pcVar22 = (char *)((uint)puVar13 & 0xffffff00 | (uint)(byte)((char)puVar13 + 8));
code_r0x080422ec:
  *(byte *)(in_ECX + 7) = bVar6;
  pcVar22[in_ECX] = pcVar22[in_ECX] | bVar8;
  *pcVar22 = *pcVar22 + (char)pcVar22;
  bVar6 = (char)pcVar22 - 0x30;
  cVar11 = *(char *)(((uint)pcVar22 & 0xffffff00 | (uint)bVar6) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar13 = (uint *)(((uint)pcVar22 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar22 & 0xffffff00) >> 8) + cVar11,bVar6)) + 2);
  *puVar13 = *puVar13 | (uint)puVar13;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_create(pthread_t *__newthread,pthread_attr_t *__attr,void *(*__start_routine)(void *),
                  void *__arg)

{
  undefined uVar1;
  int iVar2;
  undefined *puVar3;
  undefined *puVar4;
  code *pcVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  char cVar10;
  ushort uVar11;
  uint *puVar12;
  uint uVar13;
  uint uVar14;
  byte *pbVar15;
  uint uVar16;
  int iVar17;
  uint uVar18;
  int *piVar19;
  int iVar20;
  int iVar21;
  char *pcVar22;
  uint uVar23;
  uint uVar24;
  byte bVar25;
  void *(*pVar26)(void *);
  void *Var27(void *);
  uint *unaff_EBX;
  int iVar28;
  undefined *puVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined4 *puVar32;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar33;
  byte in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar6 = (char)__newthread - 0x30;
  uVar16 = (uint)__newthread & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__newthread & 0xffffff00) >> 8) +
                          *(char *)(((uint)__newthread & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar6 = (char)puVar12 + 8;
  pbVar15 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)bVar6);
  bVar9 = (byte)__start_routine;
  if ((int)(puVar3 + uVar18 + 1) < 0) {
    *pbVar15 = *pbVar15 | bVar9;
    *pbVar15 = *pbVar15 + bVar6;
    pbVar15 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar16 = (uint)pbVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar15 >> 8) + pbVar15[2],(char)pbVar15);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar16 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  uVar13 = uVar16 - 1;
  bVar6 = (byte)__attr;
  if ((int)uVar13 < 0) {
    *(byte *)(uVar13 * 2) = *(byte *)(uVar13 * 2) | bVar6;
    pcVar22 = (char *)(uVar13 + (int)__attr * 8);
    *pcVar22 = *pcVar22 + (char)uVar13;
  }
  uVar13 = uVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar16 + 1),(char)uVar13);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar13 + 4) + (uint)((uVar14 & 1) != 0) + iVar17 + uVar18 + 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar18 = (uint)puVar12 & 0xffffff00;
  pbVar15 = (byte *)(uVar18 | (uint)bVar7);
  if ((int)(puVar3 + (uVar16 - 1)) < 0) {
    *pbVar15 = *pbVar15 | (byte)(uVar18 >> 8);
    *pbVar15 = *pbVar15 + bVar7;
    pbVar15 = (byte *)(uVar18 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar14 = (uint)pbVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar15 >> 8) + pbVar15[2],(char)pbVar15);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar14 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar14 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
  *(uint *)(puVar3 + iVar17 + (uVar16 - 1) + (uVar18 - 4)) = uVar14;
  bVar25 = (byte)((uint)__start_routine >> 8);
  if ((char)bVar7 < 0) {
    *(byte *)(uVar14 * 2) = *(byte *)(uVar14 * 2) | bVar25;
    pcVar22 = (char *)(uVar14 + (int)__attr * 8);
    *pcVar22 = *pcVar22 + bVar7;
  }
  uVar13 = (uint)puVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),bVar7);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  puVar3 = puVar3 + iVar17 + (uVar16 - 1) + *(int *)(uVar13 + 4) + (uVar18 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  pbVar15 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)bVar7);
  *(undefined **)(puVar3 + uVar14 + -4) = puVar3 + uVar14;
  Var27 = SUB41((uint)unaff_EBX >> 8,0);
  if ((char)bVar7 < 0) {
    *pbVar15 = *pbVar15 | (byte)Var27;
    *pbVar15 = *pbVar15 + bVar7;
    pbVar15 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar16 = (uint)pbVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar15 >> 8) + pbVar15[2],(char)pbVar15);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar16 = *(uint *)(puVar3 + iVar17 + uVar14 + -4 + uVar18);
  if ((char)((char)puVar12 + '\b') < 0) {
    pbVar15 = (byte *)(uVar16 * 2 + -0x2ffc0000);
    *pbVar15 = *pbVar15 | (byte)uVar16;
  }
  uVar13 = uVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(byte)uVar16);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar20 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar13 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
  iVar28 = *(int *)(puVar3 + iVar17 + uVar14 + -4 + (uint)((uVar16 & 1) != 0) + iVar20 + uVar18 + 4)
  ;
  puVar29 = (undefined *)(iVar28 + 4);
  if (-1 < (char)bVar7) {
    uVar16 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar13 + 2),bVar7)
    ;
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar29 = (undefined *)(iVar28 + 4 + *(int *)(uVar16 + 4) + (uint)((uVar18 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar16 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar13 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar13 + 0x4000000) = *(byte *)(uVar13 + 0x4000000) | bVar6;
  (*__attr)[0] = (*__attr)[0] << 1 | (char)(*__attr)[0] < 0;
  *(uint *)(puVar29 + -4) = uVar13;
  *(void *(**)(void *))(puVar29 + -8) = __start_routine;
  *(pthread_attr_t **)(puVar29 + -0xc) = __attr;
  *(uint **)(puVar29 + -0x10) = unaff_EBX;
  *(undefined **)(puVar29 + -0x14) = puVar29;
  *(undefined4 **)(puVar29 + -0x18) = unaff_EBP;
  *(undefined **)(puVar29 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x20) = unaff_EDI;
  uVar18 = (uint)__attr & 0xffffff00 | (uint)(byte)(bVar6 + bVar9);
  iVar17 = uVar13 - *(int *)(uVar13 + 0x13);
  *(int *)(puVar29 + -0x24) = iVar17;
  *(void *(**)(void *))(puVar29 + -0x28) = __start_routine;
  *(uint *)(puVar29 + -0x2c) = uVar18;
  *(uint **)(puVar29 + -0x30) = unaff_EBX;
  *(undefined **)(puVar29 + -0x34) = puVar29 + -0x20;
  *(undefined4 **)(puVar29 + -0x38) = unaff_EBP;
  *(undefined **)(puVar29 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x40) = unaff_EDI;
  pVar26 = __start_routine + uVar18;
  pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
  *pcVar22 = *pcVar22 + (char)Var27;
  pbVar15 = (byte *)(pcVar22 + (int)__start_routine);
  *pbVar15 = *pbVar15 & (byte)pcVar22;
  bVar6 = *pbVar15;
  *(char **)(puVar29 + -0x44) = pcVar22;
  *(void *(**)(void *))(puVar29 + -0x48) = __start_routine;
  *(void *(**)(void *))(puVar29 + -0x4c) = pVar26;
  *(uint **)(puVar29 + -0x50) = unaff_EBX;
  *(undefined **)(puVar29 + -0x54) = puVar29 + -0x40;
  *(undefined4 **)(puVar29 + -0x58) = unaff_EBP;
  *(undefined **)(puVar29 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x60) = unaff_EDI;
  bVar7 = (byte)unaff_EBX;
  if ((char)bVar6 < 0) {
    pbVar15 = (byte *)((int)pcVar22 * 2 + -0x2ffc0000);
    *pbVar15 = *pbVar15 | bVar7;
  }
  uVar16 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(byte)pcVar22);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = *(int *)(uVar16 + 4);
  puVar30 = puVar29 + iVar17 + -0x60 + uVar18;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar6 = (char)puVar12 + 8;
  uVar16 = (uint)puVar12 & 0xffffff00 | (uint)bVar6;
  if (-1 < (char)bVar6) {
    uVar14 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar16 + 2),bVar6)
    ;
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = puVar29 + iVar17 + -0x60 + (uint)((uVar16 & 1) != 0) + *(int *)(uVar14 + 4) + uVar18;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar14 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar16 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar16 + 0x4000000) = *(byte *)(uVar16 + 0x4000000) | bVar25;
  *(char *)pVar26 = (char)*pVar26 << 1 | (char)*pVar26 < 0;
  *(uint *)(puVar30 + -4) = uVar16;
  *(void *(**)(void *))(puVar30 + -8) = __start_routine;
  *(void *(**)(void *))(puVar30 + -0xc) = pVar26;
  *(uint **)(puVar30 + -0x10) = unaff_EBX;
  *(undefined **)(puVar30 + -0x14) = puVar30;
  *(undefined4 **)(puVar30 + -0x18) = unaff_EBP;
  *(undefined **)(puVar30 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x20) = unaff_EDI;
  uVar18 = (uint)pVar26 & 0xffffff00 | (uint)(byte)((char)pVar26 + bVar9);
  iVar17 = uVar16 - *(int *)(uVar16 + 0x13);
  *(int *)(puVar30 + -0x24) = iVar17;
  *(void *(**)(void *))(puVar30 + -0x28) = __start_routine;
  *(uint *)(puVar30 + -0x2c) = uVar18;
  *(uint **)(puVar30 + -0x30) = unaff_EBX;
  *(undefined **)(puVar30 + -0x34) = puVar30 + -0x20;
  *(undefined4 **)(puVar30 + -0x38) = unaff_EBP;
  *(undefined **)(puVar30 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x40) = unaff_EDI;
  pVar26 = __start_routine + uVar18;
  pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
  *pcVar22 = *pcVar22 + (char)Var27;
  bVar6 = (byte)pcVar22;
  pcVar22[(int)__start_routine] = pcVar22[(int)__start_routine] & bVar6;
  *(undefined4 *)(puVar30 + -0x44) = 0xb4080779;
  *pcVar22 = *pcVar22 + bVar6;
  pcVar22[(int)pVar26 * 8] = pcVar22[(int)pVar26 * 8] + bVar6;
  uVar16 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],bVar6);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar6 = (char)puVar12 + 8;
  pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar6);
  puVar3 = unaff_EDI + 1;
  uVar1 = in((short)pVar26);
  *unaff_EDI = uVar1;
  if ((char)bVar6 < 0) {
    pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar6);
    *pcVar22 = *pcVar22 + bVar6;
    pcVar22[(int)pVar26 * 8] = pcVar22[(int)pVar26 * 8] + bVar6;
  }
  uVar14 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar4 = puVar30 + *(int *)(uVar14 + 4) + (uint)((uVar18 & 1) != 0) + iVar17 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar14 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar6 = (char)puVar12 + 8;
  uVar18 = (uint)puVar12 & 0xffffff00 | (uint)bVar6;
  cVar10 = (char)pVar26;
  if (SCARRY1((char)puVar12,'\b')) {
    *(uint *)(puVar4 + (uVar16 - 4)) = uVar18;
    *(void *(**)(void *))(puVar4 + (uVar16 - 8)) = __start_routine;
    *(void *(**)(void *))(puVar4 + (uVar16 - 0xc)) = pVar26;
    *(uint **)(puVar4 + (uVar16 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar16)) = puVar4 + uVar16;
    *(undefined4 **)(puVar4 + (uVar16 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar16 - 0x1c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar16 - 0x20)) = puVar3;
    uVar14 = (uint)pVar26 & 0xffffff00 | (uint)(byte)(cVar10 + bVar9);
    iVar17 = uVar18 - *(int *)(uVar18 + 0x13);
    *(int *)(puVar4 + (uVar16 - 0x24)) = iVar17;
    *(void *(**)(void *))(puVar4 + (uVar16 - 0x28)) = __start_routine;
    *(uint *)(puVar4 + (uVar16 - 0x2c)) = uVar14;
    *(uint **)(puVar4 + (uVar16 - 0x30)) = unaff_EBX;
    *(undefined **)(puVar4 + (uVar16 - 0x34)) = puVar4 + (uVar16 - 0x20);
    *(undefined4 **)(puVar4 + (uVar16 - 0x38)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar16 - 0x3c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar16 - 0x40)) = puVar3;
    pVar26 = __start_routine + uVar14;
    piVar19 = (int *)(iVar17 - *(int *)(iVar17 + 9));
    *(byte *)piVar19 = *(byte *)piVar19 + (char)Var27;
    *(byte *)((int)piVar19 + (int)__start_routine) =
         *(byte *)((int)piVar19 + (int)__start_routine) & (byte)piVar19;
  }
  else {
    uVar18 = (uint)CONCAT11((byte)(((uint)puVar12 & 0xffffff00) >> 8) | bVar9,bVar6);
    pcVar22 = (char *)((uint)puVar12 & 0xffff0000 | uVar18);
    *pcVar22 = *pcVar22 + bVar6;
    pcVar22[(int)pVar26 * 8] = pcVar22[(int)pVar26 * 8] + bVar6;
    uVar14 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11((char)(uVar18 >> 8) + pcVar22[2],bVar6);
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar18 = (uint)((uVar18 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar14 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar14 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar6 = (char)puVar12 + 8;
    uVar16 = (uint)puVar12 & 0xffffff00;
    uVar14 = uVar16 | (uint)bVar6;
    if (bVar6 == 0) {
      *(uint *)(puVar4 + (uVar18 - 4)) = uVar14;
      *(void *(**)(void *))(puVar4 + (uVar18 - 8)) = __start_routine;
      *(void *(**)(void *))(puVar4 + (uVar18 - 0xc)) = pVar26;
      *(uint **)(puVar4 + (uVar18 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar18)) = puVar4 + uVar18;
      *(undefined4 **)(puVar4 + (uVar18 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar18 - 0x20)) = puVar3;
      iVar17 = uVar14 - *(int *)(uVar14 + 0x13);
      *(int *)(puVar4 + (uVar18 - 0x24)) = iVar17;
      *(void *(**)(void *))(puVar4 + (uVar18 - 0x28)) = __start_routine;
      *(uint *)(puVar4 + (uVar18 - 0x2c)) = (uint)pVar26 & 0xffffff00 | (uint)(byte)(cVar10 + bVar9)
      ;
      *(uint **)(puVar4 + (uVar18 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar18 - 0x34)) = puVar4 + (uVar18 - 0x20);
      *(undefined4 **)(puVar4 + (uVar18 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar18 - 0x40)) = puVar3;
      bVar7 = cVar10 + bVar9 + bVar9;
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + (char)Var27;
      pcVar22[(int)__start_routine] = pcVar22[(int)__start_routine] & (byte)pcVar22;
      goto code_r0x080422ec;
    }
    bVar6 = bVar6 | bVar7;
    pcVar22 = (char *)(uVar16 | (uint)bVar6);
    *pcVar22 = *pcVar22 + bVar6;
    pcVar22[(int)pVar26 * 8] = pcVar22[(int)pVar26 * 8] + bVar6;
    uVar14 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11((char)(uVar16 >> 8) + pcVar22[2],bVar6);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar16 = (uint)((uVar16 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar14 + 4) + uVar18 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar14 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar6 = (char)puVar12 + 8;
    uVar18 = (uint)puVar12 & 0xffffff00 | (uint)bVar6;
    if ((char)bVar6 < 0) {
      *(uint *)(puVar4 + (uVar16 - 4)) = uVar18;
      *(void *(**)(void *))(puVar4 + (uVar16 - 8)) = __start_routine;
      *(void *(**)(void *))(puVar4 + (uVar16 - 0xc)) = pVar26;
      *(uint **)(puVar4 + (uVar16 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar16 - 0x14)) = puVar4 + uVar16;
      *(undefined4 **)(puVar4 + (uVar16 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar16 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar16 - 0x20)) = puVar3;
      iVar17 = uVar18 - *(int *)(uVar18 + 0x13);
      *(int *)(puVar4 + (uVar16 - 0x24)) = iVar17;
      *(void *(**)(void *))(puVar4 + (uVar16 - 0x28)) = __start_routine;
      *(uint *)(puVar4 + (uVar16 - 0x2c)) = (uint)pVar26 & 0xffffff00 | (uint)(byte)(cVar10 + bVar9)
      ;
      *(uint **)(puVar4 + (uVar16 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar16 - 0x34)) = puVar4 + (uVar16 - 0x20);
      *(undefined4 **)(puVar4 + (uVar16 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar16 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar16 - 0x40)) = puVar3;
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + (char)Var27;
      pcVar22[(int)__start_routine] = pcVar22[(int)__start_routine] & (byte)pcVar22;
      return;
    }
    uVar18 = (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8),bVar6);
    pcVar22 = (char *)((uint)puVar12 & 0xffff0000 | uVar18);
    *pcVar22 = *pcVar22 + bVar6;
    pcVar22[(int)pVar26 * 8] = pcVar22[(int)pVar26 * 8] + bVar6;
    uVar14 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11((char)(uVar18 >> 8) + pcVar22[2],bVar6);
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar18 = (uint)((uVar18 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar14 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar14 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar6 = (char)puVar12 + 8;
    uVar16 = (uint)puVar12 & 0xffffff00;
    uVar14 = uVar16 | (uint)bVar6;
    if (SCARRY1((char)puVar12,'\b') != (char)bVar6 < 0) {
      *(uint *)(puVar4 + (uVar18 - 4)) = uVar14;
      *(void *(**)(void *))(puVar4 + (uVar18 - 8)) = __start_routine;
      *(void *(**)(void *))(puVar4 + (uVar18 - 0xc)) = pVar26;
      *(uint **)(puVar4 + (uVar18 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar18 - 0x14)) = puVar4 + uVar18;
      *(undefined4 **)(puVar4 + (uVar18 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar18 - 0x20)) = puVar3;
      uVar16 = (uint)pVar26 & 0xffffff00 | (uint)(byte)(cVar10 + bVar9);
      iVar17 = uVar14 - *(int *)(uVar14 + 0x13);
      *(int *)(puVar4 + (uVar18 - 0x24)) = iVar17;
      *(void *(**)(void *))(puVar4 + (uVar18 - 0x28)) = __start_routine;
      *(uint *)(puVar4 + (uVar18 - 0x2c)) = uVar16;
      *(uint **)(puVar4 + (uVar18 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar18 - 0x34)) = puVar4 + (uVar18 - 0x20);
      *(undefined4 **)(puVar4 + (uVar18 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar18 - 0x40)) = puVar3;
      pVar26 = __start_routine + uVar16;
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + (char)Var27;
      pbVar15 = (byte *)(pcVar22 + (int)__start_routine);
      bVar6 = (byte)pcVar22;
      *pbVar15 = *pbVar15 & bVar6;
      if ((char)*pbVar15 < 0) {
        *(byte *)(__start_routine + (int)pcVar22) = (byte)__start_routine[(int)pcVar22] | bVar25;
        *pcVar22 = *pcVar22 + bVar6;
        pcVar22 = (char *)((uint)pcVar22 & 0xffffff00 | (uint)(byte)(bVar6 - 0x30));
      }
      uVar14 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      bVar33 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar16 = (uint)bVar33;
      puVar4 = puVar4 + *(int *)(uVar14 + 4) + (uVar18 - 0x40);
      cVar10 = (char)puVar4 + bVar33;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar14 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      if ((char)bVar6 < 0) {
        puVar4[uVar16] = puVar4[uVar16] | (byte)Var27;
        *(undefined **)(puVar4 + uVar16) = puVar4 + *(int *)(puVar4 + uVar16) + uVar16;
        puVar4[(int)pVar26 * 8 + uVar16] = puVar4[(int)pVar26 * 8 + uVar16] + cVar10;
      }
      uVar16 = (uint)(puVar4 + uVar16) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar4 + uVar16) >> 8) + puVar4[uVar16 + 2],cVar10);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      iVar17 = ((uint)puVar12 & 0xffffff00 | (uint)bVar6) + *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      uVar11 = (ushort)puVar12 & 0xff00 | (ushort)bVar6;
      iVar20 = (int)(short)uVar11;
      if ((char)bVar6 < 0) {
        *(byte *)(__start_routine + iVar20) = (byte)__start_routine[iVar20] | bVar6;
        pcVar22 = (char *)(iVar20 + (int)pVar26 * 8);
        *pcVar22 = *pcVar22 + bVar6;
      }
      iVar21 = CONCAT22((short)uVar11 >> 0xf,
                        CONCAT11((char)((uint)iVar20 >> 8) + *(char *)(iVar20 + 2),bVar6));
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar21 + 4);
      uVar14 = (uint)((uVar16 & 1) != 0);
      uVar16 = *puVar12;
      iVar20 = iVar17 + uVar18 + *puVar12;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar21 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (byte)puVar12;
      bVar6 = bVar8 + 8;
      pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar6);
      *(uint *)(iVar20 + uVar14 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar8,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar6 < 0) * 0x80 |
           (uint)(bVar6 == 0) * 0x40 |
           (uint)(((iVar17 + uVar18 & 0xfffffff) + (uVar16 & 0xfffffff) + uVar14 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar8) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if ((char)bVar6 < 0) {
        pcVar22[1] = pcVar22[1] | (byte)pVar26;
        *pcVar22 = *pcVar22 + bVar6;
        pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)(bVar8 - 0x28));
      }
      uVar16 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar17 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = DAT_5c080779;
      piVar19 = (int *)((uint)puVar12 & 0xffffff00 | (uint)DAT_5c080779);
      *piVar19 = *piVar19 + (int)piVar19;
      *(byte *)(piVar19 + (int)pVar26 * 2) = *(char *)(piVar19 + (int)pVar26 * 2) + bVar6;
      uVar13 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)((int)piVar19 + 2),bVar6);
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar21 = *(int *)(uVar13 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar6);
      _DAT_03ffffc1 = unaff_EDI + 2;
      *puVar3 = *unaff_ESI;
      if ((char)bVar6 < 0) {
        pcVar22[1] = pcVar22[1] | bVar25;
        *pcVar22 = *pcVar22 + bVar6;
        pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
      }
      uVar23 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      uVar13 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar2 = *(int *)(uVar23 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar23 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      uVar23 = (uint)puVar12 & 0xffffff00 | (uint)bVar6;
      *(byte *)(__start_routine + uVar23) =
           (byte)__start_routine[uVar23] | (byte)((uint)pVar26 >> 8);
      pcVar22 = (char *)(uVar23 + (int)pVar26 * 8);
      *pcVar22 = *pcVar22 + bVar6;
      uVar24 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar23 + 2),
                              bVar6);
      uVar23 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar23 = (uint)((uVar23 & 1) != 0);
      iVar17 = iVar20 + uVar14 + iVar17 + (uint)((uVar18 & 1) != 0) + iVar21 +
               (uint)((uVar16 & 1) != 0) + iVar2 + (uint)((uVar13 & 1) != 0) + -2 +
               *(int *)(uVar24 + 4);
      puVar31 = (undefined *)(iVar17 + uVar23);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar24 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_03ffffc5 = unaff_ESI + 2;
      uVar18 = (uint)puVar12 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (-1 < (char)((char)puVar12 + '\b')) {
        uVar16 = (uint)puVar12 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)(uVar18 + 2),unaff_ESI[1]);
        uVar18 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar31 = (undefined *)(iVar17 + uVar23 + *(int *)(uVar16 + 4) + (uint)((uVar18 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar12 = (uint *)(uVar16 + 2);
        *puVar12 = *puVar12 | (uint)puVar12;
        uVar18 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      }
      *(byte *)(uVar18 + 0x4000001) = *(byte *)(uVar18 + 0x4000001) | (byte)uVar18;
      *(char *)pVar26 = (char)*pVar26 << 1 | (char)*pVar26 < 0;
      *(uint *)(puVar31 + -4) = uVar18;
      *(void *(**)(void *))(puVar31 + -8) = __start_routine;
      *(void *(**)(void *))(puVar31 + -0xc) = pVar26;
      *(uint **)(puVar31 + -0x10) = unaff_EBX;
      *(undefined **)(puVar31 + -0x14) = puVar31;
      *(undefined4 **)(puVar31 + -0x18) = unaff_EBP;
      *(undefined **)(puVar31 + -0x1c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x20) = _DAT_03ffffc1;
      uVar16 = (uint)pVar26 & 0xffffff00 | (uint)(byte)((byte)pVar26 + bVar9);
      iVar17 = uVar18 - *(int *)(uVar18 + 0x13);
      *(int *)(puVar31 + -0x24) = iVar17;
      *(void *(**)(void *))(puVar31 + -0x28) = __start_routine;
      *(uint *)(puVar31 + -0x2c) = uVar16;
      *(uint **)(puVar31 + -0x30) = unaff_EBX;
      *(undefined **)(puVar31 + -0x34) = puVar31 + -0x20;
      *(undefined4 **)(puVar31 + -0x38) = unaff_EBP;
      *(undefined **)(puVar31 + -0x3c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x40) = _DAT_03ffffc1;
      pVar26 = __start_routine + uVar16;
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + (char)Var27;
      pcVar22[(int)__start_routine] = pcVar22[(int)__start_routine] & (byte)pcVar22;
      iVar17 = CONCAT31((int3)((uint)pcVar22 >> 8),0x79);
      *(byte *)(__start_routine + iVar17 + -0x2ffc0000) =
           (byte)__start_routine[iVar17 + -0x2ffc0000] | bVar9;
      uVar16 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + *(char *)(iVar17 + 2),0x79);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      puVar3 = puVar31 + *(int *)(uVar16 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      uVar16 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar12 + '\b');
      *(byte *)(uVar16 + 0x4000001) = *(byte *)(uVar16 + 0x4000001) | bVar7;
      *(char *)pVar26 = (char)*pVar26 << 1 | (char)*pVar26 < 0;
      *(uint *)(puVar3 + uVar18) = uVar16;
      *(void *(**)(void *))(puVar3 + (uVar18 - 4)) = __start_routine;
      *(void *(**)(void *))(puVar3 + (uVar18 - 8)) = pVar26;
      *(uint **)(puVar3 + (uVar18 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar18 - 0x10)) = puVar3 + uVar18 + 4;
      *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar18)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar18 - 0x18)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar18 - 0x1c)) = _DAT_03ffffc1;
      uVar14 = (uint)pVar26 & 0xffffff00 | (uint)(byte)((char)pVar26 + bVar9);
      iVar17 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar3 + (uVar18 - 0x20)) = iVar17;
      *(void *(**)(void *))(puVar3 + (uVar18 - 0x24)) = __start_routine;
      *(uint *)(puVar3 + (uVar18 - 0x28)) = uVar14;
      *(uint **)(puVar3 + (uVar18 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar18 - 0x30)) = puVar3 + (uVar18 - 0x1c);
      *(undefined4 **)(puVar3 + (uVar18 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar18 - 0x38)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar18 - 0x3c)) = _DAT_03ffffc1;
      _DAT_03fffff5 = __start_routine + uVar14;
      pcVar22 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar22 = *pcVar22 + (char)Var27;
      pcVar22[(int)__start_routine] = pcVar22[(int)__start_routine] & (byte)pcVar22;
      _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
      (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      piVar19 = (int *)((uint)puVar12 & 0xffffff00 | (uint)bVar6);
      *piVar19 = *piVar19 + (int)piVar19;
      *(byte *)(piVar19 + (int)_DAT_03fffff5 * 2) =
           *(char *)(piVar19 + (int)_DAT_03fffff5 * 2) + bVar6;
      cVar10 = *(char *)((int)piVar19 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + cVar10,bVar6)) +
                        2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_03fffffd = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      *(char *)(__start_routine + 7) = (char)__start_routine[7] >> 8;
      *(char *)_DAT_03fffff5 = (char)*_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
      _DAT_03ffffed = 0x4000001;
      _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar9);
      _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
      _DAT_03ffffcd = &DAT_03ffffe1;
      pVar26 = __start_routine + _DAT_03ffffd5;
      pcVar22 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
      _DAT_03ffffc9 = unaff_EBP;
      _DAT_03ffffd1 = unaff_EBX;
      _DAT_03ffffd9 = __start_routine;
      _DAT_03ffffe1 = _DAT_03ffffc1;
      _DAT_03ffffe5 = _DAT_03ffffc5;
      _DAT_03ffffe9 = unaff_EBP;
      _DAT_03fffff1 = unaff_EBX;
      _DAT_03fffff9 = __start_routine;
      *pcVar22 = *pcVar22 + (char)Var27;
      pcVar22[(int)__start_routine] = pcVar22[(int)__start_routine] & (byte)pcVar22;
      bVar9 = (byte)pcVar22 | bVar9;
      piVar19 = (int *)((uint)pcVar22 & 0xffffff00 | (uint)bVar9);
      *piVar19 = *piVar19 + (int)piVar19;
      *(byte *)(piVar19 + (int)pVar26 * 2) = *(char *)(piVar19 + (int)pVar26 * 2) + bVar9;
      uVar16 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar22 & 0xffffff00) >> 8) +
                              *(char *)((int)piVar19 + 2),bVar9);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      iVar17 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      puVar32 = (undefined4 *)(iVar17 + uVar18 + 0x3ffffbd);
      *(undefined4 **)(iVar17 + uVar18 + 0x3ffffbd) = unaff_EBP;
      cVar10 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar32 = puVar32 + -1;
        *puVar32 = *unaff_EBP;
        cVar10 = cVar10 + -1;
      } while (0 < cVar10);
      *(uint *)(iVar17 + uVar18 + 0x3ffff9d) = iVar17 + uVar18 + 0x3ffffbd;
      uVar16 = (uint)CONCAT11(bVar6 / 1,bVar6) & 0xffffff00;
      uVar18 = (uint)puVar12 & 0xffff0000 | uVar16;
      pcVar22 = (char *)(uVar18 | (uint)bVar6 & 0xffffff01);
      cVar10 = (char)((uint)bVar6 & 0xffffff01);
      *pcVar22 = *pcVar22 + cVar10;
      bVar6 = cVar10 - 0x30;
      cVar10 = *(char *)((uVar18 | (uint)bVar6) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar16 >> 8) + cVar10,bVar6)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      pcVar5 = (code *)swi(3);
      iVar17 = (*pcVar5)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
      return iVar17;
    }
    bVar6 = bVar6 | (byte)((uint)pVar26 >> 8);
    pcVar22 = (char *)(uVar16 | (uint)bVar6);
    *pcVar22 = *pcVar22 + bVar6;
    pcVar22[(int)pVar26 * 8] = pcVar22[(int)pVar26 * 8] + bVar6;
    cVar10 = pcVar22[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                       (uint)CONCAT11((char)(uVar16 >> 8) + cVar10,bVar6)) + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar6 = (char)puVar12 + 8;
    pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar6);
    *pcVar22 = *pcVar22 + bVar6;
    pcVar22[(int)pVar26 * 8] = pcVar22[(int)pVar26 * 8] + bVar6;
    cVar10 = pcVar22[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                       (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + cVar10,bVar6)) + 2
                      );
    *puVar12 = *puVar12 | (uint)puVar12;
    piVar19 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
  }
  bVar7 = (byte)pVar26;
  *(byte *)piVar19 = *(byte *)piVar19 | bVar9;
  *piVar19 = *piVar19 + (int)piVar19;
  *(byte *)(piVar19 + (int)pVar26 * 2) = *(byte *)(piVar19 + (int)pVar26 * 2) + (char)piVar19;
  bVar6 = *(byte *)((int)piVar19 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(((uint)piVar19 & 0xffff0000 |
                     (uint)CONCAT11((char)((uint)piVar19 >> 8) + bVar6,(char)piVar19)) + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
code_r0x080422ec:
  __start_routine[7] = Var27;
  *(byte *)(__start_routine + (int)pcVar22) = (byte)__start_routine[(int)pcVar22] | bVar7;
  *pcVar22 = *pcVar22 + (char)pcVar22;
  bVar6 = (char)pcVar22 - 0x30;
  cVar10 = *(char *)(((uint)pcVar22 & 0xffffff00 | (uint)bVar6) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(((uint)pcVar22 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar22 & 0xffffff00) >> 8) + cVar10,bVar6)) + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int sigemptyset(sigset_t *__set)

{
  undefined uVar1;
  int iVar2;
  undefined *puVar3;
  undefined *puVar4;
  code *pcVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  char cVar9;
  ushort uVar10;
  uint *puVar11;
  uint uVar12;
  byte *pbVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  uint uVar17;
  int *piVar18;
  int iVar19;
  int iVar20;
  char *pcVar21;
  uint uVar22;
  uint uVar23;
  int in_ECX;
  byte bVar24;
  byte *in_EDX;
  byte *pbVar25;
  byte bVar26;
  byte bVar27;
  uint *unaff_EBX;
  int iVar28;
  undefined *puVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined4 *puVar32;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar33;
  byte in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack9 [4];
  undefined auStack5 [4];
  undefined uStack1;
  
  bVar6 = (char)__set - 0x30;
  uVar14 = (uint)__set & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__set & 0xffffff00) >> 8) +
                          *(char *)(((uint)__set & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar16 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar14 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  uVar14 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  uVar12 = uVar14 - 1;
  bVar6 = (byte)in_EDX;
  if ((int)uVar12 < 0) {
    *(byte *)(uVar12 * 2) = *(byte *)(uVar12 * 2) | bVar6;
    pcVar21 = (char *)(uVar12 + (int)in_EDX * 8);
    *pcVar21 = *pcVar21 + (char)uVar12;
  }
  uVar12 = uVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)(uVar14 + 1),(char)uVar12);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar12 + 4) + (uint)((uVar17 & 1) != 0) + iVar16;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar12 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  uVar17 = (uint)puVar11 & 0xffffff00;
  pbVar13 = (byte *)(uVar17 | (uint)bVar7);
  if ((int)(puVar3 + (uVar14 - 1)) < 0) {
    *pbVar13 = *pbVar13 | (byte)(uVar17 >> 8);
    *pbVar13 = *pbVar13 + bVar7;
    pbVar13 = (byte *)(uVar17 | (uint)(byte)((char)puVar11 - 0x28));
  }
  uVar12 = (uint)pbVar13 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar13 >> 8) + pbVar13[2],(char)pbVar13);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  iVar16 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar12 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  uVar12 = (uint)puVar11 & 0xffffff00 | (uint)bVar7;
  *(uint *)(puVar3 + iVar16 + (uVar14 - 1) + (uVar17 - 4)) = uVar12;
  bVar24 = (byte)((uint)in_ECX >> 8);
  if ((char)bVar7 < 0) {
    *(byte *)(uVar12 * 2) = *(byte *)(uVar12 * 2) | bVar24;
    pcVar21 = (char *)(uVar12 + (int)in_EDX * 8);
    *pcVar21 = *pcVar21 + bVar7;
  }
  uVar15 = (uint)puVar11 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar12 + 2),bVar7);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar12 = (uint)((uVar12 & 1) != 0);
  puVar3 = puVar3 + iVar16 + (uVar14 - 1) + *(int *)(uVar15 + 4) + (uVar17 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar15 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  pbVar13 = (byte *)((uint)puVar11 & 0xffffff00 | (uint)bVar7);
  *(undefined **)(puVar3 + (uVar12 - 4)) = puVar3 + uVar12;
  bVar27 = (byte)((uint)unaff_EBX >> 8);
  if ((char)bVar7 < 0) {
    *pbVar13 = *pbVar13 | bVar27;
    *pbVar13 = *pbVar13 + bVar7;
    pbVar13 = (byte *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 - 0x28));
  }
  uVar14 = (uint)pbVar13 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar13 >> 8) + pbVar13[2],(char)pbVar13);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  iVar16 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar14 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  uVar14 = *(uint *)(puVar3 + iVar16 + (uVar12 - 4) + uVar17);
  if ((char)((char)puVar11 + '\b') < 0) {
    pbVar13 = (byte *)(uVar14 * 2 + -0x2ffc0000);
    *pbVar13 = *pbVar13 | (byte)uVar14;
  }
  uVar15 = uVar14 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar14 >> 8) + *(char *)(uVar14 + 2),(byte)uVar14);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar19 = *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar15 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  uVar15 = (uint)puVar11 & 0xffffff00 | (uint)bVar7;
  iVar28 = *(int *)(puVar3 + iVar16 + (uVar12 - 4) + (uint)((uVar14 & 1) != 0) + iVar19 + uVar17 + 4
                   );
  puVar29 = (undefined *)(iVar28 + 4);
  if (-1 < (char)bVar7) {
    uVar14 = (uint)puVar11 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar15 + 2),bVar7)
    ;
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar29 = (undefined *)(iVar28 + 4 + *(int *)(uVar14 + 4) + (uint)((uVar17 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar14 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    uVar15 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  }
  *(byte *)(uVar15 + 0x4000000) = *(byte *)(uVar15 + 0x4000000) | bVar6;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar29 + -4) = uVar15;
  *(int *)(puVar29 + -8) = in_ECX;
  *(byte **)(puVar29 + -0xc) = in_EDX;
  *(uint **)(puVar29 + -0x10) = unaff_EBX;
  *(undefined **)(puVar29 + -0x14) = puVar29;
  *(undefined4 **)(puVar29 + -0x18) = unaff_EBP;
  *(undefined **)(puVar29 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x20) = unaff_EDI;
  bVar7 = (byte)in_ECX;
  uVar17 = (uint)in_EDX & 0xffffff00 | (uint)(byte)(bVar6 + bVar7);
  iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
  *(int *)(puVar29 + -0x24) = iVar16;
  *(int *)(puVar29 + -0x28) = in_ECX;
  *(uint *)(puVar29 + -0x2c) = uVar17;
  *(uint **)(puVar29 + -0x30) = unaff_EBX;
  *(undefined **)(puVar29 + -0x34) = puVar29 + -0x20;
  *(undefined4 **)(puVar29 + -0x38) = unaff_EBP;
  *(undefined **)(puVar29 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x40) = unaff_EDI;
  pbVar25 = (byte *)(uVar17 + in_ECX);
  pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
  *pcVar21 = *pcVar21 + bVar27;
  pbVar13 = (byte *)(pcVar21 + in_ECX);
  *pbVar13 = *pbVar13 & (byte)pcVar21;
  bVar6 = *pbVar13;
  *(char **)(puVar29 + -0x44) = pcVar21;
  *(int *)(puVar29 + -0x48) = in_ECX;
  *(byte **)(puVar29 + -0x4c) = pbVar25;
  *(uint **)(puVar29 + -0x50) = unaff_EBX;
  *(undefined **)(puVar29 + -0x54) = puVar29 + -0x40;
  *(undefined4 **)(puVar29 + -0x58) = unaff_EBP;
  *(undefined **)(puVar29 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x60) = unaff_EDI;
  bVar26 = (byte)unaff_EBX;
  if ((char)bVar6 < 0) {
    pbVar13 = (byte *)((int)pcVar21 * 2 + -0x2ffc0000);
    *pbVar13 = *pbVar13 | bVar26;
  }
  uVar14 = (uint)pcVar21 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(byte)pcVar21);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  iVar16 = *(int *)(uVar14 + 4);
  puVar30 = puVar29 + iVar16 + -0x60 + uVar17;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar14 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  uVar14 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
  if (-1 < (char)bVar6) {
    uVar12 = (uint)puVar11 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),bVar6)
    ;
    uVar14 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = puVar29 + iVar16 + -0x60 + (uint)((uVar14 & 1) != 0) + *(int *)(uVar12 + 4) + uVar17;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar12 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    uVar14 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  }
  *(byte *)(uVar14 + 0x4000000) = *(byte *)(uVar14 + 0x4000000) | bVar24;
  *pbVar25 = *pbVar25 << 1 | (char)*pbVar25 < 0;
  *(uint *)(puVar30 + -4) = uVar14;
  *(int *)(puVar30 + -8) = in_ECX;
  *(byte **)(puVar30 + -0xc) = pbVar25;
  *(uint **)(puVar30 + -0x10) = unaff_EBX;
  *(undefined **)(puVar30 + -0x14) = puVar30;
  *(undefined4 **)(puVar30 + -0x18) = unaff_EBP;
  *(undefined **)(puVar30 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x20) = unaff_EDI;
  uVar12 = (uint)pbVar25 & 0xffffff00 | (uint)(byte)((char)pbVar25 + bVar7);
  iVar16 = uVar14 - *(int *)(uVar14 + 0x13);
  *(int *)(puVar30 + -0x24) = iVar16;
  *(int *)(puVar30 + -0x28) = in_ECX;
  *(uint *)(puVar30 + -0x2c) = uVar12;
  *(uint **)(puVar30 + -0x30) = unaff_EBX;
  *(undefined **)(puVar30 + -0x34) = puVar30 + -0x20;
  *(undefined4 **)(puVar30 + -0x38) = unaff_EBP;
  *(undefined **)(puVar30 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x40) = unaff_EDI;
  uVar12 = uVar12 + in_ECX;
  pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
  *pcVar21 = *pcVar21 + bVar27;
  bVar6 = (byte)pcVar21;
  pcVar21[in_ECX] = pcVar21[in_ECX] & bVar6;
  *(undefined4 *)(puVar30 + -0x44) = 0xb4080779;
  *pcVar21 = *pcVar21 + bVar6;
  pcVar21[uVar12 * 8] = pcVar21[uVar12 * 8] + bVar6;
  uVar14 = (uint)pcVar21 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],bVar6);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar16 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar14 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
  puVar3 = unaff_EDI + 1;
  uVar1 = in((short)uVar12);
  *unaff_EDI = uVar1;
  if ((char)bVar6 < 0) {
    pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar12 * 8] = pcVar21[uVar12 * 8] + bVar6;
  }
  uVar15 = (uint)pcVar21 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(char)pcVar21);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  puVar4 = puVar30 + *(int *)(uVar15 + 4) + (uint)((uVar17 & 1) != 0) + iVar16 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar15 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  uVar17 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
  cVar9 = (char)uVar12;
  if (SCARRY1((char)puVar11,'\b')) {
    *(uint *)(puVar4 + (uVar14 - 4)) = uVar17;
    *(int *)(puVar4 + (uVar14 - 8)) = in_ECX;
    *(uint *)(puVar4 + (uVar14 - 0xc)) = uVar12;
    *(uint **)(puVar4 + (uVar14 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar14)) = puVar4 + uVar14;
    *(undefined4 **)(puVar4 + (uVar14 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar14 - 0x1c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar14 - 0x20)) = puVar3;
    uVar12 = uVar12 & 0xffffff00 | (uint)(byte)(cVar9 + bVar7);
    iVar16 = uVar17 - *(int *)(uVar17 + 0x13);
    *(int *)(puVar4 + (uVar14 - 0x24)) = iVar16;
    *(int *)(puVar4 + (uVar14 - 0x28)) = in_ECX;
    *(uint *)(puVar4 + (uVar14 - 0x2c)) = uVar12;
    *(uint **)(puVar4 + (uVar14 - 0x30)) = unaff_EBX;
    *(undefined **)(puVar4 + (uVar14 - 0x34)) = puVar4 + (uVar14 - 0x20);
    *(undefined4 **)(puVar4 + (uVar14 - 0x38)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar14 - 0x3c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar14 - 0x40)) = puVar3;
    uVar12 = uVar12 + in_ECX;
    piVar18 = (int *)(iVar16 - *(int *)(iVar16 + 9));
    *(byte *)piVar18 = *(byte *)piVar18 + bVar27;
    *(byte *)((int)piVar18 + in_ECX) = *(byte *)((int)piVar18 + in_ECX) & (byte)piVar18;
  }
  else {
    uVar17 = (uint)CONCAT11((byte)(((uint)puVar11 & 0xffffff00) >> 8) | bVar7,bVar6);
    pcVar21 = (char *)((uint)puVar11 & 0xffff0000 | uVar17);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar12 * 8] = pcVar21[uVar12 * 8] + bVar6;
    uVar15 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11((char)(uVar17 >> 8) + pcVar21[2],bVar6);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar17 = (uint)((uVar17 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar15 + 4) + uVar14 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar15 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar6 = (char)puVar11 + 8;
    uVar14 = (uint)puVar11 & 0xffffff00;
    uVar15 = uVar14 | (uint)bVar6;
    if (bVar6 == 0) {
      *(uint *)(puVar4 + (uVar17 - 4)) = uVar15;
      *(int *)(puVar4 + (uVar17 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar17 - 0xc)) = uVar12;
      *(uint **)(puVar4 + (uVar17 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar17)) = puVar4 + uVar17;
      *(undefined4 **)(puVar4 + (uVar17 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar17 - 0x20)) = puVar3;
      iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar4 + (uVar17 - 0x24)) = iVar16;
      *(int *)(puVar4 + (uVar17 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar17 - 0x2c)) = uVar12 & 0xffffff00 | (uint)(byte)(cVar9 + bVar7);
      *(uint **)(puVar4 + (uVar17 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar17 - 0x34)) = puVar4 + (uVar17 - 0x20);
      *(undefined4 **)(puVar4 + (uVar17 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar17 - 0x40)) = puVar3;
      bVar24 = cVar9 + bVar7 + bVar7;
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      goto code_r0x080422ec;
    }
    bVar6 = bVar6 | bVar26;
    pcVar21 = (char *)(uVar14 | (uint)bVar6);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar12 * 8] = pcVar21[uVar12 * 8] + bVar6;
    uVar15 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11((char)(uVar14 >> 8) + pcVar21[2],bVar6);
    uVar14 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar14 = (uint)((uVar14 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar15 + 4) + uVar17 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar15 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar6 = (char)puVar11 + 8;
    uVar17 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
    if ((char)bVar6 < 0) {
      *(uint *)(puVar4 + (uVar14 - 4)) = uVar17;
      *(int *)(puVar4 + (uVar14 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar14 - 0xc)) = uVar12;
      *(uint **)(puVar4 + (uVar14 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar14 - 0x14)) = puVar4 + uVar14;
      *(undefined4 **)(puVar4 + (uVar14 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar14 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar14 - 0x20)) = puVar3;
      iVar16 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar4 + (uVar14 - 0x24)) = iVar16;
      *(int *)(puVar4 + (uVar14 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar14 - 0x2c)) = uVar12 & 0xffffff00 | (uint)(byte)(cVar9 + bVar7);
      *(uint **)(puVar4 + (uVar14 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar14 - 0x34)) = puVar4 + (uVar14 - 0x20);
      *(undefined4 **)(puVar4 + (uVar14 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar14 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar14 - 0x40)) = puVar3;
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      return;
    }
    uVar17 = (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8),bVar6);
    pcVar21 = (char *)((uint)puVar11 & 0xffff0000 | uVar17);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar12 * 8] = pcVar21[uVar12 * 8] + bVar6;
    uVar15 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11((char)(uVar17 >> 8) + pcVar21[2],bVar6);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar17 = (uint)((uVar17 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar15 + 4) + uVar14 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar15 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar6 = (char)puVar11 + 8;
    uVar14 = (uint)puVar11 & 0xffffff00;
    uVar15 = uVar14 | (uint)bVar6;
    if (SCARRY1((char)puVar11,'\b') != (char)bVar6 < 0) {
      *(uint *)(puVar4 + (uVar17 - 4)) = uVar15;
      *(int *)(puVar4 + (uVar17 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar17 - 0xc)) = uVar12;
      *(uint **)(puVar4 + (uVar17 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar17 - 0x14)) = puVar4 + uVar17;
      *(undefined4 **)(puVar4 + (uVar17 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar17 - 0x20)) = puVar3;
      uVar14 = uVar12 & 0xffffff00 | (uint)(byte)(cVar9 + bVar7);
      iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar4 + (uVar17 - 0x24)) = iVar16;
      *(int *)(puVar4 + (uVar17 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar17 - 0x2c)) = uVar14;
      *(uint **)(puVar4 + (uVar17 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar17 - 0x34)) = puVar4 + (uVar17 - 0x20);
      *(undefined4 **)(puVar4 + (uVar17 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar17 - 0x40)) = puVar3;
      pbVar25 = (byte *)(uVar14 + in_ECX);
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pbVar13 = (byte *)(pcVar21 + in_ECX);
      bVar6 = (byte)pcVar21;
      *pbVar13 = *pbVar13 & bVar6;
      if ((char)*pbVar13 < 0) {
        pcVar21[in_ECX] = pcVar21[in_ECX] | bVar24;
        *pcVar21 = *pcVar21 + bVar6;
        pcVar21 = (char *)((uint)pcVar21 & 0xffffff00 | (uint)(byte)(bVar6 - 0x30));
      }
      uVar12 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(char)pcVar21);
      bVar33 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar14 = (uint)bVar33;
      puVar4 = puVar4 + *(int *)(uVar12 + 4) + (uVar17 - 0x40);
      cVar9 = (char)puVar4 + bVar33;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar12 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      if ((char)bVar6 < 0) {
        puVar4[uVar14] = puVar4[uVar14] | bVar27;
        *(undefined **)(puVar4 + uVar14) = puVar4 + *(int *)(puVar4 + uVar14) + uVar14;
        puVar4[(int)pbVar25 * 8 + uVar14] = puVar4[(int)pbVar25 * 8 + uVar14] + cVar9;
      }
      uVar14 = (uint)(puVar4 + uVar14) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar4 + uVar14) >> 8) + puVar4[uVar14 + 2],cVar9);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      iVar16 = ((uint)puVar11 & 0xffffff00 | (uint)bVar6) + *(int *)(uVar14 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar14 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      uVar10 = (ushort)puVar11 & 0xff00 | (ushort)bVar6;
      iVar19 = (int)(short)uVar10;
      if ((char)bVar6 < 0) {
        *(byte *)(in_ECX + iVar19) = *(byte *)(in_ECX + iVar19) | bVar6;
        pcVar21 = (char *)(iVar19 + (int)pbVar25 * 8);
        *pcVar21 = *pcVar21 + bVar6;
      }
      iVar20 = CONCAT22((short)uVar10 >> 0xf,
                        CONCAT11((char)((uint)iVar19 >> 8) + *(char *)(iVar19 + 2),bVar6));
      uVar14 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(iVar20 + 4);
      uVar12 = (uint)((uVar14 & 1) != 0);
      uVar14 = *puVar11;
      iVar19 = iVar16 + uVar17 + *puVar11;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(iVar20 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (byte)puVar11;
      bVar8 = bVar6 + 8;
      pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar8);
      *(uint *)(iVar19 + uVar12 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar6,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar8 < 0) * 0x80 |
           (uint)(bVar8 == 0) * 0x40 |
           (uint)(((iVar16 + uVar17 & 0xfffffff) + (uVar14 & 0xfffffff) + uVar12 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar6) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if ((char)bVar8 < 0) {
        pcVar21[1] = pcVar21[1] | (byte)pbVar25;
        *pcVar21 = *pcVar21 + bVar8;
        pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)(bVar6 - 0x28));
      }
      uVar14 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(char)pcVar21);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar16 = *(int *)(uVar14 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar14 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = DAT_5c080779;
      piVar18 = (int *)((uint)puVar11 & 0xffffff00 | (uint)DAT_5c080779);
      *piVar18 = *piVar18 + (int)piVar18;
      *(byte *)(piVar18 + (int)pbVar25 * 2) = *(char *)(piVar18 + (int)pbVar25 * 2) + bVar6;
      uVar15 = (uint)puVar11 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)((int)piVar18 + 2),bVar6);
      uVar14 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar20 = *(int *)(uVar15 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar15 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
      _DAT_03ffffc1 = unaff_EDI + 2;
      *puVar3 = *unaff_ESI;
      if ((char)bVar6 < 0) {
        pcVar21[1] = pcVar21[1] | bVar24;
        *pcVar21 = *pcVar21 + bVar6;
        pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 - 0x28));
      }
      uVar22 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(char)pcVar21);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar2 = *(int *)(uVar22 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar22 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      uVar22 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
      *(byte *)(in_ECX + uVar22) = *(byte *)(in_ECX + uVar22) | (byte)((uint)pbVar25 >> 8);
      pcVar21 = (char *)(uVar22 + (int)pbVar25 * 8);
      *pcVar21 = *pcVar21 + bVar6;
      uVar23 = (uint)puVar11 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar22 + 2),
                              bVar6);
      uVar22 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar22 = (uint)((uVar22 & 1) != 0);
      iVar16 = iVar19 + uVar12 + iVar16 + (uint)((uVar17 & 1) != 0) + iVar20 +
               (uint)((uVar14 & 1) != 0) + iVar2 + (uint)((uVar15 & 1) != 0) + -2 +
               *(int *)(uVar23 + 4);
      puVar31 = (undefined *)(iVar16 + uVar22);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar23 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      _DAT_03ffffc5 = unaff_ESI + 2;
      uVar17 = (uint)puVar11 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (-1 < (char)((char)puVar11 + '\b')) {
        uVar14 = (uint)puVar11 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)(uVar17 + 2),unaff_ESI[1]);
        uVar17 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar31 = (undefined *)(iVar16 + uVar22 + *(int *)(uVar14 + 4) + (uint)((uVar17 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar11 = (uint *)(uVar14 + 2);
        *puVar11 = *puVar11 | (uint)puVar11;
        uVar17 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
      }
      *(byte *)(uVar17 + 0x4000001) = *(byte *)(uVar17 + 0x4000001) | (byte)uVar17;
      *pbVar25 = *pbVar25 << 1 | (char)*pbVar25 < 0;
      *(uint *)(puVar31 + -4) = uVar17;
      *(int *)(puVar31 + -8) = in_ECX;
      *(byte **)(puVar31 + -0xc) = pbVar25;
      *(uint **)(puVar31 + -0x10) = unaff_EBX;
      *(undefined **)(puVar31 + -0x14) = puVar31;
      *(undefined4 **)(puVar31 + -0x18) = unaff_EBP;
      *(undefined **)(puVar31 + -0x1c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x20) = _DAT_03ffffc1;
      uVar14 = (uint)pbVar25 & 0xffffff00 | (uint)(byte)((byte)pbVar25 + bVar7);
      iVar16 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar31 + -0x24) = iVar16;
      *(int *)(puVar31 + -0x28) = in_ECX;
      *(uint *)(puVar31 + -0x2c) = uVar14;
      *(uint **)(puVar31 + -0x30) = unaff_EBX;
      *(undefined **)(puVar31 + -0x34) = puVar31 + -0x20;
      *(undefined4 **)(puVar31 + -0x38) = unaff_EBP;
      *(undefined **)(puVar31 + -0x3c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x40) = _DAT_03ffffc1;
      pbVar25 = (byte *)(uVar14 + in_ECX);
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      iVar16 = CONCAT31((int3)((uint)pcVar21 >> 8),0x79);
      pbVar13 = (byte *)(in_ECX + -0x2ffc0000 + iVar16);
      *pbVar13 = *pbVar13 | bVar7;
      uVar14 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar21 >> 8) + *(char *)(iVar16 + 2),0x79);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      puVar3 = puVar31 + *(int *)(uVar14 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar14 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      uVar14 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar11 + '\b');
      *(byte *)(uVar14 + 0x4000001) = *(byte *)(uVar14 + 0x4000001) | bVar26;
      *pbVar25 = *pbVar25 << 1 | (char)*pbVar25 < 0;
      *(uint *)(puVar3 + uVar17) = uVar14;
      *(int *)(puVar3 + (uVar17 - 4)) = in_ECX;
      *(byte **)(puVar3 + (uVar17 - 8)) = pbVar25;
      *(uint **)(puVar3 + (uVar17 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar17 - 0x10)) = puVar3 + uVar17 + 4;
      *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar17)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar17 - 0x18)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar17 - 0x1c)) = _DAT_03ffffc1;
      uVar12 = (uint)pbVar25 & 0xffffff00 | (uint)(byte)((char)pbVar25 + bVar7);
      iVar16 = uVar14 - *(int *)(uVar14 + 0x13);
      *(int *)(puVar3 + (uVar17 - 0x20)) = iVar16;
      *(int *)(puVar3 + (uVar17 - 0x24)) = in_ECX;
      *(uint *)(puVar3 + (uVar17 - 0x28)) = uVar12;
      *(uint **)(puVar3 + (uVar17 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar17 - 0x30)) = puVar3 + (uVar17 - 0x1c);
      *(undefined4 **)(puVar3 + (uVar17 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar17 - 0x38)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar17 - 0x3c)) = _DAT_03ffffc1;
      _DAT_03fffff5 = (byte *)(uVar12 + in_ECX);
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
      (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      piVar18 = (int *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
      *piVar18 = *piVar18 + (int)piVar18;
      *(byte *)(piVar18 + (int)_DAT_03fffff5 * 2) =
           *(char *)(piVar18 + (int)_DAT_03fffff5 * 2) + bVar6;
      cVar9 = *(char *)((int)piVar18 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + cVar9,bVar6)) +
                        2);
      *puVar11 = *puVar11 | (uint)puVar11;
      _DAT_03fffffd = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
      *(char *)(in_ECX + 7) = *(char *)(in_ECX + 7) >> 8;
      *_DAT_03fffff5 = *_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
      _DAT_03ffffed = 0x4000001;
      _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar7);
      _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
      _DAT_03ffffcd = &DAT_03ffffe1;
      iVar16 = _DAT_03ffffd5 + in_ECX;
      pcVar21 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
      _DAT_03ffffc9 = unaff_EBP;
      _DAT_03ffffd1 = unaff_EBX;
      _DAT_03ffffd9 = in_ECX;
      _DAT_03ffffe1 = _DAT_03ffffc1;
      _DAT_03ffffe5 = _DAT_03ffffc5;
      _DAT_03ffffe9 = unaff_EBP;
      _DAT_03fffff1 = unaff_EBX;
      _DAT_03fffff9 = in_ECX;
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      bVar7 = (byte)pcVar21 | bVar7;
      piVar18 = (int *)((uint)pcVar21 & 0xffffff00 | (uint)bVar7);
      *piVar18 = *piVar18 + (int)piVar18;
      *(byte *)(piVar18 + iVar16 * 2) = *(char *)(piVar18 + iVar16 * 2) + bVar7;
      uVar14 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar21 & 0xffffff00) >> 8) +
                              *(char *)((int)piVar18 + 2),bVar7);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      iVar16 = *(int *)(uVar14 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar14 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      puVar32 = (undefined4 *)(iVar16 + uVar17 + 0x3ffffbd);
      *(undefined4 **)(iVar16 + uVar17 + 0x3ffffbd) = unaff_EBP;
      cVar9 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar32 = puVar32 + -1;
        *puVar32 = *unaff_EBP;
        cVar9 = cVar9 + -1;
      } while (0 < cVar9);
      *(uint *)(iVar16 + uVar17 + 0x3ffff9d) = iVar16 + uVar17 + 0x3ffffbd;
      uVar14 = (uint)CONCAT11(bVar6 / 1,bVar6) & 0xffffff00;
      uVar17 = (uint)puVar11 & 0xffff0000 | uVar14;
      pcVar21 = (char *)(uVar17 | (uint)bVar6 & 0xffffff01);
      cVar9 = (char)((uint)bVar6 & 0xffffff01);
      *pcVar21 = *pcVar21 + cVar9;
      bVar6 = cVar9 - 0x30;
      cVar9 = *(char *)((uVar17 | (uint)bVar6) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar14 >> 8) + cVar9,bVar6)) + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      pcVar5 = (code *)swi(3);
      iVar16 = (*pcVar5)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
      return iVar16;
    }
    bVar6 = bVar6 | (byte)(uVar12 >> 8);
    pcVar21 = (char *)(uVar14 | (uint)bVar6);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar12 * 8] = pcVar21[uVar12 * 8] + bVar6;
    cVar9 = pcVar21[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                       (uint)CONCAT11((char)(uVar14 >> 8) + cVar9,bVar6)) + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar6 = (char)puVar11 + 8;
    pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar12 * 8] = pcVar21[uVar12 * 8] + bVar6;
    cVar9 = pcVar21[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                       (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + cVar9,bVar6)) + 2)
    ;
    *puVar11 = *puVar11 | (uint)puVar11;
    piVar18 = (int *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
  }
  bVar24 = (byte)uVar12;
  *(byte *)piVar18 = *(byte *)piVar18 | bVar7;
  *piVar18 = *piVar18 + (int)piVar18;
  *(byte *)(piVar18 + uVar12 * 2) = *(byte *)(piVar18 + uVar12 * 2) + (char)piVar18;
  bVar6 = *(byte *)((int)piVar18 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(((uint)piVar18 & 0xffff0000 |
                     (uint)CONCAT11((char)((uint)piVar18 >> 8) + bVar6,(char)piVar18)) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
code_r0x080422ec:
  *(byte *)(in_ECX + 7) = bVar27;
  pcVar21[in_ECX] = pcVar21[in_ECX] | bVar24;
  *pcVar21 = *pcVar21 + (char)pcVar21;
  bVar6 = (char)pcVar21 - 0x30;
  cVar9 = *(char *)(((uint)pcVar21 & 0xffffff00 | (uint)bVar6) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(((uint)pcVar21 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar21 & 0xffffff00) >> 8) + cVar9,bVar6)) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

char * strerror(int __errnum)

{
  undefined uVar1;
  int iVar2;
  undefined *puVar3;
  undefined *puVar4;
  code *pcVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  char cVar9;
  ushort uVar10;
  uint *puVar11;
  uint uVar12;
  byte *pbVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  uint uVar17;
  int *piVar18;
  int iVar19;
  int iVar20;
  char *pcVar21;
  uint uVar22;
  uint uVar23;
  int in_ECX;
  byte bVar24;
  byte *in_EDX;
  byte *pbVar25;
  byte bVar26;
  byte bVar27;
  uint *unaff_EBX;
  int iVar28;
  undefined *puVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined4 *puVar32;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar33;
  byte in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar6 = (char)__errnum - 0x30;
  uVar12 = __errnum & 0xffff0000U |
           (uint)CONCAT11((char)((__errnum & 0xffffff00U) >> 8) +
                          *(char *)((__errnum & 0xffffff00U | (uint)bVar6) + 2),bVar6);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  iVar16 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar12 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  uVar12 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
  *(uint *)(&stack0x00000000 + iVar16 + (uVar17 - 4)) = uVar12;
  bVar24 = (byte)((uint)in_ECX >> 8);
  if ((char)bVar6 < 0) {
    *(byte *)(uVar12 * 2) = *(byte *)(uVar12 * 2) | bVar24;
    pcVar21 = (char *)(uVar12 + (int)in_EDX * 8);
    *pcVar21 = *pcVar21 + bVar6;
  }
  uVar14 = (uint)puVar11 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar12 + 2),bVar6);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar12 = (uint)((uVar12 & 1) != 0);
  puVar3 = &stack0x00000000 + iVar16 + *(int *)(uVar14 + 4) + (uVar17 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar14 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  pbVar13 = (byte *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
  *(undefined **)(puVar3 + (uVar12 - 4)) = puVar3 + uVar12;
  bVar27 = (byte)((uint)unaff_EBX >> 8);
  if ((char)bVar6 < 0) {
    *pbVar13 = *pbVar13 | bVar27;
    *pbVar13 = *pbVar13 + bVar6;
    pbVar13 = (byte *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 - 0x28));
  }
  uVar14 = (uint)pbVar13 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar13 >> 8) + pbVar13[2],(char)pbVar13);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  iVar16 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar14 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  uVar14 = *(uint *)(puVar3 + iVar16 + (uVar12 - 4) + uVar17);
  if ((char)((char)puVar11 + '\b') < 0) {
    pbVar13 = (byte *)(uVar14 * 2 + -0x2ffc0000);
    *pbVar13 = *pbVar13 | (byte)uVar14;
  }
  uVar15 = uVar14 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar14 >> 8) + *(char *)(uVar14 + 2),(byte)uVar14);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar19 = *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar15 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  uVar15 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
  iVar28 = *(int *)(puVar3 + iVar16 + (uVar12 - 4) + (uint)((uVar14 & 1) != 0) + iVar19 + uVar17 + 4
                   );
  puVar29 = (undefined *)(iVar28 + 4);
  if (-1 < (char)bVar6) {
    uVar12 = (uint)puVar11 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar15 + 2),bVar6)
    ;
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar29 = (undefined *)(iVar28 + 4 + *(int *)(uVar12 + 4) + (uint)((uVar17 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar12 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    uVar15 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  }
  *(byte *)(uVar15 + 0x4000000) = *(byte *)(uVar15 + 0x4000000) | (byte)in_EDX;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar29 + -4) = uVar15;
  *(int *)(puVar29 + -8) = in_ECX;
  *(byte **)(puVar29 + -0xc) = in_EDX;
  *(uint **)(puVar29 + -0x10) = unaff_EBX;
  *(undefined **)(puVar29 + -0x14) = puVar29;
  *(undefined4 **)(puVar29 + -0x18) = unaff_EBP;
  *(undefined **)(puVar29 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x20) = unaff_EDI;
  bVar8 = (byte)in_ECX;
  uVar17 = (uint)in_EDX & 0xffffff00 | (uint)(byte)((byte)in_EDX + bVar8);
  iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
  *(int *)(puVar29 + -0x24) = iVar16;
  *(int *)(puVar29 + -0x28) = in_ECX;
  *(uint *)(puVar29 + -0x2c) = uVar17;
  *(uint **)(puVar29 + -0x30) = unaff_EBX;
  *(undefined **)(puVar29 + -0x34) = puVar29 + -0x20;
  *(undefined4 **)(puVar29 + -0x38) = unaff_EBP;
  *(undefined **)(puVar29 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x40) = unaff_EDI;
  pbVar25 = (byte *)(uVar17 + in_ECX);
  pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
  *pcVar21 = *pcVar21 + bVar27;
  pbVar13 = (byte *)(pcVar21 + in_ECX);
  *pbVar13 = *pbVar13 & (byte)pcVar21;
  bVar6 = *pbVar13;
  *(char **)(puVar29 + -0x44) = pcVar21;
  *(int *)(puVar29 + -0x48) = in_ECX;
  *(byte **)(puVar29 + -0x4c) = pbVar25;
  *(uint **)(puVar29 + -0x50) = unaff_EBX;
  *(undefined **)(puVar29 + -0x54) = puVar29 + -0x40;
  *(undefined4 **)(puVar29 + -0x58) = unaff_EBP;
  *(undefined **)(puVar29 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x60) = unaff_EDI;
  bVar26 = (byte)unaff_EBX;
  if ((char)bVar6 < 0) {
    pbVar13 = (byte *)((int)pcVar21 * 2 + -0x2ffc0000);
    *pbVar13 = *pbVar13 | bVar26;
  }
  uVar12 = (uint)pcVar21 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(byte)pcVar21);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  iVar16 = *(int *)(uVar12 + 4);
  puVar30 = puVar29 + iVar16 + -0x60 + uVar17;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar12 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  uVar12 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
  if (-1 < (char)bVar6) {
    uVar14 = (uint)puVar11 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar12 + 2),bVar6)
    ;
    uVar12 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = puVar29 + iVar16 + -0x60 + (uint)((uVar12 & 1) != 0) + *(int *)(uVar14 + 4) + uVar17;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar14 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    uVar12 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  }
  *(byte *)(uVar12 + 0x4000000) = *(byte *)(uVar12 + 0x4000000) | bVar24;
  *pbVar25 = *pbVar25 << 1 | (char)*pbVar25 < 0;
  *(uint *)(puVar30 + -4) = uVar12;
  *(int *)(puVar30 + -8) = in_ECX;
  *(byte **)(puVar30 + -0xc) = pbVar25;
  *(uint **)(puVar30 + -0x10) = unaff_EBX;
  *(undefined **)(puVar30 + -0x14) = puVar30;
  *(undefined4 **)(puVar30 + -0x18) = unaff_EBP;
  *(undefined **)(puVar30 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x20) = unaff_EDI;
  uVar14 = (uint)pbVar25 & 0xffffff00 | (uint)(byte)((char)pbVar25 + bVar8);
  iVar16 = uVar12 - *(int *)(uVar12 + 0x13);
  *(int *)(puVar30 + -0x24) = iVar16;
  *(int *)(puVar30 + -0x28) = in_ECX;
  *(uint *)(puVar30 + -0x2c) = uVar14;
  *(uint **)(puVar30 + -0x30) = unaff_EBX;
  *(undefined **)(puVar30 + -0x34) = puVar30 + -0x20;
  *(undefined4 **)(puVar30 + -0x38) = unaff_EBP;
  *(undefined **)(puVar30 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x40) = unaff_EDI;
  uVar14 = uVar14 + in_ECX;
  pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
  *pcVar21 = *pcVar21 + bVar27;
  bVar6 = (byte)pcVar21;
  pcVar21[in_ECX] = pcVar21[in_ECX] & bVar6;
  *(undefined4 *)(puVar30 + -0x44) = 0xb4080779;
  *pcVar21 = *pcVar21 + bVar6;
  pcVar21[uVar14 * 8] = pcVar21[uVar14 * 8] + bVar6;
  uVar12 = (uint)pcVar21 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],bVar6);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar16 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar12 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
  puVar3 = unaff_EDI + 1;
  uVar1 = in((short)uVar14);
  *unaff_EDI = uVar1;
  if ((char)bVar6 < 0) {
    pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar14 * 8] = pcVar21[uVar14 * 8] + bVar6;
  }
  uVar15 = (uint)pcVar21 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(char)pcVar21);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar12 = (uint)((uVar12 & 1) != 0);
  puVar4 = puVar30 + *(int *)(uVar15 + 4) + (uint)((uVar17 & 1) != 0) + iVar16 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar15 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  uVar17 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
  cVar9 = (char)uVar14;
  if (SCARRY1((char)puVar11,'\b')) {
    *(uint *)(puVar4 + (uVar12 - 4)) = uVar17;
    *(int *)(puVar4 + (uVar12 - 8)) = in_ECX;
    *(uint *)(puVar4 + (uVar12 - 0xc)) = uVar14;
    *(uint **)(puVar4 + (uVar12 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar12)) = puVar4 + uVar12;
    *(undefined4 **)(puVar4 + (uVar12 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar12 - 0x1c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar12 - 0x20)) = puVar3;
    uVar14 = uVar14 & 0xffffff00 | (uint)(byte)(cVar9 + bVar8);
    iVar16 = uVar17 - *(int *)(uVar17 + 0x13);
    *(int *)(puVar4 + (uVar12 - 0x24)) = iVar16;
    *(int *)(puVar4 + (uVar12 - 0x28)) = in_ECX;
    *(uint *)(puVar4 + (uVar12 - 0x2c)) = uVar14;
    *(uint **)(puVar4 + (uVar12 - 0x30)) = unaff_EBX;
    *(undefined **)(puVar4 + (uVar12 - 0x34)) = puVar4 + (uVar12 - 0x20);
    *(undefined4 **)(puVar4 + (uVar12 - 0x38)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar12 - 0x3c)) = unaff_ESI;
    *(undefined **)(puVar4 + (uVar12 - 0x40)) = puVar3;
    uVar14 = uVar14 + in_ECX;
    piVar18 = (int *)(iVar16 - *(int *)(iVar16 + 9));
    *(byte *)piVar18 = *(byte *)piVar18 + bVar27;
    *(byte *)((int)piVar18 + in_ECX) = *(byte *)((int)piVar18 + in_ECX) & (byte)piVar18;
  }
  else {
    uVar17 = (uint)CONCAT11((byte)(((uint)puVar11 & 0xffffff00) >> 8) | bVar8,bVar6);
    pcVar21 = (char *)((uint)puVar11 & 0xffff0000 | uVar17);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar14 * 8] = pcVar21[uVar14 * 8] + bVar6;
    uVar15 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11((char)(uVar17 >> 8) + pcVar21[2],bVar6);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar17 = (uint)((uVar17 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar15 + 4) + uVar12 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar15 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar6 = (char)puVar11 + 8;
    uVar12 = (uint)puVar11 & 0xffffff00;
    uVar15 = uVar12 | (uint)bVar6;
    if (bVar6 == 0) {
      *(uint *)(puVar4 + (uVar17 - 4)) = uVar15;
      *(int *)(puVar4 + (uVar17 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar17 - 0xc)) = uVar14;
      *(uint **)(puVar4 + (uVar17 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar17)) = puVar4 + uVar17;
      *(undefined4 **)(puVar4 + (uVar17 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar17 - 0x20)) = puVar3;
      iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar4 + (uVar17 - 0x24)) = iVar16;
      *(int *)(puVar4 + (uVar17 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar17 - 0x2c)) = uVar14 & 0xffffff00 | (uint)(byte)(cVar9 + bVar8);
      *(uint **)(puVar4 + (uVar17 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar17 - 0x34)) = puVar4 + (uVar17 - 0x20);
      *(undefined4 **)(puVar4 + (uVar17 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar17 - 0x40)) = puVar3;
      bVar24 = cVar9 + bVar8 + bVar8;
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      goto code_r0x080422ec;
    }
    bVar6 = bVar6 | bVar26;
    pcVar21 = (char *)(uVar12 | (uint)bVar6);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar14 * 8] = pcVar21[uVar14 * 8] + bVar6;
    uVar15 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11((char)(uVar12 >> 8) + pcVar21[2],bVar6);
    uVar12 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar12 = (uint)((uVar12 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar15 + 4) + uVar17 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar15 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar6 = (char)puVar11 + 8;
    uVar17 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
    if ((char)bVar6 < 0) {
      *(uint *)(puVar4 + (uVar12 - 4)) = uVar17;
      *(int *)(puVar4 + (uVar12 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar12 - 0xc)) = uVar14;
      *(uint **)(puVar4 + (uVar12 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar12 - 0x14)) = puVar4 + uVar12;
      *(undefined4 **)(puVar4 + (uVar12 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar12 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar12 - 0x20)) = puVar3;
      iVar16 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar4 + (uVar12 - 0x24)) = iVar16;
      *(int *)(puVar4 + (uVar12 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar12 - 0x2c)) = uVar14 & 0xffffff00 | (uint)(byte)(cVar9 + bVar8);
      *(uint **)(puVar4 + (uVar12 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar12 - 0x34)) = puVar4 + (uVar12 - 0x20);
      *(undefined4 **)(puVar4 + (uVar12 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar12 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar12 - 0x40)) = puVar3;
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      return;
    }
    uVar17 = (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8),bVar6);
    pcVar21 = (char *)((uint)puVar11 & 0xffff0000 | uVar17);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar14 * 8] = pcVar21[uVar14 * 8] + bVar6;
    uVar15 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11((char)(uVar17 >> 8) + pcVar21[2],bVar6);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar17 = (uint)((uVar17 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar15 + 4) + uVar12 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar15 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar6 = (char)puVar11 + 8;
    uVar12 = (uint)puVar11 & 0xffffff00;
    uVar15 = uVar12 | (uint)bVar6;
    if (SCARRY1((char)puVar11,'\b') != (char)bVar6 < 0) {
      *(uint *)(puVar4 + (uVar17 - 4)) = uVar15;
      *(int *)(puVar4 + (uVar17 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar17 - 0xc)) = uVar14;
      *(uint **)(puVar4 + (uVar17 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar17 - 0x14)) = puVar4 + uVar17;
      *(undefined4 **)(puVar4 + (uVar17 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar17 - 0x20)) = puVar3;
      uVar12 = uVar14 & 0xffffff00 | (uint)(byte)(cVar9 + bVar8);
      iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar4 + (uVar17 - 0x24)) = iVar16;
      *(int *)(puVar4 + (uVar17 - 0x28)) = in_ECX;
      *(uint *)(puVar4 + (uVar17 - 0x2c)) = uVar12;
      *(uint **)(puVar4 + (uVar17 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar17 - 0x34)) = puVar4 + (uVar17 - 0x20);
      *(undefined4 **)(puVar4 + (uVar17 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar17 - 0x40)) = puVar3;
      pbVar25 = (byte *)(uVar12 + in_ECX);
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pbVar13 = (byte *)(pcVar21 + in_ECX);
      bVar6 = (byte)pcVar21;
      *pbVar13 = *pbVar13 & bVar6;
      if ((char)*pbVar13 < 0) {
        pcVar21[in_ECX] = pcVar21[in_ECX] | bVar24;
        *pcVar21 = *pcVar21 + bVar6;
        pcVar21 = (char *)((uint)pcVar21 & 0xffffff00 | (uint)(byte)(bVar6 - 0x30));
      }
      uVar14 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(char)pcVar21);
      bVar33 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar12 = (uint)bVar33;
      puVar4 = puVar4 + *(int *)(uVar14 + 4) + (uVar17 - 0x40);
      cVar9 = (char)puVar4 + bVar33;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar14 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      if ((char)bVar6 < 0) {
        puVar4[uVar12] = puVar4[uVar12] | bVar27;
        *(undefined **)(puVar4 + uVar12) = puVar4 + *(int *)(puVar4 + uVar12) + uVar12;
        puVar4[(int)pbVar25 * 8 + uVar12] = puVar4[(int)pbVar25 * 8 + uVar12] + cVar9;
      }
      uVar12 = (uint)(puVar4 + uVar12) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar4 + uVar12) >> 8) + puVar4[uVar12 + 2],cVar9);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      iVar16 = ((uint)puVar11 & 0xffffff00 | (uint)bVar6) + *(int *)(uVar12 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar12 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      uVar10 = (ushort)puVar11 & 0xff00 | (ushort)bVar6;
      iVar19 = (int)(short)uVar10;
      if ((char)bVar6 < 0) {
        *(byte *)(in_ECX + iVar19) = *(byte *)(in_ECX + iVar19) | bVar6;
        pcVar21 = (char *)(iVar19 + (int)pbVar25 * 8);
        *pcVar21 = *pcVar21 + bVar6;
      }
      iVar20 = CONCAT22((short)uVar10 >> 0xf,
                        CONCAT11((char)((uint)iVar19 >> 8) + *(char *)(iVar19 + 2),bVar6));
      uVar12 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(iVar20 + 4);
      uVar14 = (uint)((uVar12 & 1) != 0);
      uVar12 = *puVar11;
      iVar19 = iVar16 + uVar17 + *puVar11;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(iVar20 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (byte)puVar11;
      bVar7 = bVar6 + 8;
      pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar7);
      *(uint *)(iVar19 + uVar14 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar6,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar7 < 0) * 0x80 |
           (uint)(bVar7 == 0) * 0x40 |
           (uint)(((iVar16 + uVar17 & 0xfffffff) + (uVar12 & 0xfffffff) + uVar14 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar6) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if ((char)bVar7 < 0) {
        pcVar21[1] = pcVar21[1] | (byte)pbVar25;
        *pcVar21 = *pcVar21 + bVar7;
        pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)(bVar6 - 0x28));
      }
      uVar12 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(char)pcVar21);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar16 = *(int *)(uVar12 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar12 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = DAT_5c080779;
      piVar18 = (int *)((uint)puVar11 & 0xffffff00 | (uint)DAT_5c080779);
      *piVar18 = *piVar18 + (int)piVar18;
      *(byte *)(piVar18 + (int)pbVar25 * 2) = *(char *)(piVar18 + (int)pbVar25 * 2) + bVar6;
      uVar15 = (uint)puVar11 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)((int)piVar18 + 2),bVar6);
      uVar12 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar20 = *(int *)(uVar15 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar15 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
      _DAT_03ffffc1 = unaff_EDI + 2;
      *puVar3 = *unaff_ESI;
      if ((char)bVar6 < 0) {
        pcVar21[1] = pcVar21[1] | bVar24;
        *pcVar21 = *pcVar21 + bVar6;
        pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 - 0x28));
      }
      uVar22 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar21 >> 8) + pcVar21[2],(char)pcVar21);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar2 = *(int *)(uVar22 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar22 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      uVar22 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
      *(byte *)(in_ECX + uVar22) = *(byte *)(in_ECX + uVar22) | (byte)((uint)pbVar25 >> 8);
      pcVar21 = (char *)(uVar22 + (int)pbVar25 * 8);
      *pcVar21 = *pcVar21 + bVar6;
      uVar23 = (uint)puVar11 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar22 + 2),
                              bVar6);
      uVar22 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar22 = (uint)((uVar22 & 1) != 0);
      iVar16 = iVar19 + uVar14 + iVar16 + (uint)((uVar17 & 1) != 0) + iVar20 +
               (uint)((uVar12 & 1) != 0) + iVar2 + (uint)((uVar15 & 1) != 0) + -2 +
               *(int *)(uVar23 + 4);
      puVar31 = (undefined *)(iVar16 + uVar22);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar23 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      _DAT_03ffffc5 = unaff_ESI + 2;
      uVar17 = (uint)puVar11 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (-1 < (char)((char)puVar11 + '\b')) {
        uVar12 = (uint)puVar11 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)(uVar17 + 2),unaff_ESI[1]);
        uVar17 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar31 = (undefined *)(iVar16 + uVar22 + *(int *)(uVar12 + 4) + (uint)((uVar17 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar11 = (uint *)(uVar12 + 2);
        *puVar11 = *puVar11 | (uint)puVar11;
        uVar17 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
      }
      *(byte *)(uVar17 + 0x4000001) = *(byte *)(uVar17 + 0x4000001) | (byte)uVar17;
      *pbVar25 = *pbVar25 << 1 | (char)*pbVar25 < 0;
      *(uint *)(puVar31 + -4) = uVar17;
      *(int *)(puVar31 + -8) = in_ECX;
      *(byte **)(puVar31 + -0xc) = pbVar25;
      *(uint **)(puVar31 + -0x10) = unaff_EBX;
      *(undefined **)(puVar31 + -0x14) = puVar31;
      *(undefined4 **)(puVar31 + -0x18) = unaff_EBP;
      *(undefined **)(puVar31 + -0x1c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x20) = _DAT_03ffffc1;
      uVar12 = (uint)pbVar25 & 0xffffff00 | (uint)(byte)((byte)pbVar25 + bVar8);
      iVar16 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar31 + -0x24) = iVar16;
      *(int *)(puVar31 + -0x28) = in_ECX;
      *(uint *)(puVar31 + -0x2c) = uVar12;
      *(uint **)(puVar31 + -0x30) = unaff_EBX;
      *(undefined **)(puVar31 + -0x34) = puVar31 + -0x20;
      *(undefined4 **)(puVar31 + -0x38) = unaff_EBP;
      *(undefined **)(puVar31 + -0x3c) = _DAT_03ffffc5;
      *(undefined **)(puVar31 + -0x40) = _DAT_03ffffc1;
      pbVar25 = (byte *)(uVar12 + in_ECX);
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      iVar16 = CONCAT31((int3)((uint)pcVar21 >> 8),0x79);
      pbVar13 = (byte *)(in_ECX + -0x2ffc0000 + iVar16);
      *pbVar13 = *pbVar13 | bVar8;
      uVar12 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar21 >> 8) + *(char *)(iVar16 + 2),0x79);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      puVar3 = puVar31 + *(int *)(uVar12 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar12 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      uVar12 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar11 + '\b');
      *(byte *)(uVar12 + 0x4000001) = *(byte *)(uVar12 + 0x4000001) | bVar26;
      *pbVar25 = *pbVar25 << 1 | (char)*pbVar25 < 0;
      *(uint *)(puVar3 + uVar17) = uVar12;
      *(int *)(puVar3 + (uVar17 - 4)) = in_ECX;
      *(byte **)(puVar3 + (uVar17 - 8)) = pbVar25;
      *(uint **)(puVar3 + (uVar17 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar17 - 0x10)) = puVar3 + uVar17 + 4;
      *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar17)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar17 - 0x18)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar17 - 0x1c)) = _DAT_03ffffc1;
      uVar14 = (uint)pbVar25 & 0xffffff00 | (uint)(byte)((char)pbVar25 + bVar8);
      iVar16 = uVar12 - *(int *)(uVar12 + 0x13);
      *(int *)(puVar3 + (uVar17 - 0x20)) = iVar16;
      *(int *)(puVar3 + (uVar17 - 0x24)) = in_ECX;
      *(uint *)(puVar3 + (uVar17 - 0x28)) = uVar14;
      *(uint **)(puVar3 + (uVar17 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar17 - 0x30)) = puVar3 + (uVar17 - 0x1c);
      *(undefined4 **)(puVar3 + (uVar17 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar17 - 0x38)) = _DAT_03ffffc5;
      *(undefined **)(puVar3 + (uVar17 - 0x3c)) = _DAT_03ffffc1;
      _DAT_03fffff5 = (byte *)(uVar14 + in_ECX);
      pcVar21 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
      (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      piVar18 = (int *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
      *piVar18 = *piVar18 + (int)piVar18;
      *(byte *)(piVar18 + (int)_DAT_03fffff5 * 2) =
           *(char *)(piVar18 + (int)_DAT_03fffff5 * 2) + bVar6;
      cVar9 = *(char *)((int)piVar18 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + cVar9,bVar6)) +
                        2);
      *puVar11 = *puVar11 | (uint)puVar11;
      _DAT_03fffffd = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
      *(char *)(in_ECX + 7) = *(char *)(in_ECX + 7) >> 8;
      *_DAT_03fffff5 = *_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
      _DAT_03ffffed = 0x4000001;
      _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar8);
      _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
      _DAT_03ffffcd = &DAT_03ffffe1;
      iVar16 = _DAT_03ffffd5 + in_ECX;
      pcVar21 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
      _DAT_03ffffc9 = unaff_EBP;
      _DAT_03ffffd1 = unaff_EBX;
      _DAT_03ffffd9 = in_ECX;
      _DAT_03ffffe1 = _DAT_03ffffc1;
      _DAT_03ffffe5 = _DAT_03ffffc5;
      _DAT_03ffffe9 = unaff_EBP;
      _DAT_03fffff1 = unaff_EBX;
      _DAT_03fffff9 = in_ECX;
      *pcVar21 = *pcVar21 + bVar27;
      pcVar21[in_ECX] = pcVar21[in_ECX] & (byte)pcVar21;
      bVar8 = (byte)pcVar21 | bVar8;
      piVar18 = (int *)((uint)pcVar21 & 0xffffff00 | (uint)bVar8);
      *piVar18 = *piVar18 + (int)piVar18;
      *(byte *)(piVar18 + iVar16 * 2) = *(char *)(piVar18 + iVar16 * 2) + bVar8;
      uVar12 = (uint)pcVar21 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar21 & 0xffffff00) >> 8) +
                              *(char *)((int)piVar18 + 2),bVar8);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      iVar16 = *(int *)(uVar12 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar12 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      puVar32 = (undefined4 *)(iVar16 + uVar17 + 0x3ffffbd);
      *(undefined4 **)(iVar16 + uVar17 + 0x3ffffbd) = unaff_EBP;
      cVar9 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar32 = puVar32 + -1;
        *puVar32 = *unaff_EBP;
        cVar9 = cVar9 + -1;
      } while (0 < cVar9);
      *(uint *)(iVar16 + uVar17 + 0x3ffff9d) = iVar16 + uVar17 + 0x3ffffbd;
      uVar12 = (uint)CONCAT11(bVar6 / 1,bVar6) & 0xffffff00;
      uVar17 = (uint)puVar11 & 0xffff0000 | uVar12;
      pcVar21 = (char *)(uVar17 | (uint)bVar6 & 0xffffff01);
      cVar9 = (char)((uint)bVar6 & 0xffffff01);
      *pcVar21 = *pcVar21 + cVar9;
      bVar6 = cVar9 - 0x30;
      cVar9 = *(char *)((uVar17 | (uint)bVar6) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar12 >> 8) + cVar9,bVar6)) + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      pcVar5 = (code *)swi(3);
      pcVar21 = (char *)(*pcVar5)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
      return pcVar21;
    }
    bVar6 = bVar6 | (byte)(uVar14 >> 8);
    pcVar21 = (char *)(uVar12 | (uint)bVar6);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar14 * 8] = pcVar21[uVar14 * 8] + bVar6;
    cVar9 = pcVar21[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                       (uint)CONCAT11((char)(uVar12 >> 8) + cVar9,bVar6)) + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar6 = (char)puVar11 + 8;
    pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
    *pcVar21 = *pcVar21 + bVar6;
    pcVar21[uVar14 * 8] = pcVar21[uVar14 * 8] + bVar6;
    cVar9 = pcVar21[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                       (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + cVar9,bVar6)) + 2)
    ;
    *puVar11 = *puVar11 | (uint)puVar11;
    piVar18 = (int *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
  }
  bVar24 = (byte)uVar14;
  *(byte *)piVar18 = *(byte *)piVar18 | bVar8;
  *piVar18 = *piVar18 + (int)piVar18;
  *(byte *)(piVar18 + uVar14 * 2) = *(byte *)(piVar18 + uVar14 * 2) + (char)piVar18;
  bVar6 = *(byte *)((int)piVar18 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(((uint)piVar18 & 0xffff0000 |
                     (uint)CONCAT11((char)((uint)piVar18 >> 8) + bVar6,(char)piVar18)) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  pcVar21 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
code_r0x080422ec:
  *(byte *)(in_ECX + 7) = bVar27;
  pcVar21[in_ECX] = pcVar21[in_ECX] | bVar24;
  *pcVar21 = *pcVar21 + (char)pcVar21;
  bVar6 = (char)pcVar21 - 0x30;
  cVar9 = *(char *)(((uint)pcVar21 & 0xffffff00 | (uint)bVar6) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(((uint)pcVar21 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar21 & 0xffffff00) >> 8) + cVar9,bVar6)) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

void * memmove(void *__dest,void *__src,size_t __n)

{
  byte *pbVar1;
  undefined *puVar2;
  undefined uVar3;
  int iVar4;
  undefined *puVar5;
  code *pcVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  char cVar10;
  ushort uVar11;
  uint *puVar12;
  uint uVar13;
  int iVar14;
  uint uVar15;
  uint uVar16;
  int *piVar17;
  int iVar18;
  int iVar19;
  char *pcVar20;
  uint uVar21;
  uint uVar22;
  void *pvVar23;
  byte bVar24;
  byte bVar25;
  byte *pbVar26;
  uint uVar27;
  byte bVar28;
  uint *unaff_EBX;
  int iVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined *puVar32;
  undefined4 *puVar33;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar34;
  byte in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  
  bVar7 = (char)__dest - 0x30;
  uVar13 = (uint)__dest & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__dest & 0xffffff00) >> 8) +
                          *(char *)(((uint)__dest & 0xffffff00 | (uint)bVar7) + 2),bVar7);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  iVar14 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar13 = *(uint *)(&stack0x00000000 + iVar14 + uVar15);
  if ((char)((char)puVar12 + '\b') < 0) {
    pbVar1 = (byte *)(uVar13 * 2 + -0x2ffc0000);
    *pbVar1 = *pbVar1 | (byte)uVar13;
  }
  uVar27 = uVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar13 + 2),(byte)uVar13);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar18 = *(int *)(uVar27 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar27 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar27 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
  iVar29 = *(int *)(&stack0x00000000 + iVar14 + (uint)((uVar13 & 1) != 0) + iVar18 + uVar15 + 4);
  puVar30 = (undefined *)(iVar29 + 4);
  if (-1 < (char)bVar7) {
    uVar13 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar27 + 2),bVar7)
    ;
    uVar15 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = (undefined *)(iVar29 + 4 + *(int *)(uVar13 + 4) + (uint)((uVar15 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar13 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar27 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar27 + 0x4000000) = *(byte *)(uVar27 + 0x4000000) | (byte)__src;
  *(char *)__src = *(char *)__src << 1 | *(char *)__src < 0;
  *(uint *)(puVar30 + -4) = uVar27;
  *(size_t *)(puVar30 + -8) = __n;
  *(void **)(puVar30 + -0xc) = __src;
  *(uint **)(puVar30 + -0x10) = unaff_EBX;
  *(undefined **)(puVar30 + -0x14) = puVar30;
  *(undefined4 **)(puVar30 + -0x18) = unaff_EBP;
  *(undefined **)(puVar30 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x20) = unaff_EDI;
  bVar9 = (byte)__n;
  uVar15 = (uint)__src & 0xffffff00 | (uint)(byte)((byte)__src + bVar9);
  iVar14 = uVar27 - *(int *)(uVar27 + 0x13);
  *(int *)(puVar30 + -0x24) = iVar14;
  *(size_t *)(puVar30 + -0x28) = __n;
  *(uint *)(puVar30 + -0x2c) = uVar15;
  *(uint **)(puVar30 + -0x30) = unaff_EBX;
  *(undefined **)(puVar30 + -0x34) = puVar30 + -0x20;
  *(undefined4 **)(puVar30 + -0x38) = unaff_EBP;
  *(undefined **)(puVar30 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x40) = unaff_EDI;
  pbVar26 = (byte *)(uVar15 + __n);
  pcVar20 = (char *)(iVar14 - *(int *)(iVar14 + 9));
  bVar28 = (byte)((uint)unaff_EBX >> 8);
  *pcVar20 = *pcVar20 + bVar28;
  pbVar1 = (byte *)(pcVar20 + __n);
  *pbVar1 = *pbVar1 & (byte)pcVar20;
  bVar7 = *pbVar1;
  *(char **)(puVar30 + -0x44) = pcVar20;
  *(size_t *)(puVar30 + -0x48) = __n;
  *(byte **)(puVar30 + -0x4c) = pbVar26;
  *(uint **)(puVar30 + -0x50) = unaff_EBX;
  *(undefined **)(puVar30 + -0x54) = puVar30 + -0x40;
  *(undefined4 **)(puVar30 + -0x58) = unaff_EBP;
  *(undefined **)(puVar30 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x60) = unaff_EDI;
  bVar25 = (byte)unaff_EBX;
  if ((char)bVar7 < 0) {
    pbVar1 = (byte *)((int)pcVar20 * 2 + -0x2ffc0000);
    *pbVar1 = *pbVar1 | bVar25;
  }
  uVar13 = (uint)pcVar20 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar20 >> 8) + pcVar20[2],(byte)pcVar20);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  iVar14 = *(int *)(uVar13 + 4);
  puVar31 = puVar30 + iVar14 + -0x60 + uVar15;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar13 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
  if (-1 < (char)bVar7) {
    uVar27 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar13 + 2),bVar7)
    ;
    uVar13 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar31 = puVar30 + iVar14 + -0x60 + (uint)((uVar13 & 1) != 0) + *(int *)(uVar27 + 4) + uVar15;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar27 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar13 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  bVar24 = (byte)(__n >> 8);
  *(byte *)(uVar13 + 0x4000000) = *(byte *)(uVar13 + 0x4000000) | bVar24;
  *pbVar26 = *pbVar26 << 1 | (char)*pbVar26 < 0;
  *(uint *)(puVar31 + -4) = uVar13;
  *(size_t *)(puVar31 + -8) = __n;
  *(byte **)(puVar31 + -0xc) = pbVar26;
  *(uint **)(puVar31 + -0x10) = unaff_EBX;
  *(undefined **)(puVar31 + -0x14) = puVar31;
  *(undefined4 **)(puVar31 + -0x18) = unaff_EBP;
  *(undefined **)(puVar31 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar31 + -0x20) = unaff_EDI;
  uVar27 = (uint)pbVar26 & 0xffffff00 | (uint)(byte)((char)pbVar26 + bVar9);
  iVar14 = uVar13 - *(int *)(uVar13 + 0x13);
  *(int *)(puVar31 + -0x24) = iVar14;
  *(size_t *)(puVar31 + -0x28) = __n;
  *(uint *)(puVar31 + -0x2c) = uVar27;
  *(uint **)(puVar31 + -0x30) = unaff_EBX;
  *(undefined **)(puVar31 + -0x34) = puVar31 + -0x20;
  *(undefined4 **)(puVar31 + -0x38) = unaff_EBP;
  *(undefined **)(puVar31 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar31 + -0x40) = unaff_EDI;
  uVar27 = uVar27 + __n;
  pcVar20 = (char *)(iVar14 - *(int *)(iVar14 + 9));
  *pcVar20 = *pcVar20 + bVar28;
  bVar7 = (byte)pcVar20;
  pcVar20[__n] = pcVar20[__n] & bVar7;
  *(undefined4 *)(puVar31 + -0x44) = 0xb4080779;
  *pcVar20 = *pcVar20 + bVar7;
  pcVar20[uVar27 * 8] = pcVar20[uVar27 * 8] + bVar7;
  uVar13 = (uint)pcVar20 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar20 >> 8) + pcVar20[2],bVar7);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar14 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  pcVar20 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar7);
  puVar2 = unaff_EDI + 1;
  uVar3 = in((short)uVar27);
  *unaff_EDI = uVar3;
  if ((char)bVar7 < 0) {
    pcVar20 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar7);
    *pcVar20 = *pcVar20 + bVar7;
    pcVar20[uVar27 * 8] = pcVar20[uVar27 * 8] + bVar7;
  }
  uVar16 = (uint)pcVar20 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar20 >> 8) + pcVar20[2],(char)pcVar20);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar13 & 1) != 0);
  puVar5 = puVar31 + *(int *)(uVar16 + 4) + (uint)((uVar15 & 1) != 0) + iVar14 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar15 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
  cVar10 = (char)uVar27;
  if (SCARRY1((char)puVar12,'\b')) {
    *(uint *)(puVar5 + (uVar13 - 4)) = uVar15;
    *(size_t *)(puVar5 + (uVar13 - 8)) = __n;
    *(uint *)(puVar5 + (uVar13 - 0xc)) = uVar27;
    *(uint **)(puVar5 + (uVar13 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar5 + (int)(&DAT_ffffffec + uVar13)) = puVar5 + uVar13;
    *(undefined4 **)(puVar5 + (uVar13 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar5 + (uVar13 - 0x1c)) = unaff_ESI;
    *(undefined **)(puVar5 + (uVar13 - 0x20)) = puVar2;
    uVar27 = uVar27 & 0xffffff00 | (uint)(byte)(cVar10 + bVar9);
    iVar14 = uVar15 - *(int *)(uVar15 + 0x13);
    *(int *)(puVar5 + (uVar13 - 0x24)) = iVar14;
    *(size_t *)(puVar5 + (uVar13 - 0x28)) = __n;
    *(uint *)(puVar5 + (uVar13 - 0x2c)) = uVar27;
    *(uint **)(puVar5 + (uVar13 - 0x30)) = unaff_EBX;
    *(undefined **)(puVar5 + (uVar13 - 0x34)) = puVar5 + (uVar13 - 0x20);
    *(undefined4 **)(puVar5 + (uVar13 - 0x38)) = unaff_EBP;
    *(undefined **)(puVar5 + (uVar13 - 0x3c)) = unaff_ESI;
    *(undefined **)(puVar5 + (uVar13 - 0x40)) = puVar2;
    uVar27 = uVar27 + __n;
    piVar17 = (int *)(iVar14 - *(int *)(iVar14 + 9));
    *(byte *)piVar17 = *(byte *)piVar17 + bVar28;
    *(byte *)((int)piVar17 + __n) = *(byte *)((int)piVar17 + __n) & (byte)piVar17;
  }
  else {
    uVar15 = (uint)CONCAT11((byte)(((uint)puVar12 & 0xffffff00) >> 8) | bVar9,bVar7);
    pcVar20 = (char *)((uint)puVar12 & 0xffff0000 | uVar15);
    *pcVar20 = *pcVar20 + bVar7;
    pcVar20[uVar27 * 8] = pcVar20[uVar27 * 8] + bVar7;
    uVar16 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11((char)(uVar15 >> 8) + pcVar20[2],bVar7);
    uVar15 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar15 = (uint)((uVar15 & 1) != 0);
    puVar5 = puVar5 + *(int *)(uVar16 + 4) + uVar13 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar16 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar7 = (char)puVar12 + 8;
    uVar13 = (uint)puVar12 & 0xffffff00;
    uVar16 = uVar13 | (uint)bVar7;
    if (bVar7 == 0) {
      *(uint *)(puVar5 + (uVar15 - 4)) = uVar16;
      *(size_t *)(puVar5 + (uVar15 - 8)) = __n;
      *(uint *)(puVar5 + (uVar15 - 0xc)) = uVar27;
      *(uint **)(puVar5 + (uVar15 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar5 + (int)(&DAT_ffffffec + uVar15)) = puVar5 + uVar15;
      *(undefined4 **)(puVar5 + (uVar15 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar5 + (uVar15 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar5 + (uVar15 - 0x20)) = puVar2;
      iVar14 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar5 + (uVar15 - 0x24)) = iVar14;
      *(size_t *)(puVar5 + (uVar15 - 0x28)) = __n;
      *(uint *)(puVar5 + (uVar15 - 0x2c)) = uVar27 & 0xffffff00 | (uint)(byte)(cVar10 + bVar9);
      *(uint **)(puVar5 + (uVar15 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar5 + (uVar15 - 0x34)) = puVar5 + (uVar15 - 0x20);
      *(undefined4 **)(puVar5 + (uVar15 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar5 + (uVar15 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar5 + (uVar15 - 0x40)) = puVar2;
      bVar25 = cVar10 + bVar9 + bVar9;
      pcVar20 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar20 = *pcVar20 + bVar28;
      pcVar20[__n] = pcVar20[__n] & (byte)pcVar20;
      goto code_r0x080422ec;
    }
    bVar7 = bVar7 | bVar25;
    pcVar20 = (char *)(uVar13 | (uint)bVar7);
    *pcVar20 = *pcVar20 + bVar7;
    pcVar20[uVar27 * 8] = pcVar20[uVar27 * 8] + bVar7;
    uVar16 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11((char)(uVar13 >> 8) + pcVar20[2],bVar7);
    uVar13 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar13 = (uint)((uVar13 & 1) != 0);
    puVar5 = puVar5 + *(int *)(uVar16 + 4) + uVar15 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar16 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar7 = (char)puVar12 + 8;
    uVar15 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
    if ((char)bVar7 < 0) {
      *(uint *)(puVar5 + (uVar13 - 4)) = uVar15;
      *(size_t *)(puVar5 + (uVar13 - 8)) = __n;
      *(uint *)(puVar5 + (uVar13 - 0xc)) = uVar27;
      *(uint **)(puVar5 + (uVar13 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar5 + (uVar13 - 0x14)) = puVar5 + uVar13;
      *(undefined4 **)(puVar5 + (uVar13 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar5 + (uVar13 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar5 + (uVar13 - 0x20)) = puVar2;
      iVar14 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar5 + (uVar13 - 0x24)) = iVar14;
      *(size_t *)(puVar5 + (uVar13 - 0x28)) = __n;
      *(uint *)(puVar5 + (uVar13 - 0x2c)) = uVar27 & 0xffffff00 | (uint)(byte)(cVar10 + bVar9);
      *(uint **)(puVar5 + (uVar13 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar5 + (uVar13 - 0x34)) = puVar5 + (uVar13 - 0x20);
      *(undefined4 **)(puVar5 + (uVar13 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar5 + (uVar13 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar5 + (uVar13 - 0x40)) = puVar2;
      pcVar20 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar20 = *pcVar20 + bVar28;
      pcVar20[__n] = pcVar20[__n] & (byte)pcVar20;
      return;
    }
    uVar15 = (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8),bVar7);
    pcVar20 = (char *)((uint)puVar12 & 0xffff0000 | uVar15);
    *pcVar20 = *pcVar20 + bVar7;
    pcVar20[uVar27 * 8] = pcVar20[uVar27 * 8] + bVar7;
    uVar16 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11((char)(uVar15 >> 8) + pcVar20[2],bVar7);
    uVar15 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar15 = (uint)((uVar15 & 1) != 0);
    puVar5 = puVar5 + *(int *)(uVar16 + 4) + uVar13 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar16 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar7 = (char)puVar12 + 8;
    uVar13 = (uint)puVar12 & 0xffffff00;
    uVar16 = uVar13 | (uint)bVar7;
    if (SCARRY1((char)puVar12,'\b') != (char)bVar7 < 0) {
      *(uint *)(puVar5 + (uVar15 - 4)) = uVar16;
      *(size_t *)(puVar5 + (uVar15 - 8)) = __n;
      *(uint *)(puVar5 + (uVar15 - 0xc)) = uVar27;
      *(uint **)(puVar5 + (uVar15 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar5 + (uVar15 - 0x14)) = puVar5 + uVar15;
      *(undefined4 **)(puVar5 + (uVar15 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar5 + (uVar15 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar5 + (uVar15 - 0x20)) = puVar2;
      uVar13 = uVar27 & 0xffffff00 | (uint)(byte)(cVar10 + bVar9);
      iVar14 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar5 + (uVar15 - 0x24)) = iVar14;
      *(size_t *)(puVar5 + (uVar15 - 0x28)) = __n;
      *(uint *)(puVar5 + (uVar15 - 0x2c)) = uVar13;
      *(uint **)(puVar5 + (uVar15 - 0x30)) = unaff_EBX;
      *(undefined **)(puVar5 + (uVar15 - 0x34)) = puVar5 + (uVar15 - 0x20);
      *(undefined4 **)(puVar5 + (uVar15 - 0x38)) = unaff_EBP;
      *(undefined **)(puVar5 + (uVar15 - 0x3c)) = unaff_ESI;
      *(undefined **)(puVar5 + (uVar15 - 0x40)) = puVar2;
      pbVar26 = (byte *)(uVar13 + __n);
      pcVar20 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar20 = *pcVar20 + bVar28;
      pbVar1 = (byte *)(pcVar20 + __n);
      bVar7 = (byte)pcVar20;
      *pbVar1 = *pbVar1 & bVar7;
      if ((char)*pbVar1 < 0) {
        pcVar20[__n] = pcVar20[__n] | bVar24;
        *pcVar20 = *pcVar20 + bVar7;
        pcVar20 = (char *)((uint)pcVar20 & 0xffffff00 | (uint)(byte)(bVar7 - 0x30));
      }
      uVar27 = (uint)pcVar20 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar20 >> 8) + pcVar20[2],(char)pcVar20);
      bVar34 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar13 = (uint)bVar34;
      puVar5 = puVar5 + *(int *)(uVar27 + 4) + (uVar15 - 0x40);
      cVar10 = (char)puVar5 + bVar34;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar27 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = (char)puVar12 + 8;
      if ((char)bVar7 < 0) {
        puVar5[uVar13] = puVar5[uVar13] | bVar28;
        *(undefined **)(puVar5 + uVar13) = puVar5 + *(int *)(puVar5 + uVar13) + uVar13;
        puVar5[(int)pbVar26 * 8 + uVar13] = puVar5[(int)pbVar26 * 8 + uVar13] + cVar10;
      }
      uVar13 = (uint)(puVar5 + uVar13) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar5 + uVar13) >> 8) + puVar5[uVar13 + 2],cVar10);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar15 = (uint)((uVar15 & 1) != 0);
      iVar14 = ((uint)puVar12 & 0xffffff00 | (uint)bVar7) + *(int *)(uVar13 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = (char)puVar12 + 8;
      uVar11 = (ushort)puVar12 & 0xff00 | (ushort)bVar7;
      iVar18 = (int)(short)uVar11;
      if ((char)bVar7 < 0) {
        *(byte *)(__n + iVar18) = *(byte *)(__n + iVar18) | bVar7;
        pcVar20 = (char *)(iVar18 + (int)pbVar26 * 8);
        *pcVar20 = *pcVar20 + bVar7;
      }
      iVar19 = CONCAT22((short)uVar11 >> 0xf,
                        CONCAT11((char)((uint)iVar18 >> 8) + *(char *)(iVar18 + 2),bVar7));
      uVar13 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar19 + 4);
      uVar27 = (uint)((uVar13 & 1) != 0);
      uVar13 = *puVar12;
      iVar18 = iVar14 + uVar15 + *puVar12;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar19 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (byte)puVar12;
      bVar7 = bVar8 + 8;
      pcVar20 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar7);
      *(uint *)(iVar18 + uVar27 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar8,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar7 < 0) * 0x80 |
           (uint)(bVar7 == 0) * 0x40 |
           (uint)(((iVar14 + uVar15 & 0xfffffff) + (uVar13 & 0xfffffff) + uVar27 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar8) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if ((char)bVar7 < 0) {
        pcVar20[1] = pcVar20[1] | (byte)pbVar26;
        *pcVar20 = *pcVar20 + bVar7;
        pcVar20 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)(bVar8 - 0x28));
      }
      uVar13 = (uint)pcVar20 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar20 >> 8) + pcVar20[2],(char)pcVar20);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar14 = *(int *)(uVar13 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = DAT_5c080779;
      piVar17 = (int *)((uint)puVar12 & 0xffffff00 | (uint)DAT_5c080779);
      *piVar17 = *piVar17 + (int)piVar17;
      *(byte *)(piVar17 + (int)pbVar26 * 2) = *(char *)(piVar17 + (int)pbVar26 * 2) + bVar7;
      uVar16 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)((int)piVar17 + 2),bVar7);
      uVar13 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar19 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = (char)puVar12 + 8;
      pcVar20 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar7);
      _DAT_03ffffc1 = unaff_EDI + 2;
      *puVar2 = *unaff_ESI;
      if ((char)bVar7 < 0) {
        pcVar20[1] = pcVar20[1] | bVar24;
        *pcVar20 = *pcVar20 + bVar7;
        pcVar20 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
      }
      uVar21 = (uint)pcVar20 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar20 >> 8) + pcVar20[2],(char)pcVar20);
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar4 = *(int *)(uVar21 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar21 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = (char)puVar12 + 8;
      uVar21 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
      *(byte *)(__n + uVar21) = *(byte *)(__n + uVar21) | (byte)((uint)pbVar26 >> 8);
      pcVar20 = (char *)(uVar21 + (int)pbVar26 * 8);
      *pcVar20 = *pcVar20 + bVar7;
      uVar22 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar21 + 2),
                              bVar7);
      uVar21 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar21 = (uint)((uVar21 & 1) != 0);
      iVar14 = iVar18 + uVar27 + iVar14 + (uint)((uVar15 & 1) != 0) + iVar19 +
               (uint)((uVar13 & 1) != 0) + iVar4 + (uint)((uVar16 & 1) != 0) + -2 +
               *(int *)(uVar22 + 4);
      puVar32 = (undefined *)(iVar14 + uVar21);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar22 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_03ffffc5 = unaff_ESI + 2;
      uVar15 = (uint)puVar12 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (-1 < (char)((char)puVar12 + '\b')) {
        uVar13 = (uint)puVar12 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)(uVar15 + 2),unaff_ESI[1]);
        uVar15 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar32 = (undefined *)(iVar14 + uVar21 + *(int *)(uVar13 + 4) + (uint)((uVar15 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar12 = (uint *)(uVar13 + 2);
        *puVar12 = *puVar12 | (uint)puVar12;
        uVar15 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      }
      *(byte *)(uVar15 + 0x4000001) = *(byte *)(uVar15 + 0x4000001) | (byte)uVar15;
      *pbVar26 = *pbVar26 << 1 | (char)*pbVar26 < 0;
      *(uint *)(puVar32 + -4) = uVar15;
      *(size_t *)(puVar32 + -8) = __n;
      *(byte **)(puVar32 + -0xc) = pbVar26;
      *(uint **)(puVar32 + -0x10) = unaff_EBX;
      *(undefined **)(puVar32 + -0x14) = puVar32;
      *(undefined4 **)(puVar32 + -0x18) = unaff_EBP;
      *(undefined **)(puVar32 + -0x1c) = _DAT_03ffffc5;
      *(undefined **)(puVar32 + -0x20) = _DAT_03ffffc1;
      uVar13 = (uint)pbVar26 & 0xffffff00 | (uint)(byte)((byte)pbVar26 + bVar9);
      iVar14 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar32 + -0x24) = iVar14;
      *(size_t *)(puVar32 + -0x28) = __n;
      *(uint *)(puVar32 + -0x2c) = uVar13;
      *(uint **)(puVar32 + -0x30) = unaff_EBX;
      *(undefined **)(puVar32 + -0x34) = puVar32 + -0x20;
      *(undefined4 **)(puVar32 + -0x38) = unaff_EBP;
      *(undefined **)(puVar32 + -0x3c) = _DAT_03ffffc5;
      *(undefined **)(puVar32 + -0x40) = _DAT_03ffffc1;
      pbVar26 = (byte *)(uVar13 + __n);
      pcVar20 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar20 = *pcVar20 + bVar28;
      pcVar20[__n] = pcVar20[__n] & (byte)pcVar20;
      iVar14 = CONCAT31((int3)((uint)pcVar20 >> 8),0x79);
      pbVar1 = (byte *)(__n + 0xd0040000 + iVar14);
      *pbVar1 = *pbVar1 | bVar9;
      uVar13 = (uint)pcVar20 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar20 >> 8) + *(char *)(iVar14 + 2),0x79);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar15 = (uint)((uVar15 & 1) != 0);
      puVar2 = puVar32 + *(int *)(uVar13 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      uVar13 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar12 + '\b');
      *(byte *)(uVar13 + 0x4000001) = *(byte *)(uVar13 + 0x4000001) | bVar25;
      *pbVar26 = *pbVar26 << 1 | (char)*pbVar26 < 0;
      *(uint *)(puVar2 + uVar15) = uVar13;
      *(size_t *)(puVar2 + (uVar15 - 4)) = __n;
      *(byte **)(puVar2 + (uVar15 - 8)) = pbVar26;
      *(uint **)(puVar2 + (uVar15 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar2 + (uVar15 - 0x10)) = puVar2 + uVar15 + 4;
      *(undefined4 **)(puVar2 + (int)(&DAT_ffffffec + uVar15)) = unaff_EBP;
      *(undefined **)(puVar2 + (uVar15 - 0x18)) = _DAT_03ffffc5;
      *(undefined **)(puVar2 + (uVar15 - 0x1c)) = _DAT_03ffffc1;
      uVar27 = (uint)pbVar26 & 0xffffff00 | (uint)(byte)((char)pbVar26 + bVar9);
      iVar14 = uVar13 - *(int *)(uVar13 + 0x13);
      *(int *)(puVar2 + (uVar15 - 0x20)) = iVar14;
      *(size_t *)(puVar2 + (uVar15 - 0x24)) = __n;
      *(uint *)(puVar2 + (uVar15 - 0x28)) = uVar27;
      *(uint **)(puVar2 + (uVar15 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar2 + (uVar15 - 0x30)) = puVar2 + (uVar15 - 0x1c);
      *(undefined4 **)(puVar2 + (uVar15 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar2 + (uVar15 - 0x38)) = _DAT_03ffffc5;
      *(undefined **)(puVar2 + (uVar15 - 0x3c)) = _DAT_03ffffc1;
      _DAT_03fffff5 = (byte *)(uVar27 + __n);
      pcVar20 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar20 = *pcVar20 + bVar28;
      pcVar20[__n] = pcVar20[__n] & (byte)pcVar20;
      _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
      (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = (char)puVar12 + 8;
      piVar17 = (int *)((uint)puVar12 & 0xffffff00 | (uint)bVar7);
      *piVar17 = *piVar17 + (int)piVar17;
      *(byte *)(piVar17 + (int)_DAT_03fffff5 * 2) =
           *(char *)(piVar17 + (int)_DAT_03fffff5 * 2) + bVar7;
      cVar10 = *(char *)((int)piVar17 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + cVar10,bVar7)) +
                        2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_03fffffd = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      *(char *)(__n + 7) = *(char *)(__n + 7) >> 8;
      *_DAT_03fffff5 = *_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
      _DAT_03ffffed = 0x4000001;
      _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar9);
      _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
      _DAT_03ffffcd = &DAT_03ffffe1;
      iVar14 = _DAT_03ffffd5 + __n;
      pcVar20 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
      _DAT_03ffffc9 = unaff_EBP;
      _DAT_03ffffd1 = unaff_EBX;
      _DAT_03ffffd9 = __n;
      _DAT_03ffffe1 = _DAT_03ffffc1;
      _DAT_03ffffe5 = _DAT_03ffffc5;
      _DAT_03ffffe9 = unaff_EBP;
      _DAT_03fffff1 = unaff_EBX;
      _DAT_03fffff9 = __n;
      *pcVar20 = *pcVar20 + bVar28;
      pcVar20[__n] = pcVar20[__n] & (byte)pcVar20;
      bVar9 = (byte)pcVar20 | bVar9;
      piVar17 = (int *)((uint)pcVar20 & 0xffffff00 | (uint)bVar9);
      *piVar17 = *piVar17 + (int)piVar17;
      *(byte *)(piVar17 + iVar14 * 2) = *(char *)(piVar17 + iVar14 * 2) + bVar9;
      uVar13 = (uint)pcVar20 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar20 & 0xffffff00) >> 8) +
                              *(char *)((int)piVar17 + 2),bVar9);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar15 = (uint)((uVar15 & 1) != 0);
      iVar14 = *(int *)(uVar13 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = (char)puVar12 + 8;
      puVar33 = (undefined4 *)(iVar14 + uVar15 + 0x3ffffbd);
      *(undefined4 **)(iVar14 + uVar15 + 0x3ffffbd) = unaff_EBP;
      cVar10 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar33 = puVar33 + -1;
        *puVar33 = *unaff_EBP;
        cVar10 = cVar10 + -1;
      } while (0 < cVar10);
      *(uint *)(iVar14 + uVar15 + 0x3ffff9d) = iVar14 + uVar15 + 0x3ffffbd;
      uVar13 = (uint)CONCAT11(bVar7 / 1,bVar7) & 0xffffff00;
      uVar15 = (uint)puVar12 & 0xffff0000 | uVar13;
      pcVar20 = (char *)(uVar15 | (uint)bVar7 & 0xffffff01);
      cVar10 = (char)((uint)bVar7 & 0xffffff01);
      *pcVar20 = *pcVar20 + cVar10;
      bVar7 = cVar10 - 0x30;
      cVar10 = *(char *)((uVar15 | (uint)bVar7) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar13 >> 8) + cVar10,bVar7)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      pcVar6 = (code *)swi(3);
      pvVar23 = (void *)(*pcVar6)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
      return pvVar23;
    }
    bVar7 = bVar7 | (byte)(uVar27 >> 8);
    pcVar20 = (char *)(uVar13 | (uint)bVar7);
    *pcVar20 = *pcVar20 + bVar7;
    pcVar20[uVar27 * 8] = pcVar20[uVar27 * 8] + bVar7;
    cVar10 = pcVar20[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                       (uint)CONCAT11((char)(uVar13 >> 8) + cVar10,bVar7)) + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar7 = (char)puVar12 + 8;
    pcVar20 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar7);
    *pcVar20 = *pcVar20 + bVar7;
    pcVar20[uVar27 * 8] = pcVar20[uVar27 * 8] + bVar7;
    cVar10 = pcVar20[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                       (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + cVar10,bVar7)) + 2
                      );
    *puVar12 = *puVar12 | (uint)puVar12;
    piVar17 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
  }
  bVar25 = (byte)uVar27;
  *(byte *)piVar17 = *(byte *)piVar17 | bVar9;
  *piVar17 = *piVar17 + (int)piVar17;
  *(byte *)(piVar17 + uVar27 * 2) = *(byte *)(piVar17 + uVar27 * 2) + (char)piVar17;
  bVar7 = *(byte *)((int)piVar17 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(((uint)piVar17 & 0xffff0000 |
                     (uint)CONCAT11((char)((uint)piVar17 >> 8) + bVar7,(char)piVar17)) + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  pcVar20 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
code_r0x080422ec:
  *(byte *)(__n + 7) = bVar28;
  pcVar20[__n] = pcVar20[__n] | bVar25;
  *pcVar20 = *pcVar20 + (char)pcVar20;
  bVar7 = (char)pcVar20 - 0x30;
  cVar10 = *(char *)(((uint)pcVar20 & 0xffffff00 | (uint)bVar7) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(((uint)pcVar20 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar20 & 0xffffff00) >> 8) + cVar10,bVar7)) + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void MsgSend_r(uint uParm1)

{
  char cVar1;
  byte bVar2;
  uint *puVar3;
  uint *unaff_EBX;
  
  bVar2 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar2) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar3 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar2)) + 2);
  *puVar3 = *puVar3 | (uint)puVar3;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void TimerDestroy(uint uParm1,byte *pbParm2,int iParm3)

{
  byte *pbVar1;
  int iVar2;
  undefined *puVar3;
  code *pcVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  char cVar8;
  ushort uVar9;
  uint uVar10;
  uint *puVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  char *pcVar16;
  uint uVar17;
  uint uVar18;
  int iVar19;
  uint uVar20;
  int *piVar21;
  byte *pbVar22;
  byte bVar23;
  uint *unaff_EBX;
  undefined *puVar24;
  undefined4 *puVar25;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar26;
  byte in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  
  bVar5 = (char)uParm1 - 0x30;
  uVar10 = uParm1 & 0xffff0000 |
           (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                          *(char *)((uParm1 & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar20 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar19 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar5 = (char)puVar11 + 8;
  pcVar16 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar5);
  bVar7 = (byte)((uint)iParm3 >> 8);
  if ((char)bVar5 < 0) {
    pcVar16[iParm3] = pcVar16[iParm3] | bVar7;
    *pcVar16 = *pcVar16 + bVar5;
    pcVar16 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 - 0x28));
  }
  uVar12 = (uint)pcVar16 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar16 >> 8) + pcVar16[2],(char)pcVar16);
  bVar26 = (*unaff_EBX & 1) != 0;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar10 = (uint)bVar26;
  puVar3 = &stack0x00000000 + *(int *)(uVar12 + 4) + (uint)((uVar20 & 1) != 0) + iVar19;
  cVar8 = (char)puVar3 + bVar26;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar12 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar5 = (char)puVar11 + 8;
  bVar23 = (byte)((uint)unaff_EBX >> 8);
  if ((char)bVar5 < 0) {
    puVar3[uVar10] = puVar3[uVar10] | bVar23;
    *(undefined **)(puVar3 + uVar10) = puVar3 + *(int *)(puVar3 + uVar10) + uVar10;
    puVar3[(int)pbParm2 * 8 + uVar10] = puVar3[(int)pbParm2 * 8 + uVar10] + cVar8;
  }
  uVar10 = (uint)(puVar3 + uVar10) & 0xffff0000 |
           (uint)CONCAT11((char)((uint)(puVar3 + uVar10) >> 8) + puVar3[uVar10 + 2],cVar8);
  uVar20 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar20 = (uint)((uVar20 & 1) != 0);
  iVar19 = ((uint)puVar11 & 0xffffff00 | (uint)bVar5) + *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar5 = (char)puVar11 + 8;
  uVar9 = (ushort)puVar11 & 0xff00 | (ushort)bVar5;
  iVar13 = (int)(short)uVar9;
  if ((char)bVar5 < 0) {
    *(byte *)(iParm3 + iVar13) = *(byte *)(iParm3 + iVar13) | bVar5;
    pcVar16 = (char *)(iVar13 + (int)pbParm2 * 8);
    *pcVar16 = *pcVar16 + bVar5;
  }
  iVar14 = CONCAT22((short)uVar9 >> 0xf,
                    CONCAT11((char)((uint)iVar13 >> 8) + *(char *)(iVar13 + 2),bVar5));
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(iVar14 + 4);
  uVar12 = (uint)((uVar10 & 1) != 0);
  uVar10 = *puVar11;
  iVar13 = iVar19 + uVar20 + *puVar11;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(iVar14 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (byte)puVar11;
  bVar5 = bVar6 + 8;
  pcVar16 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar5);
  *(uint *)(iVar13 + uVar12 + -4) =
       (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar6,'\b') * 0x800 | (uint)(in_IF & 1) * 0x200 |
       (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar5 < 0) * 0x80 | (uint)(bVar5 == 0) * 0x40 |
       (uint)(((iVar19 + uVar20 & 0xfffffff) + (uVar10 & 0xfffffff) + uVar12 & 0x10000000) != 0) *
       0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar6) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  if ((char)bVar5 < 0) {
    pcVar16[1] = pcVar16[1] | (byte)pbParm2;
    *pcVar16 = *pcVar16 + bVar5;
    pcVar16 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)(bVar6 - 0x28));
  }
  uVar10 = (uint)pcVar16 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar16 >> 8) + pcVar16[2],(char)pcVar16);
  uVar20 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar19 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar5 = DAT_5c080779;
  piVar21 = (int *)((uint)puVar11 & 0xffffff00 | (uint)DAT_5c080779);
  *piVar21 = *piVar21 + (int)piVar21;
  *(byte *)(piVar21 + (int)pbParm2 * 2) = *(char *)(piVar21 + (int)pbParm2 * 2) + bVar5;
  uVar15 = (uint)puVar11 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)((int)piVar21 + 2),bVar5);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar14 = *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar15 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar5 = (char)puVar11 + 8;
  pcVar16 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar5);
  _DAT_03ffffc1 = unaff_EDI + 1;
  *unaff_EDI = *unaff_ESI;
  if ((char)bVar5 < 0) {
    pcVar16[1] = pcVar16[1] | bVar7;
    *pcVar16 = *pcVar16 + bVar5;
    pcVar16 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 - 0x28));
  }
  uVar17 = (uint)pcVar16 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar16 >> 8) + pcVar16[2],(char)pcVar16);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar17 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar17 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar5 = (char)puVar11 + 8;
  uVar17 = (uint)puVar11 & 0xffffff00 | (uint)bVar5;
  *(byte *)(iParm3 + uVar17) = *(byte *)(iParm3 + uVar17) | (byte)((uint)pbParm2 >> 8);
  pcVar16 = (char *)(uVar17 + (int)pbParm2 * 8);
  *pcVar16 = *pcVar16 + bVar5;
  uVar18 = (uint)puVar11 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar17 + 2),bVar5);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  iVar19 = iVar13 + uVar12 + iVar19 + (uint)((uVar20 & 1) != 0) + iVar14 + (uint)((uVar10 & 1) != 0)
           + iVar2 + (uint)((uVar15 & 1) != 0) + -2 + *(int *)(uVar18 + 4);
  puVar24 = (undefined *)(iVar19 + uVar17);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar18 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  _DAT_03ffffc5 = unaff_ESI + 2;
  uVar20 = (uint)puVar11 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
  if (-1 < (char)((char)puVar11 + '\b')) {
    uVar10 = (uint)puVar11 & 0xffff0000 |
             (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)(uVar20 + 2),unaff_ESI[1]);
    uVar20 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar24 = (undefined *)(iVar19 + uVar17 + *(int *)(uVar10 + 4) + (uint)((uVar20 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar10 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    uVar20 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  }
  *(byte *)(uVar20 + 0x4000001) = *(byte *)(uVar20 + 0x4000001) | (byte)uVar20;
  *pbParm2 = *pbParm2 << 1 | (char)*pbParm2 < 0;
  *(uint *)(puVar24 + -4) = uVar20;
  *(int *)(puVar24 + -8) = iParm3;
  *(byte **)(puVar24 + -0xc) = pbParm2;
  *(uint **)(puVar24 + -0x10) = unaff_EBX;
  *(undefined **)(puVar24 + -0x14) = puVar24;
  *(undefined4 **)(puVar24 + -0x18) = unaff_EBP;
  *(undefined **)(puVar24 + -0x1c) = _DAT_03ffffc5;
  *(undefined **)(puVar24 + -0x20) = _DAT_03ffffc1;
  bVar7 = (byte)iParm3;
  uVar10 = (uint)pbParm2 & 0xffffff00 | (uint)(byte)((byte)pbParm2 + bVar7);
  iVar19 = uVar20 - *(int *)(uVar20 + 0x13);
  *(int *)(puVar24 + -0x24) = iVar19;
  *(int *)(puVar24 + -0x28) = iParm3;
  *(uint *)(puVar24 + -0x2c) = uVar10;
  *(uint **)(puVar24 + -0x30) = unaff_EBX;
  *(undefined **)(puVar24 + -0x34) = puVar24 + -0x20;
  *(undefined4 **)(puVar24 + -0x38) = unaff_EBP;
  *(undefined **)(puVar24 + -0x3c) = _DAT_03ffffc5;
  *(undefined **)(puVar24 + -0x40) = _DAT_03ffffc1;
  pbVar22 = (byte *)(uVar10 + iParm3);
  pcVar16 = (char *)(iVar19 - *(int *)(iVar19 + 9));
  *pcVar16 = *pcVar16 + bVar23;
  pcVar16[iParm3] = pcVar16[iParm3] & (byte)pcVar16;
  iVar19 = CONCAT31((int3)((uint)pcVar16 >> 8),0x79);
  pbVar1 = (byte *)(iParm3 + -0x2ffc0000 + iVar19);
  *pbVar1 = *pbVar1 | bVar7;
  uVar10 = (uint)pcVar16 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar16 >> 8) + *(char *)(iVar19 + 2),0x79);
  uVar20 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar20 = (uint)((uVar20 & 1) != 0);
  puVar3 = puVar24 + *(int *)(uVar10 + 4) + -0x40;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  uVar10 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar11 + '\b');
  *(byte *)(uVar10 + 0x4000001) = *(byte *)(uVar10 + 0x4000001) | (byte)unaff_EBX;
  *pbVar22 = *pbVar22 << 1 | (char)*pbVar22 < 0;
  *(uint *)(puVar3 + uVar20) = uVar10;
  *(int *)(puVar3 + (uVar20 - 4)) = iParm3;
  *(byte **)(puVar3 + (uVar20 - 8)) = pbVar22;
  *(uint **)(puVar3 + (uVar20 - 0xc)) = unaff_EBX;
  *(undefined **)(puVar3 + (uVar20 - 0x10)) = puVar3 + uVar20 + 4;
  *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar20)) = unaff_EBP;
  *(undefined **)(puVar3 + (uVar20 - 0x18)) = _DAT_03ffffc5;
  *(undefined **)(puVar3 + (uVar20 - 0x1c)) = _DAT_03ffffc1;
  uVar12 = (uint)pbVar22 & 0xffffff00 | (uint)(byte)((char)pbVar22 + bVar7);
  iVar19 = uVar10 - *(int *)(uVar10 + 0x13);
  *(int *)(puVar3 + (uVar20 - 0x20)) = iVar19;
  *(int *)(puVar3 + (uVar20 - 0x24)) = iParm3;
  *(uint *)(puVar3 + (uVar20 - 0x28)) = uVar12;
  *(uint **)(puVar3 + (uVar20 - 0x2c)) = unaff_EBX;
  *(undefined **)(puVar3 + (uVar20 - 0x30)) = puVar3 + (uVar20 - 0x1c);
  *(undefined4 **)(puVar3 + (uVar20 - 0x34)) = unaff_EBP;
  *(undefined **)(puVar3 + (uVar20 - 0x38)) = _DAT_03ffffc5;
  *(undefined **)(puVar3 + (uVar20 - 0x3c)) = _DAT_03ffffc1;
  _DAT_03fffff5 = (byte *)(uVar12 + iParm3);
  pcVar16 = (char *)(iVar19 - *(int *)(iVar19 + 9));
  *pcVar16 = *pcVar16 + bVar23;
  pcVar16[iParm3] = pcVar16[iParm3] & (byte)pcVar16;
  _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
  (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar5 = (char)puVar11 + 8;
  piVar21 = (int *)((uint)puVar11 & 0xffffff00 | (uint)bVar5);
  *piVar21 = *piVar21 + (int)piVar21;
  *(byte *)(piVar21 + (int)_DAT_03fffff5 * 2) = *(char *)(piVar21 + (int)_DAT_03fffff5 * 2) + bVar5;
  cVar8 = *(char *)((int)piVar21 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + cVar8,bVar5)) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  _DAT_03fffffd = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  *(char *)(iParm3 + 7) = *(char *)(iParm3 + 7) >> 8;
  *_DAT_03fffff5 = *_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
  _DAT_03ffffed = 0x4000001;
  _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar7);
  _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
  _DAT_03ffffcd = &DAT_03ffffe1;
  iVar19 = _DAT_03ffffd5 + iParm3;
  pcVar16 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
  _DAT_03ffffc9 = unaff_EBP;
  _DAT_03ffffd1 = unaff_EBX;
  _DAT_03ffffd9 = iParm3;
  _DAT_03ffffe1 = _DAT_03ffffc1;
  _DAT_03ffffe5 = _DAT_03ffffc5;
  _DAT_03ffffe9 = unaff_EBP;
  _DAT_03fffff1 = unaff_EBX;
  _DAT_03fffff9 = iParm3;
  *pcVar16 = *pcVar16 + bVar23;
  pcVar16[iParm3] = pcVar16[iParm3] & (byte)pcVar16;
  bVar7 = (byte)pcVar16 | bVar7;
  piVar21 = (int *)((uint)pcVar16 & 0xffffff00 | (uint)bVar7);
  *piVar21 = *piVar21 + (int)piVar21;
  *(byte *)(piVar21 + iVar19 * 2) = *(char *)(piVar21 + iVar19 * 2) + bVar7;
  uVar10 = (uint)pcVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)pcVar16 & 0xffffff00) >> 8) + *(char *)((int)piVar21 + 2),
                          bVar7);
  uVar20 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar20 = (uint)((uVar20 & 1) != 0);
  iVar19 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar5 = (char)puVar11 + 8;
  puVar25 = (undefined4 *)(iVar19 + uVar20 + 0x3ffffbd);
  *(undefined4 **)(iVar19 + uVar20 + 0x3ffffbd) = unaff_EBP;
  cVar8 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar25 = puVar25 + -1;
    *puVar25 = *unaff_EBP;
    cVar8 = cVar8 + -1;
  } while (0 < cVar8);
  *(uint *)(iVar19 + uVar20 + 0x3ffff9d) = iVar19 + uVar20 + 0x3ffffbd;
  uVar10 = (uint)CONCAT11(bVar5 / 1,bVar5) & 0xffffff00;
  uVar20 = (uint)puVar11 & 0xffff0000 | uVar10;
  pcVar16 = (char *)(uVar20 | (uint)bVar5 & 0xffffff01);
  cVar8 = (char)((uint)bVar5 & 0xffffff01);
  *pcVar16 = *pcVar16 + cVar8;
  bVar5 = cVar8 - 0x30;
  cVar8 = *(char *)((uVar20 | (uint)bVar5) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 | (uint)CONCAT11((char)(uVar10 >> 8) + cVar8,bVar5)
                     ) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  pcVar4 = (code *)swi(3);
  (*pcVar4)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
  return;
}



// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int sem_destroy(sem_t *__sem)

{
  byte *pbVar1;
  int iVar2;
  undefined *puVar3;
  code *pcVar4;
  byte bVar5;
  byte bVar6;
  char cVar7;
  ushort uVar8;
  uint uVar9;
  uint *puVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  char *pcVar14;
  uint uVar15;
  uint uVar16;
  int iVar17;
  uint uVar18;
  int *piVar19;
  int in_ECX;
  byte *in_EDX;
  byte *pbVar20;
  uint uVar21;
  byte bVar22;
  uint *unaff_EBX;
  undefined *puVar23;
  undefined4 *puVar24;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar25;
  byte in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  
  bVar5 = (char)__sem - 0x30;
  uVar9 = (uint)__sem & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__sem & 0xffffff00) >> 8) +
                         *(char *)(((uint)__sem & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  bVar25 = (*unaff_EBX & 1) != 0;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)bVar25;
  puVar3 = &stack0x00000000 + *(int *)(uVar9 + 4);
  cVar7 = (char)puVar3 + bVar25;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar9 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  bVar5 = (char)puVar10 + 8;
  bVar22 = (byte)((uint)unaff_EBX >> 8);
  if ((char)bVar5 < 0) {
    puVar3[uVar18] = puVar3[uVar18] | bVar22;
    *(undefined **)(puVar3 + uVar18) = puVar3 + *(int *)(puVar3 + uVar18) + uVar18;
    puVar3[(int)in_EDX * 8 + uVar18] = puVar3[(int)in_EDX * 8 + uVar18] + cVar7;
  }
  uVar9 = (uint)(puVar3 + uVar18) & 0xffff0000 |
          (uint)CONCAT11((char)((uint)(puVar3 + uVar18) >> 8) + puVar3[uVar18 + 2],cVar7);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = ((uint)puVar10 & 0xffffff00 | (uint)bVar5) + *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar9 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  bVar5 = (char)puVar10 + 8;
  uVar8 = (ushort)puVar10 & 0xff00 | (ushort)bVar5;
  iVar11 = (int)(short)uVar8;
  if ((char)bVar5 < 0) {
    *(byte *)(in_ECX + iVar11) = *(byte *)(in_ECX + iVar11) | bVar5;
    pcVar14 = (char *)(iVar11 + (int)in_EDX * 8);
    *pcVar14 = *pcVar14 + bVar5;
  }
  iVar12 = CONCAT22((short)uVar8 >> 0xf,
                    CONCAT11((char)((uint)iVar11 >> 8) + *(char *)(iVar11 + 2),bVar5));
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(iVar12 + 4);
  uVar21 = (uint)((uVar9 & 1) != 0);
  uVar9 = *puVar10;
  iVar11 = iVar17 + uVar18 + *puVar10;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(iVar12 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  bVar6 = (byte)puVar10;
  bVar5 = bVar6 + 8;
  pcVar14 = (char *)((uint)puVar10 & 0xffffff00 | (uint)bVar5);
  *(uint *)(iVar11 + uVar21 + -4) =
       (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar6,'\b') * 0x800 | (uint)(in_IF & 1) * 0x200 |
       (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar5 < 0) * 0x80 | (uint)(bVar5 == 0) * 0x40 |
       (uint)(((iVar17 + uVar18 & 0xfffffff) + (uVar9 & 0xfffffff) + uVar21 & 0x10000000) != 0) *
       0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar6) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  if ((char)bVar5 < 0) {
    pcVar14[1] = pcVar14[1] | (byte)in_EDX;
    *pcVar14 = *pcVar14 + bVar5;
    pcVar14 = (char *)((uint)puVar10 & 0xffffff00 | (uint)(byte)(bVar6 - 0x28));
  }
  uVar9 = (uint)pcVar14 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)pcVar14 >> 8) + pcVar14[2],(char)pcVar14);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar17 = *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar9 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  bVar5 = DAT_5c080779;
  piVar19 = (int *)((uint)puVar10 & 0xffffff00 | (uint)DAT_5c080779);
  *piVar19 = *piVar19 + (int)piVar19;
  *(byte *)(piVar19 + (int)in_EDX * 2) = *(char *)(piVar19 + (int)in_EDX * 2) + bVar5;
  uVar13 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)puVar10 >> 8) + *(char *)((int)piVar19 + 2),bVar5);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar12 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar13 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  bVar5 = (char)puVar10 + 8;
  pcVar14 = (char *)((uint)puVar10 & 0xffffff00 | (uint)bVar5);
  _DAT_03ffffc1 = unaff_EDI + 1;
  *unaff_EDI = *unaff_ESI;
  if ((char)bVar5 < 0) {
    pcVar14[1] = pcVar14[1] | (byte)((uint)in_ECX >> 8);
    *pcVar14 = *pcVar14 + bVar5;
    pcVar14 = (char *)((uint)puVar10 & 0xffffff00 | (uint)(byte)((char)puVar10 - 0x28));
  }
  uVar15 = (uint)pcVar14 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar14 >> 8) + pcVar14[2],(char)pcVar14);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar15 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  bVar5 = (char)puVar10 + 8;
  uVar15 = (uint)puVar10 & 0xffffff00 | (uint)bVar5;
  *(byte *)(in_ECX + uVar15) = *(byte *)(in_ECX + uVar15) | (byte)((uint)in_EDX >> 8);
  pcVar14 = (char *)(uVar15 + (int)in_EDX * 8);
  *pcVar14 = *pcVar14 + bVar5;
  uVar16 = (uint)puVar10 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + *(char *)(uVar15 + 2),bVar5);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  iVar17 = iVar11 + uVar21 + iVar17 + (uint)((uVar18 & 1) != 0) + iVar12 + (uint)((uVar9 & 1) != 0)
           + iVar2 + (uint)((uVar13 & 1) != 0) + -2 + *(int *)(uVar16 + 4);
  puVar23 = (undefined *)(iVar17 + uVar15);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar16 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  _DAT_03ffffc5 = unaff_ESI + 2;
  uVar18 = (uint)puVar10 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
  if (-1 < (char)((char)puVar10 + '\b')) {
    uVar9 = (uint)puVar10 & 0xffff0000 |
            (uint)CONCAT11((char)((uint)puVar10 >> 8) + *(char *)(uVar18 + 2),unaff_ESI[1]);
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (undefined *)(iVar17 + uVar15 + *(int *)(uVar9 + 4) + (uint)((uVar18 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar10 = (uint *)(uVar9 + 2);
    *puVar10 = *puVar10 | (uint)puVar10;
    uVar18 = (uint)puVar10 & 0xffffff00 | (uint)(byte)((char)puVar10 + 8);
  }
  *(byte *)(uVar18 + 0x4000001) = *(byte *)(uVar18 + 0x4000001) | (byte)uVar18;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar23 + -4) = uVar18;
  *(int *)(puVar23 + -8) = in_ECX;
  *(byte **)(puVar23 + -0xc) = in_EDX;
  *(uint **)(puVar23 + -0x10) = unaff_EBX;
  *(undefined **)(puVar23 + -0x14) = puVar23;
  *(undefined4 **)(puVar23 + -0x18) = unaff_EBP;
  *(undefined **)(puVar23 + -0x1c) = _DAT_03ffffc5;
  *(undefined **)(puVar23 + -0x20) = _DAT_03ffffc1;
  bVar6 = (byte)in_ECX;
  uVar9 = (uint)in_EDX & 0xffffff00 | (uint)(byte)((byte)in_EDX + bVar6);
  iVar17 = uVar18 - *(int *)(uVar18 + 0x13);
  *(int *)(puVar23 + -0x24) = iVar17;
  *(int *)(puVar23 + -0x28) = in_ECX;
  *(uint *)(puVar23 + -0x2c) = uVar9;
  *(uint **)(puVar23 + -0x30) = unaff_EBX;
  *(undefined **)(puVar23 + -0x34) = puVar23 + -0x20;
  *(undefined4 **)(puVar23 + -0x38) = unaff_EBP;
  *(undefined **)(puVar23 + -0x3c) = _DAT_03ffffc5;
  *(undefined **)(puVar23 + -0x40) = _DAT_03ffffc1;
  pbVar20 = (byte *)(uVar9 + in_ECX);
  pcVar14 = (char *)(iVar17 - *(int *)(iVar17 + 9));
  *pcVar14 = *pcVar14 + bVar22;
  pcVar14[in_ECX] = pcVar14[in_ECX] & (byte)pcVar14;
  iVar17 = CONCAT31((int3)((uint)pcVar14 >> 8),0x79);
  pbVar1 = (byte *)(in_ECX + -0x2ffc0000 + iVar17);
  *pbVar1 = *pbVar1 | bVar6;
  uVar9 = (uint)pcVar14 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)pcVar14 >> 8) + *(char *)(iVar17 + 2),0x79);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  puVar3 = puVar23 + *(int *)(uVar9 + 4) + -0x40;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar9 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  uVar9 = (uint)puVar10 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar10 + '\b');
  *(byte *)(uVar9 + 0x4000001) = *(byte *)(uVar9 + 0x4000001) | (byte)unaff_EBX;
  *pbVar20 = *pbVar20 << 1 | (char)*pbVar20 < 0;
  *(uint *)(puVar3 + uVar18) = uVar9;
  *(int *)(puVar3 + (uVar18 - 4)) = in_ECX;
  *(byte **)(puVar3 + (uVar18 - 8)) = pbVar20;
  *(uint **)(puVar3 + (uVar18 - 0xc)) = unaff_EBX;
  *(undefined **)(puVar3 + (uVar18 - 0x10)) = puVar3 + uVar18 + 4;
  *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar18)) = unaff_EBP;
  *(undefined **)(puVar3 + (uVar18 - 0x18)) = _DAT_03ffffc5;
  *(undefined **)(puVar3 + (uVar18 - 0x1c)) = _DAT_03ffffc1;
  uVar21 = (uint)pbVar20 & 0xffffff00 | (uint)(byte)((char)pbVar20 + bVar6);
  iVar17 = uVar9 - *(int *)(uVar9 + 0x13);
  *(int *)(puVar3 + (uVar18 - 0x20)) = iVar17;
  *(int *)(puVar3 + (uVar18 - 0x24)) = in_ECX;
  *(uint *)(puVar3 + (uVar18 - 0x28)) = uVar21;
  *(uint **)(puVar3 + (uVar18 - 0x2c)) = unaff_EBX;
  *(undefined **)(puVar3 + (uVar18 - 0x30)) = puVar3 + (uVar18 - 0x1c);
  *(undefined4 **)(puVar3 + (uVar18 - 0x34)) = unaff_EBP;
  *(undefined **)(puVar3 + (uVar18 - 0x38)) = _DAT_03ffffc5;
  *(undefined **)(puVar3 + (uVar18 - 0x3c)) = _DAT_03ffffc1;
  _DAT_03fffff5 = (byte *)(uVar21 + in_ECX);
  pcVar14 = (char *)(iVar17 - *(int *)(iVar17 + 9));
  *pcVar14 = *pcVar14 + bVar22;
  pcVar14[in_ECX] = pcVar14[in_ECX] & (byte)pcVar14;
  _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
  (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  bVar5 = (char)puVar10 + 8;
  piVar19 = (int *)((uint)puVar10 & 0xffffff00 | (uint)bVar5);
  *piVar19 = *piVar19 + (int)piVar19;
  *(byte *)(piVar19 + (int)_DAT_03fffff5 * 2) = *(char *)(piVar19 + (int)_DAT_03fffff5 * 2) + bVar5;
  cVar7 = *(char *)((int)piVar19 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(((uint)puVar10 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar10 & 0xffffff00) >> 8) + cVar7,bVar5)) + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  _DAT_03fffffd = (uint)puVar10 & 0xffffff00 | (uint)(byte)((char)puVar10 + 8);
  *(char *)(in_ECX + 7) = *(char *)(in_ECX + 7) >> 8;
  *_DAT_03fffff5 = *_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
  _DAT_03ffffed = 0x4000001;
  _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar6);
  _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
  _DAT_03ffffcd = &DAT_03ffffe1;
  iVar17 = _DAT_03ffffd5 + in_ECX;
  pcVar14 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
  _DAT_03ffffc9 = unaff_EBP;
  _DAT_03ffffd1 = unaff_EBX;
  _DAT_03ffffd9 = in_ECX;
  _DAT_03ffffe1 = _DAT_03ffffc1;
  _DAT_03ffffe5 = _DAT_03ffffc5;
  _DAT_03ffffe9 = unaff_EBP;
  _DAT_03fffff1 = unaff_EBX;
  _DAT_03fffff9 = in_ECX;
  *pcVar14 = *pcVar14 + bVar22;
  pcVar14[in_ECX] = pcVar14[in_ECX] & (byte)pcVar14;
  bVar6 = (byte)pcVar14 | bVar6;
  piVar19 = (int *)((uint)pcVar14 & 0xffffff00 | (uint)bVar6);
  *piVar19 = *piVar19 + (int)piVar19;
  *(byte *)(piVar19 + iVar17 * 2) = *(char *)(piVar19 + iVar17 * 2) + bVar6;
  uVar9 = (uint)pcVar14 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)pcVar14 & 0xffffff00) >> 8) + *(char *)((int)piVar19 + 2),
                         bVar6);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(uVar9 + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  bVar5 = (char)puVar10 + 8;
  puVar24 = (undefined4 *)(iVar17 + uVar18 + 0x3ffffbd);
  *(undefined4 **)(iVar17 + uVar18 + 0x3ffffbd) = unaff_EBP;
  cVar7 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar24 = puVar24 + -1;
    *puVar24 = *unaff_EBP;
    cVar7 = cVar7 + -1;
  } while (0 < cVar7);
  *(uint *)(iVar17 + uVar18 + 0x3ffff9d) = iVar17 + uVar18 + 0x3ffffbd;
  uVar9 = (uint)CONCAT11(bVar5 / 1,bVar5) & 0xffffff00;
  uVar18 = (uint)puVar10 & 0xffff0000 | uVar9;
  pcVar14 = (char *)(uVar18 | (uint)bVar5 & 0xffffff01);
  cVar7 = (char)((uint)bVar5 & 0xffffff01);
  *pcVar14 = *pcVar14 + cVar7;
  bVar5 = cVar7 - 0x30;
  cVar7 = *(char *)((uVar18 | (uint)bVar5) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar10 = (uint *)(((uint)puVar10 & 0xffff0000 | (uint)CONCAT11((char)(uVar9 >> 8) + cVar7,bVar5))
                    + 2);
  *puVar10 = *puVar10 | (uint)puVar10;
  pcVar4 = (code *)swi(3);
  iVar17 = (*pcVar4)((uint)puVar10 & 0xffffff00 | (uint)(byte)((char)puVar10 + 8));
  return iVar17;
}



// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SignalProcmask(uint uParm1,byte *pbParm2,int iParm3)

{
  byte *pbVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  code *pcVar6;
  byte bVar7;
  byte bVar8;
  char cVar9;
  uint uVar10;
  uint *puVar11;
  uint uVar12;
  char *pcVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  uint uVar17;
  int *piVar18;
  uint uVar19;
  byte *pbVar20;
  char cVar21;
  uint *unaff_EBX;
  undefined *puVar22;
  undefined4 *puVar23;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  
  bVar7 = (char)uParm1 - 0x30;
  uVar10 = uParm1 & 0xffff0000 |
           (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                          *(char *)((uParm1 & 0xffffff00 | (uint)bVar7) + 2),bVar7);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar16 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = DAT_5c080779;
  piVar18 = (int *)((uint)puVar11 & 0xffffff00 | (uint)DAT_5c080779);
  *piVar18 = *piVar18 + (int)piVar18;
  *(byte *)(piVar18 + (int)pbParm2 * 2) = *(char *)(piVar18 + (int)pbParm2 * 2) + bVar7;
  uVar12 = (uint)puVar11 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)((int)piVar18 + 2),bVar7);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar12 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  pcVar13 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar7);
  _DAT_03ffffc1 = unaff_EDI + 1;
  *unaff_EDI = *unaff_ESI;
  if ((char)bVar7 < 0) {
    pcVar13[1] = pcVar13[1] | (byte)((uint)iParm3 >> 8);
    *pcVar13 = *pcVar13 + bVar7;
    pcVar13 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 - 0x28));
  }
  uVar14 = (uint)pcVar13 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar13 >> 8) + pcVar13[2],(char)pcVar13);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar14 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  uVar14 = (uint)puVar11 & 0xffffff00 | (uint)bVar7;
  *(byte *)(iParm3 + uVar14) = *(byte *)(iParm3 + uVar14) | (byte)((uint)pbParm2 >> 8);
  pcVar13 = (char *)(uVar14 + (int)pbParm2 * 8);
  *pcVar13 = *pcVar13 + bVar7;
  uVar17 = (uint)puVar11 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),bVar7);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  iVar4 = *(int *)(uVar17 + 4);
  puVar22 = &stack0x00000002 +
            iVar4 + (uint)((uVar12 & 1) != 0) +
                    iVar3 + (uint)((uVar10 & 1) != 0) + iVar2 + (uint)((uVar19 & 1) != 0) + iVar16 +
            uVar14;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar17 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  _DAT_03ffffc5 = unaff_ESI + 2;
  uVar17 = (uint)puVar11 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
  if (-1 < (char)((char)puVar11 + '\b')) {
    uVar15 = (uint)puVar11 & 0xffff0000 |
             (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)(uVar17 + 2),unaff_ESI[1]);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar22 = &stack0x00000002 +
              iVar4 + (uint)((uVar12 & 1) != 0) +
                      iVar3 + (uint)((uVar10 & 1) != 0) + iVar2 + (uint)((uVar19 & 1) != 0) + iVar16
              + (uint)((uVar17 & 1) != 0) + *(int *)(uVar15 + 4) + uVar14;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar15 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    uVar17 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  }
  *(byte *)(uVar17 + 0x4000001) = *(byte *)(uVar17 + 0x4000001) | (byte)uVar17;
  *pbParm2 = *pbParm2 << 1 | (char)*pbParm2 < 0;
  *(uint *)(puVar22 + -4) = uVar17;
  *(int *)(puVar22 + -8) = iParm3;
  *(byte **)(puVar22 + -0xc) = pbParm2;
  *(uint **)(puVar22 + -0x10) = unaff_EBX;
  *(undefined **)(puVar22 + -0x14) = puVar22;
  *(undefined4 **)(puVar22 + -0x18) = unaff_EBP;
  *(undefined **)(puVar22 + -0x1c) = _DAT_03ffffc5;
  *(undefined **)(puVar22 + -0x20) = _DAT_03ffffc1;
  bVar8 = (byte)iParm3;
  uVar19 = (uint)pbParm2 & 0xffffff00 | (uint)(byte)((char)pbParm2 + bVar8);
  iVar16 = uVar17 - *(int *)(uVar17 + 0x13);
  *(int *)(puVar22 + -0x24) = iVar16;
  *(int *)(puVar22 + -0x28) = iParm3;
  *(uint *)(puVar22 + -0x2c) = uVar19;
  *(uint **)(puVar22 + -0x30) = unaff_EBX;
  *(undefined **)(puVar22 + -0x34) = puVar22 + -0x20;
  *(undefined4 **)(puVar22 + -0x38) = unaff_EBP;
  *(undefined **)(puVar22 + -0x3c) = _DAT_03ffffc5;
  *(undefined **)(puVar22 + -0x40) = _DAT_03ffffc1;
  pbVar20 = (byte *)(uVar19 + iParm3);
  pcVar13 = (char *)(iVar16 - *(int *)(iVar16 + 9));
  cVar21 = (char)((uint)unaff_EBX >> 8);
  *pcVar13 = *pcVar13 + cVar21;
  pcVar13[iParm3] = pcVar13[iParm3] & (byte)pcVar13;
  iVar16 = CONCAT31((int3)((uint)pcVar13 >> 8),0x79);
  pbVar1 = (byte *)(iParm3 + -0x2ffc0000 + iVar16);
  *pbVar1 = *pbVar1 | bVar8;
  uVar10 = (uint)pcVar13 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar13 >> 8) + *(char *)(iVar16 + 2),0x79);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar19 = (uint)((uVar19 & 1) != 0);
  puVar5 = puVar22 + *(int *)(uVar10 + 4) + -0x40;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  uVar10 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar11 + '\b');
  *(byte *)(uVar10 + 0x4000001) = *(byte *)(uVar10 + 0x4000001) | (byte)unaff_EBX;
  *pbVar20 = *pbVar20 << 1 | (char)*pbVar20 < 0;
  *(uint *)(puVar5 + uVar19) = uVar10;
  *(int *)(puVar5 + (uVar19 - 4)) = iParm3;
  *(byte **)(puVar5 + (uVar19 - 8)) = pbVar20;
  *(uint **)(puVar5 + (uVar19 - 0xc)) = unaff_EBX;
  *(undefined **)(puVar5 + (uVar19 - 0x10)) = puVar5 + uVar19 + 4;
  *(undefined4 **)(puVar5 + (int)(&DAT_ffffffec + uVar19)) = unaff_EBP;
  *(undefined **)(puVar5 + (uVar19 - 0x18)) = _DAT_03ffffc5;
  *(undefined **)(puVar5 + (uVar19 - 0x1c)) = _DAT_03ffffc1;
  uVar12 = (uint)pbVar20 & 0xffffff00 | (uint)(byte)((char)pbVar20 + bVar8);
  iVar16 = uVar10 - *(int *)(uVar10 + 0x13);
  *(int *)(puVar5 + (uVar19 - 0x20)) = iVar16;
  *(int *)(puVar5 + (uVar19 - 0x24)) = iParm3;
  *(uint *)(puVar5 + (uVar19 - 0x28)) = uVar12;
  *(uint **)(puVar5 + (uVar19 - 0x2c)) = unaff_EBX;
  *(undefined **)(puVar5 + (uVar19 - 0x30)) = puVar5 + (uVar19 - 0x1c);
  *(undefined4 **)(puVar5 + (uVar19 - 0x34)) = unaff_EBP;
  *(undefined **)(puVar5 + (uVar19 - 0x38)) = _DAT_03ffffc5;
  *(undefined **)(puVar5 + (uVar19 - 0x3c)) = _DAT_03ffffc1;
  _DAT_03fffff5 = (byte *)(uVar12 + iParm3);
  pcVar13 = (char *)(iVar16 - *(int *)(iVar16 + 9));
  *pcVar13 = *pcVar13 + cVar21;
  pcVar13[iParm3] = pcVar13[iParm3] & (byte)pcVar13;
  _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
  (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  piVar18 = (int *)((uint)puVar11 & 0xffffff00 | (uint)bVar7);
  *piVar18 = *piVar18 + (int)piVar18;
  *(byte *)(piVar18 + (int)_DAT_03fffff5 * 2) = *(char *)(piVar18 + (int)_DAT_03fffff5 * 2) + bVar7;
  cVar9 = *(char *)((int)piVar18 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + cVar9,bVar7)) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  _DAT_03fffffd = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  *(char *)(iParm3 + 7) = *(char *)(iParm3 + 7) >> 8;
  *_DAT_03fffff5 = *_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
  _DAT_03ffffed = 0x4000001;
  _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar8);
  _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
  _DAT_03ffffcd = &DAT_03ffffe1;
  iVar16 = _DAT_03ffffd5 + iParm3;
  pcVar13 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
  _DAT_03ffffc9 = unaff_EBP;
  _DAT_03ffffd1 = unaff_EBX;
  _DAT_03ffffd9 = iParm3;
  _DAT_03ffffe1 = _DAT_03ffffc1;
  _DAT_03ffffe5 = _DAT_03ffffc5;
  _DAT_03ffffe9 = unaff_EBP;
  _DAT_03fffff1 = unaff_EBX;
  _DAT_03fffff9 = iParm3;
  *pcVar13 = *pcVar13 + cVar21;
  pcVar13[iParm3] = pcVar13[iParm3] & (byte)pcVar13;
  bVar8 = (byte)pcVar13 | bVar8;
  piVar18 = (int *)((uint)pcVar13 & 0xffffff00 | (uint)bVar8);
  *piVar18 = *piVar18 + (int)piVar18;
  *(byte *)(piVar18 + iVar16 * 2) = *(char *)(piVar18 + iVar16 * 2) + bVar8;
  uVar10 = (uint)pcVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)pcVar13 & 0xffffff00) >> 8) + *(char *)((int)piVar18 + 2),
                          bVar8);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar19 = (uint)((uVar19 & 1) != 0);
  iVar16 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar10 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  puVar23 = (undefined4 *)(iVar16 + uVar19 + 0x3ffffbd);
  *(undefined4 **)(iVar16 + uVar19 + 0x3ffffbd) = unaff_EBP;
  cVar9 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar23 = puVar23 + -1;
    *puVar23 = *unaff_EBP;
    cVar9 = cVar9 + -1;
  } while (0 < cVar9);
  *(uint *)(iVar16 + uVar19 + 0x3ffff9d) = iVar16 + uVar19 + 0x3ffffbd;
  uVar10 = (uint)CONCAT11(bVar7 / 1,bVar7) & 0xffffff00;
  uVar19 = (uint)puVar11 & 0xffff0000 | uVar10;
  pcVar13 = (char *)(uVar19 | (uint)bVar7 & 0xffffff01);
  cVar9 = (char)((uint)bVar7 & 0xffffff01);
  *pcVar13 = *pcVar13 + cVar9;
  bVar7 = cVar9 - 0x30;
  cVar9 = *(char *)((uVar19 | (uint)bVar7) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 | (uint)CONCAT11((char)(uVar10 >> 8) + cVar9,bVar7)
                     ) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  pcVar6 = (code *)swi(3);
  (*pcVar6)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
  return;
}



// WARNING: Instruction at (ram,0x080423f2) overlaps instruction at (ram,0x080423f1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int sem_wait(sem_t *__sem)

{
  byte *pbVar1;
  int iVar2;
  undefined *puVar3;
  code *pcVar4;
  byte bVar5;
  byte bVar6;
  char cVar7;
  uint *puVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  char *pcVar12;
  uint uVar13;
  int *piVar14;
  int in_ECX;
  byte *in_EDX;
  uint uVar15;
  byte *pbVar16;
  char cVar17;
  uint *unaff_EBX;
  undefined *puVar18;
  undefined4 *puVar19;
  undefined4 *unaff_EBP;
  byte *unaff_ESI;
  undefined4 unaff_EDI;
  
  bVar5 = (char)__sem - 0x30;
  uVar9 = (uint)__sem & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__sem & 0xffffff00) >> 8) +
                         *(char *)(((uint)__sem & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar11 = *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar9 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar5 = (char)puVar8 + 8;
  uVar9 = (uint)puVar8 & 0xffffff00 | (uint)bVar5;
  *(byte *)(in_ECX + uVar9) = *(byte *)(in_ECX + uVar9) | (byte)((uint)in_EDX >> 8);
  pcVar12 = (char *)(uVar9 + (int)in_EDX * 8);
  *pcVar12 = *pcVar12 + bVar5;
  uVar13 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + *(char *)(uVar9 + 2),bVar5);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar2 = *(int *)(uVar13 + 4);
  puVar18 = &stack0x00000002 + iVar2 + (uint)((uVar15 & 1) != 0) + iVar11 + uVar9;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar13 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  _DAT_03ffffc5 = unaff_ESI + 1;
  uVar13 = (uint)puVar8 & 0xffffff00 | (uint)*unaff_ESI;
  if (-1 < (char)((char)puVar8 + '\b')) {
    uVar10 = (uint)puVar8 & 0xffff0000 |
             (uint)CONCAT11((char)((uint)puVar8 >> 8) + *(char *)(uVar13 + 2),*unaff_ESI);
    uVar13 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar18 = &stack0x00000002 + iVar2 + (uint)((uVar15 & 1) != 0) + iVar11 +
              (uint)((uVar13 & 1) != 0) + *(int *)(uVar10 + 4) + uVar9;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar8 = (uint *)(uVar10 + 2);
    *puVar8 = *puVar8 | (uint)puVar8;
    uVar13 = (uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 8);
  }
  *(byte *)(uVar13 + 0x4000001) = *(byte *)(uVar13 + 0x4000001) | (byte)uVar13;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar18 + -4) = uVar13;
  *(int *)(puVar18 + -8) = in_ECX;
  *(byte **)(puVar18 + -0xc) = in_EDX;
  *(uint **)(puVar18 + -0x10) = unaff_EBX;
  *(undefined **)(puVar18 + -0x14) = puVar18;
  *(undefined4 **)(puVar18 + -0x18) = unaff_EBP;
  *(byte **)(puVar18 + -0x1c) = _DAT_03ffffc5;
  *(undefined4 *)(puVar18 + -0x20) = unaff_EDI;
  bVar6 = (byte)in_ECX;
  uVar15 = (uint)in_EDX & 0xffffff00 | (uint)(byte)((char)in_EDX + bVar6);
  iVar11 = uVar13 - *(int *)(uVar13 + 0x13);
  *(int *)(puVar18 + -0x24) = iVar11;
  *(int *)(puVar18 + -0x28) = in_ECX;
  *(uint *)(puVar18 + -0x2c) = uVar15;
  *(uint **)(puVar18 + -0x30) = unaff_EBX;
  *(undefined **)(puVar18 + -0x34) = puVar18 + -0x20;
  *(undefined4 **)(puVar18 + -0x38) = unaff_EBP;
  *(byte **)(puVar18 + -0x3c) = _DAT_03ffffc5;
  *(undefined4 *)(puVar18 + -0x40) = unaff_EDI;
  pbVar16 = (byte *)(uVar15 + in_ECX);
  pcVar12 = (char *)(iVar11 - *(int *)(iVar11 + 9));
  cVar17 = (char)((uint)unaff_EBX >> 8);
  *pcVar12 = *pcVar12 + cVar17;
  pcVar12[in_ECX] = pcVar12[in_ECX] & (byte)pcVar12;
  iVar11 = CONCAT31((int3)((uint)pcVar12 >> 8),0x79);
  pbVar1 = (byte *)(in_ECX + -0x2ffc0000 + iVar11);
  *pbVar1 = *pbVar1 | bVar6;
  uVar9 = (uint)pcVar12 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)pcVar12 >> 8) + *(char *)(iVar11 + 2),0x79);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  puVar3 = puVar18 + *(int *)(uVar9 + 4) + -0x40;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar9 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar9 = (uint)puVar8 & 0xffff0000 | (uint)CONCAT11(0x79,(char)puVar8 + '\b');
  *(byte *)(uVar9 + 0x4000001) = *(byte *)(uVar9 + 0x4000001) | (byte)unaff_EBX;
  *pbVar16 = *pbVar16 << 1 | (char)*pbVar16 < 0;
  *(uint *)(puVar3 + uVar15) = uVar9;
  *(int *)(puVar3 + (uVar15 - 4)) = in_ECX;
  *(byte **)(puVar3 + (uVar15 - 8)) = pbVar16;
  *(uint **)(puVar3 + (uVar15 - 0xc)) = unaff_EBX;
  *(undefined **)(puVar3 + (uVar15 - 0x10)) = puVar3 + uVar15 + 4;
  *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar15)) = unaff_EBP;
  *(byte **)(puVar3 + (uVar15 - 0x18)) = _DAT_03ffffc5;
  *(undefined4 *)(puVar3 + (uVar15 - 0x1c)) = unaff_EDI;
  uVar13 = (uint)pbVar16 & 0xffffff00 | (uint)(byte)((char)pbVar16 + bVar6);
  iVar11 = uVar9 - *(int *)(uVar9 + 0x13);
  *(int *)(puVar3 + (uVar15 - 0x20)) = iVar11;
  *(int *)(puVar3 + (uVar15 - 0x24)) = in_ECX;
  *(uint *)(puVar3 + (uVar15 - 0x28)) = uVar13;
  *(uint **)(puVar3 + (uVar15 - 0x2c)) = unaff_EBX;
  *(undefined **)(puVar3 + (uVar15 - 0x30)) = puVar3 + (uVar15 - 0x1c);
  *(undefined4 **)(puVar3 + (uVar15 - 0x34)) = unaff_EBP;
  *(byte **)(puVar3 + (uVar15 - 0x38)) = _DAT_03ffffc5;
  *(undefined4 *)(puVar3 + (uVar15 - 0x3c)) = unaff_EDI;
  _DAT_03fffff5 = (byte *)(uVar13 + in_ECX);
  pcVar12 = (char *)(iVar11 - *(int *)(iVar11 + 9));
  *pcVar12 = *pcVar12 + cVar17;
  pcVar12[in_ECX] = pcVar12[in_ECX] & (byte)pcVar12;
  _DAT_a4080779 = &DAT_a4080779 + (int)_DAT_a4080779;
  (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] = (&DAT_a4080779)[(int)_DAT_03fffff5 * 8] + 'y';
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(CONCAT22(0xa408,CONCAT11(DAT_a408077b + '\a',0x79)) + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar5 = (char)puVar8 + 8;
  piVar14 = (int *)((uint)puVar8 & 0xffffff00 | (uint)bVar5);
  *piVar14 = *piVar14 + (int)piVar14;
  *(byte *)(piVar14 + (int)_DAT_03fffff5 * 2) = *(char *)(piVar14 + (int)_DAT_03fffff5 * 2) + bVar5;
  cVar7 = *(char *)((int)piVar14 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(((uint)puVar8 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + cVar7,bVar5)) + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  _DAT_03fffffd = (uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 8);
  *(char *)(in_ECX + 7) = *(char *)(in_ECX + 7) >> 8;
  *_DAT_03fffff5 = *_DAT_03fffff5 << 1 | (char)*_DAT_03fffff5 < 0;
  _DAT_03ffffed = 0x4000001;
  _DAT_03ffffd5 = (uint)_DAT_03fffff5 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff5 + bVar6);
  _DAT_03ffffdd = _DAT_03fffffd - *(int *)(_DAT_03fffffd + 0x13);
  _DAT_03ffffcd = &DAT_03ffffe1;
  iVar11 = _DAT_03ffffd5 + in_ECX;
  pcVar12 = (char *)(_DAT_03ffffdd - *(int *)(_DAT_03ffffdd + 9));
  _DAT_03ffffc1 = unaff_EDI;
  _DAT_03ffffc9 = unaff_EBP;
  _DAT_03ffffd1 = unaff_EBX;
  _DAT_03ffffd9 = in_ECX;
  _DAT_03ffffe1 = unaff_EDI;
  _DAT_03ffffe5 = _DAT_03ffffc5;
  _DAT_03ffffe9 = unaff_EBP;
  _DAT_03fffff1 = unaff_EBX;
  _DAT_03fffff9 = in_ECX;
  *pcVar12 = *pcVar12 + cVar17;
  pcVar12[in_ECX] = pcVar12[in_ECX] & (byte)pcVar12;
  bVar6 = (byte)pcVar12 | bVar6;
  piVar14 = (int *)((uint)pcVar12 & 0xffffff00 | (uint)bVar6);
  *piVar14 = *piVar14 + (int)piVar14;
  *(byte *)(piVar14 + iVar11 * 2) = *(char *)(piVar14 + iVar11 * 2) + bVar6;
  uVar9 = (uint)pcVar12 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)pcVar12 & 0xffffff00) >> 8) + *(char *)((int)piVar14 + 2),
                         bVar6);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  iVar11 = *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar9 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar5 = (char)puVar8 + 8;
  puVar19 = (undefined4 *)(iVar11 + uVar15 + 0x3ffffbd);
  *(undefined4 **)(iVar11 + uVar15 + 0x3ffffbd) = unaff_EBP;
  cVar7 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar19 = puVar19 + -1;
    *puVar19 = *unaff_EBP;
    cVar7 = cVar7 + -1;
  } while (0 < cVar7);
  *(uint *)(iVar11 + uVar15 + 0x3ffff9d) = iVar11 + uVar15 + 0x3ffffbd;
  uVar9 = (uint)CONCAT11(bVar5 / 1,bVar5) & 0xffffff00;
  uVar15 = (uint)puVar8 & 0xffff0000 | uVar9;
  pcVar12 = (char *)(uVar15 | (uint)bVar5 & 0xffffff01);
  cVar7 = (char)((uint)bVar5 & 0xffffff01);
  *pcVar12 = *pcVar12 + cVar7;
  bVar5 = cVar7 - 0x30;
  cVar7 = *(char *)((uVar15 | (uint)bVar5) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(((uint)puVar8 & 0xffff0000 | (uint)CONCAT11((char)(uVar9 >> 8) + cVar7,bVar5)) +
                   2);
  *puVar8 = *puVar8 | (uint)puVar8;
  pcVar4 = (code *)swi(3);
  iVar11 = (*pcVar4)((uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 8));
  return iVar11;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

void terminate(void)

{
  char cVar1;
  code *pcVar2;
  byte bVar3;
  uint in_EAX;
  uint *puVar4;
  uint *unaff_EBX;
  
  bVar3 = (char)in_EAX - 0x30;
  cVar1 = *(char *)((in_EAX & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((in_EAX & 0xffff0000 |
                    (uint)CONCAT11((char)((in_EAX & 0xffffff00) >> 8) + cVar1,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  pcVar2 = (code *)swi(3);
  (*pcVar2)((uint)puVar4 & 0xffffff00 | (uint)(byte)((char)puVar4 + 8));
  return;
}



// WARNING: Instruction at (ram,0x080425cf) overlaps instruction at (ram,0x080425ce)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_getschedparam(pthread_t __target_thread,int *__policy,sched_param *__param)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  byte bVar5;
  char cVar6;
  uint uVar7;
  uint *puVar8;
  int *piVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  byte *pbVar13;
  uint uVar14;
  char *pcVar15;
  uint uVar16;
  char *pcVar17;
  byte extraout_CL;
  int iVar18;
  int extraout_EDX;
  byte bVar19;
  uint *unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined auStack62 [4];
  undefined auStack58 [4];
  undefined auStack54 [4];
  undefined auStack50 [4];
  undefined auStack46 [4];
  undefined auStack42 [4];
  undefined auStack38 [4];
  undefined auStack34 [4];
  undefined auStack30 [4];
  undefined auStack26 [4];
  undefined auStack22 [8];
  undefined auStack14 [4];
  undefined auStack10 [4];
  undefined auStack6 [4];
  undefined auStack2 [2];
  
  bVar5 = (char)__target_thread - 0x30;
  uVar7 = __target_thread & 0xffff0000 |
          (uint)CONCAT11((char)((__target_thread & 0xffffff00) >> 8) +
                         *(char *)((__target_thread & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar18 = *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  cVar6 = (char)puVar8 + '\b';
  pcVar17 = (char *)((int)&__param[1].__sched_priority + 3);
  *pcVar17 = *pcVar17 >> 1;
  uVar7 = (uint)CONCAT11((byte)((uint)puVar8 >> 8) | (byte)((uint)__param >> 8),cVar6);
  piVar9 = (int *)((uint)puVar8 & 0xffff0000 | uVar7);
  *piVar9 = *piVar9 + (int)piVar9;
  *(char *)(piVar9 + (int)__policy * 2) = *(char *)(piVar9 + (int)__policy * 2) + cVar6;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar7 >> 8) + *(char *)((int)piVar9 + 2),cVar6);
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar1 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar5 = (char)puVar8 + 8;
  uVar10 = (uint)CONCAT11(bVar5 / 0x79,bVar5) & 0xffffff00;
  bVar19 = (byte)((uint)unaff_EBX >> 8);
  bVar5 = bVar5 & 0x79 | bVar19;
  piVar9 = (int *)((uint)puVar8 & 0xffff0000 | uVar10 | (uint)bVar5);
  *piVar9 = *piVar9 + (int)piVar9;
  *(byte *)(piVar9 + (int)__policy * 2) = *(char *)(piVar9 + (int)__policy * 2) + bVar5;
  uVar11 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar10 >> 8) + *(char *)((int)piVar9 + 2),bVar5);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar11 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar5 = (char)puVar8 + 8;
  uVar11 = (uint)puVar8 & 0xffffff00;
  pcVar17 = (char *)(uVar11 | (uint)bVar5);
  *(byte *)((int)__policy + (int)pcVar17) = *(byte *)((int)__policy + (int)pcVar17) | bVar5;
  *pcVar17 = *pcVar17 + bVar5;
  bVar5 = (char)puVar8 - 0x28;
  uVar12 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)bVar5) + 2),bVar5);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar5 = (char)puVar8 + 8;
  uVar12 = (uint)puVar8 & 0xffffff00;
  pbVar13 = (byte *)(uVar12 | (uint)bVar5);
  *pbVar13 = *pbVar13 | (byte)__policy;
  bVar5 = bVar5 + *pbVar13;
  pcVar17 = (char *)((uVar12 | (uint)bVar5) + (int)__policy * 8);
  *pcVar17 = *pcVar17 + bVar5;
  uVar14 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)((uVar12 | (uint)bVar5) + 2),bVar5);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar12 = (uint)((uVar12 & 1) != 0);
  puVar4 = &stack0x00000002 +
           *(int *)(uVar14 + 4) +
           (uint)((uVar11 & 1) != 0) +
           iVar3 + (uint)((uVar10 & 1) != 0) +
                   iVar2 + (uint)((uVar7 & 1) != 0) + iVar1 + (uint)((uVar16 & 1) != 0) + iVar18;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar14 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar5 = (char)puVar8 + 8;
  uVar16 = (uint)puVar8 & 0xffffff00;
  pcVar17 = (char *)(uVar16 | (uint)bVar5);
  iVar18 = (int)&__param[-1].__sched_priority + 3;
  if (iVar18 == 0 || bVar5 == 0) {
    *(byte *)((int)__policy + (int)pcVar17) =
         *(byte *)((int)__policy + (int)pcVar17) | (byte)unaff_EBX;
    *pcVar17 = *pcVar17 + bVar5;
    bVar5 = (char)puVar8 - 0x28;
    uVar7 = (uint)puVar8 & 0xffff0000 |
            (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)((uVar16 | (uint)bVar5) + 2),bVar5);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar1 = *(int *)(uVar7 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar8 = (uint *)(uVar7 + 2);
    *puVar8 = *puVar8 | (uint)puVar8;
    bVar5 = in(0x79);
    pbVar13 = (byte *)((uint)puVar8 & 0xffffff00 | (uint)bVar5);
    *pbVar13 = *pbVar13 | (byte)((uint)iVar18 >> 8);
    bVar5 = bVar5 + *pbVar13;
    uVar7 = (uint)puVar8 & 0xffffff00 | (uint)bVar5;
    pcVar17 = (char *)(uVar7 + (int)__policy * 8);
    *pcVar17 = *pcVar17 + bVar5;
    uVar10 = (uint)puVar8 & 0xffff0000 |
             (uint)CONCAT11((char)((uint)puVar8 >> 8) + *(char *)(uVar7 + 2),bVar5);
    uVar7 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar18 = *(int *)(uVar10 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar8 = (uint *)(uVar10 + 2);
    *puVar8 = *puVar8 | (uint)puVar8;
    *(undefined4 *)
     (puVar4 + (uint)((uVar7 & 1) != 0) + iVar18 + (uint)((uVar16 & 1) != 0) + iVar1 + uVar12) =
         0x8042591;
    pcVar15 = (char *)func_0x3c0c2d0a((uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 8));
    bVar5 = (char)pcVar15 + *pcVar15;
    uVar16 = (uint)pcVar15 & 0xffffff00 | (uint)bVar5;
    pcVar17 = (char *)(uVar16 + extraout_EDX * 8);
    *pcVar17 = *pcVar17 + bVar5;
    cVar6 = *(char *)(uVar16 + 2);
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar8 = (uint *)(((uint)pcVar15 & 0xffff0000 |
                      (uint)CONCAT11((char)(((uint)pcVar15 & 0xffffff00) >> 8) + cVar6,bVar5)) + 2);
    *puVar8 = *puVar8 | (uint)puVar8;
    bVar5 = in((short)extraout_EDX);
    pcVar17 = (char *)((uint)puVar8 & 0xffffff00 | (uint)bVar5);
    if ((char)((char)puVar8 + '\b') < 0) {
      pcVar17[2] = pcVar17[2] | bVar5;
      *pcVar17 = *pcVar17 + bVar5;
      pcVar17 = (char *)((uint)puVar8 & 0xffffff00 | (uint)(byte)(bVar5 - 0x30));
    }
    cVar6 = pcVar17[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar8 = (uint *)(((uint)pcVar17 & 0xffff0000 |
                      (uint)CONCAT11((char)((uint)pcVar17 >> 8) + cVar6,(char)pcVar17)) + 2);
    *puVar8 = *puVar8 | (uint)puVar8;
    bVar5 = (char)puVar8 + 8;
    uVar16 = (uint)puVar8 & 0xffffff00 | (uint)bVar5;
    LOCK();
    if ((char)bVar5 < 0) {
      *(byte *)(extraout_EDX + uVar16) = *(byte *)(extraout_EDX + uVar16) | extraout_CL;
      pcVar17 = (char *)(uVar16 + extraout_EDX * 8);
      *pcVar17 = *pcVar17 + bVar5;
    }
    cVar6 = *(char *)(uVar16 + 2);
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar8 = (uint *)(((uint)puVar8 & 0xffff0000 |
                      (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + cVar6,bVar5)) + 2);
    *puVar8 = *puVar8 | (uint)puVar8;
  }
  else {
    *(char **)(puVar4 + (uVar12 - 4)) = pcVar17;
    *(int *)(puVar4 + (uVar12 - 8)) = iVar18;
    *(int **)(puVar4 + (uVar12 - 0xc)) = __policy;
    *(uint **)(puVar4 + (uVar12 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar12)) = puVar4 + uVar12;
    *(undefined4 *)(puVar4 + (uVar12 - 0x18)) = unaff_EBP;
    *(undefined4 *)(puVar4 + (uVar12 - 0x1c)) = unaff_ESI;
    *(undefined4 *)(puVar4 + (uVar12 - 0x20)) = unaff_EDI;
    pcVar17 = pcVar17 + -*(int *)(pcVar17 + 0x13);
    *(char **)(puVar4 + (uVar12 - 0x24)) = pcVar17;
    *(int *)(puVar4 + (uVar12 - 0x28)) = iVar18;
    *(uint *)(puVar4 + (uVar12 - 0x2c)) =
         (uint)__policy & 0xffffff00 | (uint)(byte)((byte)__policy + (char)iVar18);
    *(uint **)(puVar4 + (uVar12 - 0x30)) = unaff_EBX;
    *(undefined **)(puVar4 + (uVar12 - 0x34)) = puVar4 + (uVar12 - 0x20);
    *(undefined4 *)(puVar4 + (uVar12 - 0x38)) = unaff_EBP;
    *(undefined4 *)(puVar4 + (uVar12 - 0x3c)) = unaff_ESI;
    *(undefined4 *)(puVar4 + (uVar12 - 0x40)) = unaff_EDI;
    pcVar17 = pcVar17 + -*(int *)(pcVar17 + 9);
    *pcVar17 = *pcVar17 + bVar19;
    pcVar17[iVar18] = pcVar17[iVar18] & (byte)pcVar17;
  }
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Instruction at (ram,0x080425cf) overlaps instruction at (ram,0x080425ce)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_condattr_destroy(pthread_condattr_t *__attr)

{
  char cVar1;
  int iVar2;
  undefined *puVar3;
  byte bVar4;
  uint uVar5;
  uint *puVar6;
  byte *pbVar7;
  uint uVar8;
  uint uVar9;
  char *pcVar10;
  uint uVar11;
  char *pcVar12;
  byte extraout_CL;
  int in_ECX;
  int iVar13;
  uint in_EDX;
  int extraout_EDX;
  uint *unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined auStack64 [4];
  undefined auStack60 [4];
  undefined auStack56 [4];
  undefined auStack52 [4];
  undefined auStack48 [4];
  undefined auStack44 [4];
  undefined auStack40 [4];
  undefined auStack36 [4];
  undefined auStack32 [4];
  undefined auStack28 [4];
  undefined auStack24 [8];
  undefined auStack16 [4];
  undefined auStack12 [4];
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar4 = (char)__attr - 0x30;
  uVar5 = (uint)__attr & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__attr & 0xffffff00) >> 8) +
                         *(char *)(((uint)__attr & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar13 = *(int *)(uVar5 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar5 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  uVar5 = (uint)puVar6 & 0xffffff00;
  pbVar7 = (byte *)(uVar5 | (uint)bVar4);
  *pbVar7 = *pbVar7 | (byte)in_EDX;
  bVar4 = bVar4 + *pbVar7;
  pcVar12 = (char *)((uVar5 | (uint)bVar4) + in_EDX * 8);
  *pcVar12 = *pcVar12 + bVar4;
  uVar8 = (uint)puVar6 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar5 >> 8) + *(char *)((uVar5 | (uint)bVar4) + 2),bVar4);
  uVar5 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar5 = (uint)((uVar5 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar8 + 4) + (uint)((uVar11 & 1) != 0) + iVar13;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar8 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  uVar11 = (uint)puVar6 & 0xffffff00;
  pcVar12 = (char *)(uVar11 | (uint)bVar4);
  iVar13 = in_ECX + -1;
  if (iVar13 == 0 || bVar4 == 0) {
    pcVar12[in_EDX] = pcVar12[in_EDX] | (byte)unaff_EBX;
    *pcVar12 = *pcVar12 + bVar4;
    bVar4 = (char)puVar6 - 0x28;
    uVar8 = (uint)puVar6 & 0xffff0000 |
            (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)bVar4) + 2),bVar4);
    uVar11 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar2 = *(int *)(uVar8 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar6 = (uint *)(uVar8 + 2);
    *puVar6 = *puVar6 | (uint)puVar6;
    bVar4 = in(0x79);
    pbVar7 = (byte *)((uint)puVar6 & 0xffffff00 | (uint)bVar4);
    *pbVar7 = *pbVar7 | (byte)((uint)iVar13 >> 8);
    bVar4 = bVar4 + *pbVar7;
    uVar8 = (uint)puVar6 & 0xffffff00 | (uint)bVar4;
    pcVar12 = (char *)(uVar8 + in_EDX * 8);
    *pcVar12 = *pcVar12 + bVar4;
    uVar9 = (uint)puVar6 & 0xffff0000 |
            (uint)CONCAT11((char)((uint)puVar6 >> 8) + *(char *)(uVar8 + 2),bVar4);
    uVar8 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar13 = *(int *)(uVar9 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar6 = (uint *)(uVar9 + 2);
    *puVar6 = *puVar6 | (uint)puVar6;
    *(undefined4 *)
     (puVar3 + (uint)((uVar8 & 1) != 0) + iVar13 + (uint)((uVar11 & 1) != 0) + iVar2 + uVar5) =
         0x8042591;
    pcVar10 = (char *)func_0x3c0c2d0a((uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 + 8));
    bVar4 = (char)pcVar10 + *pcVar10;
    uVar11 = (uint)pcVar10 & 0xffffff00 | (uint)bVar4;
    pcVar12 = (char *)(uVar11 + extraout_EDX * 8);
    *pcVar12 = *pcVar12 + bVar4;
    cVar1 = *(char *)(uVar11 + 2);
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar6 = (uint *)(((uint)pcVar10 & 0xffff0000 |
                      (uint)CONCAT11((char)(((uint)pcVar10 & 0xffffff00) >> 8) + cVar1,bVar4)) + 2);
    *puVar6 = *puVar6 | (uint)puVar6;
    bVar4 = in((short)extraout_EDX);
    pcVar12 = (char *)((uint)puVar6 & 0xffffff00 | (uint)bVar4);
    if ((char)((char)puVar6 + '\b') < 0) {
      pcVar12[2] = pcVar12[2] | bVar4;
      *pcVar12 = *pcVar12 + bVar4;
      pcVar12 = (char *)((uint)puVar6 & 0xffffff00 | (uint)(byte)(bVar4 - 0x30));
    }
    cVar1 = pcVar12[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar6 = (uint *)(((uint)pcVar12 & 0xffff0000 |
                      (uint)CONCAT11((char)((uint)pcVar12 >> 8) + cVar1,(char)pcVar12)) + 2);
    *puVar6 = *puVar6 | (uint)puVar6;
    bVar4 = (char)puVar6 + 8;
    uVar11 = (uint)puVar6 & 0xffffff00 | (uint)bVar4;
    LOCK();
    if ((char)bVar4 < 0) {
      *(byte *)(extraout_EDX + uVar11) = *(byte *)(extraout_EDX + uVar11) | extraout_CL;
      pcVar12 = (char *)(uVar11 + extraout_EDX * 8);
      *pcVar12 = *pcVar12 + bVar4;
    }
    cVar1 = *(char *)(uVar11 + 2);
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar6 = (uint *)(((uint)puVar6 & 0xffff0000 |
                      (uint)CONCAT11((char)(((uint)puVar6 & 0xffffff00) >> 8) + cVar1,bVar4)) + 2);
    *puVar6 = *puVar6 | (uint)puVar6;
  }
  else {
    *(char **)(puVar3 + (uVar5 - 4)) = pcVar12;
    *(int *)(puVar3 + (uVar5 - 8)) = iVar13;
    *(uint *)(puVar3 + (uVar5 - 0xc)) = in_EDX;
    *(uint **)(puVar3 + (uVar5 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar3 + (int)(&DAT_ffffffec + uVar5)) = puVar3 + uVar5;
    *(undefined4 *)(puVar3 + (uVar5 - 0x18)) = unaff_EBP;
    *(undefined4 *)(puVar3 + (uVar5 - 0x1c)) = unaff_ESI;
    *(undefined4 *)(puVar3 + (uVar5 - 0x20)) = unaff_EDI;
    pcVar12 = pcVar12 + -*(int *)(pcVar12 + 0x13);
    *(char **)(puVar3 + (uVar5 - 0x24)) = pcVar12;
    *(int *)(puVar3 + (uVar5 - 0x28)) = iVar13;
    *(uint *)(puVar3 + (uVar5 - 0x2c)) =
         in_EDX & 0xffffff00 | (uint)(byte)((byte)in_EDX + (char)iVar13);
    *(uint **)(puVar3 + (uVar5 - 0x30)) = unaff_EBX;
    *(undefined **)(puVar3 + (uVar5 - 0x34)) = puVar3 + (uVar5 - 0x20);
    *(undefined4 *)(puVar3 + (uVar5 - 0x38)) = unaff_EBP;
    *(undefined4 *)(puVar3 + (uVar5 - 0x3c)) = unaff_ESI;
    *(undefined4 *)(puVar3 + (uVar5 - 0x40)) = unaff_EDI;
    pcVar12 = pcVar12 + -*(int *)(pcVar12 + 9);
    *pcVar12 = *pcVar12 + (char)((uint)unaff_EBX >> 8);
    pcVar12[iVar13] = pcVar12[iVar13] & (byte)pcVar12;
  }
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unable to track spacebase fully for stack

void MsgError(uint uParm1,int iParm2,undefined4 uParm3)

{
  char cVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  byte bVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  char *pcVar9;
  uint uVar10;
  char *pcVar11;
  byte extraout_CL;
  int extraout_EDX;
  uint *unaff_EBX;
  undefined auStack2 [2];
  
  bVar5 = (char)uParm1 - 0x30;
  uVar6 = uParm1 & 0xffff0000 |
          (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                         *(char *)((uParm1 & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar5 = in(0x79);
  pbVar4 = (byte *)((uint)puVar7 & 0xffffff00 | (uint)bVar5);
  *pbVar4 = *pbVar4 | (byte)((uint)uParm3 >> 8);
  bVar5 = bVar5 + *pbVar4;
  uVar6 = (uint)puVar7 & 0xffffff00 | (uint)bVar5;
  pcVar11 = (char *)(uVar6 + iParm2 * 8);
  *pcVar11 = *pcVar11 + bVar5;
  uVar8 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)puVar7 >> 8) + *(char *)(uVar6 + 2),bVar5);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar8 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar8 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(undefined4 *)(auStack2 + (uint)((uVar6 & 1) != 0) + iVar3 + (uint)((uVar10 & 1) != 0) + iVar2) =
       0x8042591;
  pcVar9 = (char *)func_0x3c0c2d0a((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 8));
  bVar5 = (char)pcVar9 + *pcVar9;
  uVar10 = (uint)pcVar9 & 0xffffff00 | (uint)bVar5;
  pcVar11 = (char *)(uVar10 + extraout_EDX * 8);
  *pcVar11 = *pcVar11 + bVar5;
  cVar1 = *(char *)(uVar10 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(((uint)pcVar9 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)pcVar9 & 0xffffff00) >> 8) + cVar1,bVar5)) + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar5 = in((short)extraout_EDX);
  pcVar11 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar5);
  if ((char)((char)puVar7 + '\b') < 0) {
    pcVar11[2] = pcVar11[2] | bVar5;
    *pcVar11 = *pcVar11 + bVar5;
    pcVar11 = (char *)((uint)puVar7 & 0xffffff00 | (uint)(byte)(bVar5 - 0x30));
  }
  cVar1 = pcVar11[2];
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(((uint)pcVar11 & 0xffff0000 |
                    (uint)CONCAT11((char)((uint)pcVar11 >> 8) + cVar1,(char)pcVar11)) + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar5 = (char)puVar7 + 8;
  uVar10 = (uint)puVar7 & 0xffffff00 | (uint)bVar5;
  LOCK();
  if ((char)bVar5 < 0) {
    *(byte *)(extraout_EDX + uVar10) = *(byte *)(extraout_EDX + uVar10) | extraout_CL;
    pcVar11 = (char *)(uVar10 + extraout_EDX * 8);
    *pcVar11 = *pcVar11 + bVar5;
  }
  cVar1 = *(char *)(uVar10 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(((uint)puVar7 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + cVar1,bVar5)) + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void ConnectDetach(uint uParm1,int iParm2,byte bParm3)

{
  char *pcVar1;
  char cVar2;
  byte bVar3;
  uint *puVar4;
  uint uVar5;
  uint *unaff_EBX;
  
  bVar3 = (char)uParm1 - 0x30;
  cVar2 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar2,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  bVar3 = (char)puVar4 + 8;
  uVar5 = (uint)puVar4 & 0xffffff00 | (uint)bVar3;
  LOCK();
  if ((char)bVar3 < 0) {
    *(byte *)(iParm2 + uVar5) = *(byte *)(iParm2 + uVar5) | bParm3;
    pcVar1 = (char *)(uVar5 + iParm2 * 8);
    *pcVar1 = *pcVar1 + bVar3;
  }
  cVar2 = *(char *)(uVar5 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)puVar4 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)puVar4 & 0xffffff00) >> 8) + cVar2,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SyncMutexUnlock_r(uint uParm1,byte *pbParm2,int iParm3)

{
  byte *pbVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  uint uVar14;
  undefined *puVar15;
  undefined *puVar16;
  code *pcVar17;
  byte bVar18;
  char cVar19;
  byte bVar20;
  byte bVar21;
  ushort uVar22;
  uint *puVar23;
  int iVar24;
  uint uVar25;
  uint uVar26;
  uint uVar27;
  uint uVar28;
  uint uVar29;
  uint uVar30;
  uint uVar31;
  uint uVar32;
  uint uVar33;
  uint uVar34;
  uint uVar35;
  uint uVar36;
  uint uVar37;
  uint uVar38;
  int *piVar39;
  uint uVar40;
  byte *pbVar41;
  int iVar42;
  int iVar43;
  char *pcVar44;
  char *pcVar45;
  byte bVar46;
  byte bVar47;
  byte bVar49;
  uint uVar48;
  byte bVar50;
  byte bVar51;
  uint *unaff_EBX;
  int iVar52;
  undefined *puVar53;
  undefined *puVar54;
  undefined *puVar55;
  undefined *puVar56;
  undefined *puVar57;
  undefined4 *puVar58;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar59;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack186 [12];
  undefined auStack174 [4];
  undefined auStack170 [4];
  undefined auStack166 [4];
  undefined auStack162 [4];
  undefined auStack158 [4];
  undefined auStack154 [4];
  undefined auStack150 [4];
  undefined auStack146 [4];
  undefined auStack142 [4];
  undefined auStack138 [4];
  undefined auStack134 [4];
  undefined auStack130 [4];
  undefined auStack126 [10];
  undefined auStack116 [4];
  undefined auStack112 [4];
  undefined auStack108 [4];
  undefined auStack104 [4];
  undefined auStack100 [4];
  undefined auStack96 [4];
  undefined auStack92 [4];
  undefined auStack88 [4];
  undefined auStack84 [4];
  undefined auStack80 [4];
  undefined auStack76 [4];
  undefined auStack72 [4];
  undefined auStack68 [4];
  undefined auStack64 [10];
  undefined auStack54 [4];
  undefined auStack50 [4];
  undefined auStack46 [4];
  undefined auStack42 [4];
  undefined auStack38 [4];
  undefined auStack34 [4];
  undefined auStack30 [4];
  undefined auStack26 [4];
  undefined auStack22 [4];
  undefined auStack18 [4];
  undefined auStack14 [8];
  undefined auStack6 [4];
  undefined auStack2 [2];
  
  bVar18 = (char)uParm1 - 0x30;
  uVar37 = uParm1 & 0xffff0000 |
           (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                          *(char *)((uParm1 & 0xffffff00 | (uint)bVar18) + 2),bVar18);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar24 = *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar37 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  bVar21 = (byte)(((uint)puVar23 & 0xffffff00) >> 8);
  if ((char)bVar18 < 0) {
    pbParm2[uVar37] = pbParm2[uVar37] | bVar21;
    pcVar44 = (char *)(uVar37 + (int)pbParm2 * 8);
    *pcVar44 = *pcVar44 + bVar18;
  }
  uVar48 = (uint)puVar23 & 0xffff0000 | (uint)CONCAT11(bVar21 + *(char *)(uVar37 + 2),bVar18);
  uVar37 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar42 = *(int *)(uVar48 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar48 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
  if ((char)bVar18 < 0) {
    pcVar44[2] = pcVar44[2] | (byte)((uint)pbParm2 >> 8);
    *pcVar44 = *pcVar44 + bVar18;
    pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 - 0x28));
  }
  uVar40 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
  uVar48 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar43 = *(int *)(uVar40 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar40 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar40 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  bVar51 = (byte)((uint)unaff_EBX >> 8);
  pbParm2[7] = pbParm2[7] + bVar51;
  pbParm2[uVar40] = pbParm2[uVar40] | bVar51;
  pcVar44 = (char *)(uVar40 + (int)pbParm2 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar25 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar40 + 2),bVar18);
  uVar40 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar40 = (uint)((uVar40 & 1) != 0);
  puVar15 = &stack0x00000000 +
            *(int *)(uVar25 + 4) +
            (uint)((uVar48 & 1) != 0) +
            iVar43 + (uint)((uVar37 & 1) != 0) + iVar42 + (uint)((uVar38 & 1) != 0) + iVar24;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar25 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar38 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 0x82);
  bVar21 = (byte)iParm3;
  *(byte *)(uVar38 + 0x4000002) = *(byte *)(uVar38 + 0x4000002) | bVar21;
  *pbParm2 = *pbParm2 << 1 | (char)*pbParm2 < 0;
  *(uint *)(puVar15 + (uVar40 - 2)) = uVar38;
  *(int *)(puVar15 + (uVar40 - 6)) = iParm3;
  *(byte **)(puVar15 + (int)(&DAT_fffffff6 + uVar40)) = pbParm2;
  *(uint **)(puVar15 + (uVar40 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar40 - 0x12)) = puVar15 + uVar40 + 2;
  *(undefined4 **)(puVar15 + (uVar40 - 0x16)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar40 - 0x1a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar40 - 0x1e)) = unaff_EDI;
  uVar37 = (uint)pbParm2 & 0xffffff00 | (uint)(byte)((char)pbParm2 + bVar21);
  iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
  *(int *)(puVar15 + (uVar40 - 0x22)) = iVar24;
  *(int *)(puVar15 + (uVar40 - 0x26)) = iParm3;
  *(uint *)(puVar15 + (uVar40 - 0x2a)) = uVar37;
  *(uint **)(puVar15 + (uVar40 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar40 - 0x32)) = puVar15 + (uVar40 - 0x1e);
  *(undefined4 **)(puVar15 + (uVar40 - 0x36)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar40 - 0x3a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar40 - 0x3e)) = unaff_EDI;
  pbVar41 = (byte *)(uVar37 + iParm3);
  pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
  *pcVar44 = *pcVar44 + bVar51;
  pcVar44[iParm3] = pcVar44[iParm3] & (byte)pcVar44;
  pbVar41[7] = pbVar41[7] | bVar51;
  (pbVar41 + -0x2ffc0000)[(int)pcVar44] = (pbVar41 + -0x2ffc0000)[(int)pcVar44] | (byte)pbVar41;
  uVar48 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(byte)pcVar44);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar37 = (uint)((uVar38 & 1) != 0);
  puVar15 = puVar15 + *(int *)(uVar48 + 4) + (uVar40 - 0x3e);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar48 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar38 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8) | 0x7a;
  *(byte *)(uVar38 + 0x4000002) =
       *(byte *)(uVar38 + 0x4000002) | (byte)(((uint)puVar23 & 0xffffff00) >> 8);
  *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
  *(uint *)(puVar15 + (uVar37 - 2)) = uVar38;
  *(int *)(puVar15 + (uVar37 - 6)) = iParm3;
  *(byte **)(puVar15 + (uVar37 - 10)) = pbVar41;
  *(uint **)(puVar15 + (uVar37 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar37 - 0x12)) = puVar15 + uVar37 + 2;
  *(undefined4 **)(puVar15 + (uVar37 - 0x16)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar37 - 0x1a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar37 - 0x1e)) = unaff_EDI;
  uVar48 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((byte)pbVar41 + bVar21);
  iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
  *(int *)(puVar15 + (uVar37 - 0x22)) = iVar24;
  *(int *)(puVar15 + (uVar37 - 0x26)) = iParm3;
  *(uint *)(puVar15 + (uVar37 - 0x2a)) = uVar48;
  *(uint **)(puVar15 + (uVar37 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar37 - 0x32)) = puVar15 + (uVar37 - 0x1e);
  *(undefined4 **)(puVar15 + (uVar37 - 0x36)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar37 - 0x3a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar37 - 0x3e)) = unaff_EDI;
  pbVar41 = (byte *)(uVar48 + iParm3);
  pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
  *pcVar44 = *pcVar44 + bVar51;
  pcVar44[iParm3] = pcVar44[iParm3] & (byte)pcVar44;
  pbVar41[7] = pbVar41[7] + bVar51;
  bVar46 = (byte)((uint)iParm3 >> 8);
  (pbVar41 + -0x2ffc0000)[(int)pcVar44] = (pbVar41 + -0x2ffc0000)[(int)pcVar44] | bVar46;
  uVar48 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(byte)pcVar44);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar38 & 1) != 0);
  puVar15 = puVar15 + *(int *)(uVar48 + 4) + (uVar37 - 0x3e);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar48 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar38 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((byte)puVar23 + 0x82 + (0xf7 < (byte)puVar23));
  *(byte *)(uVar38 + 0x4000002) = *(byte *)(uVar38 + 0x4000002) | bVar51;
  *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
  *(uint *)(puVar15 + (uVar14 - 2)) = uVar38;
  *(int *)(puVar15 + (uVar14 - 6)) = iParm3;
  *(byte **)(puVar15 + (uVar14 - 10)) = pbVar41;
  *(uint **)(puVar15 + (uVar14 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar14 - 0x12)) = puVar15 + uVar14 + 2;
  *(undefined4 **)(puVar15 + (uVar14 - 0x16)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar14 - 0x1a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar14 - 0x1e)) = unaff_EDI;
  uVar37 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((char)pbVar41 + bVar21);
  iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
  *(int *)(puVar15 + (uVar14 - 0x22)) = iVar24;
  *(int *)(puVar15 + (uVar14 - 0x26)) = iParm3;
  *(uint *)(puVar15 + (uVar14 - 0x2a)) = uVar37;
  *(uint **)(puVar15 + (uVar14 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar14 - 0x32)) = puVar15 + (uVar14 - 0x1e);
  *(undefined4 **)(puVar15 + (uVar14 - 0x36)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar14 - 0x3a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar14 - 0x3e)) = unaff_EDI;
  pbVar41 = (byte *)(uVar37 + iParm3);
  pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
  *pcVar44 = *pcVar44 + bVar51;
  bVar18 = (byte)pcVar44;
  pcVar44[iParm3] = pcVar44[iParm3] & bVar18;
  pbVar41[7] = pbVar41[7] - bVar51;
  uVar37 = (uint)pcVar44 & 0xffff0000;
  uVar38 = (uint)CONCAT11((byte)((uint)pcVar44 >> 8) | bVar18,bVar18);
  bVar18 = bVar18 + *(char *)(uVar37 | uVar38);
  uVar38 = uVar38 & 0xffffff00;
  uVar48 = uVar37 | uVar38 | (uint)bVar18;
  pcVar44 = (char *)(uVar48 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar37 = uVar37 | (uint)CONCAT11((char)(uVar38 >> 8) + *(char *)(uVar48 + 2),bVar18);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar24 = *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar37 = (uint)puVar23 & 0xffffff00;
  bVar47 = (byte)pbVar41;
  bVar18 = ((byte)puVar23 + 0x8e) - (0xf7 < (byte)puVar23) | bVar47;
  bVar18 = bVar18 + *(char *)(uVar37 | (uint)bVar18);
  pcVar44 = (char *)((uVar37 | (uint)bVar18) + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar48 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar37 >> 8) + *(char *)((uVar37 | (uint)bVar18) + 2),bVar18);
  uVar37 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar42 = *(int *)(uVar48 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar48 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  cVar19 = (char)puVar23 + '\b';
  pbVar41[7] = pbVar41[7] & bVar51;
  bVar50 = (byte)unaff_EBX;
  uVar40 = (uint)puVar23 & 0xffff0000;
  uVar48 = (uint)CONCAT11((byte)((uint)puVar23 >> 8) | bVar50,cVar19);
  bVar18 = cVar19 + *(char *)(uVar40 | uVar48);
  uVar48 = uVar48 & 0xffffff00;
  uVar25 = uVar40 | uVar48 | (uint)bVar18;
  pcVar44 = (char *)(uVar25 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar40 = uVar40 | (uint)CONCAT11((char)(uVar48 >> 8) + *(char *)(uVar25 + 2),bVar18);
  uVar48 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar43 = *(int *)(uVar40 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar40 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar40 = (uint)puVar23 & 0xffffff00;
  bVar18 = (char)puVar23 + 8U & 0x7a | bVar46;
  bVar18 = bVar18 + *(char *)(uVar40 | (uint)bVar18);
  pcVar44 = (char *)((uVar40 | (uint)bVar18) + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar25 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar40 >> 8) + *(char *)((uVar40 | (uint)bVar18) + 2),bVar18);
  uVar40 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar25 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar25 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  cVar19 = (char)puVar23 + '\b';
  pbVar41[7] = pbVar41[7] - bVar51;
  bVar49 = (byte)((uint)pbVar41 >> 8);
  uVar27 = (uint)puVar23 & 0xffff0000;
  uVar25 = (uint)CONCAT11((byte)((uint)puVar23 >> 8) | bVar49,cVar19);
  bVar18 = cVar19 + *(char *)(uVar27 | uVar25);
  uVar25 = uVar25 & 0xffffff00;
  uVar26 = uVar27 | uVar25 | (uint)bVar18;
  pcVar44 = (char *)(uVar26 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar27 = uVar27 | (uint)CONCAT11((char)(uVar25 >> 8) + *(char *)(uVar26 + 2),bVar18);
  uVar25 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar4 = *(int *)(uVar27 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar27 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 0x8e;
  piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
  *(byte *)piVar39 = *(byte *)piVar39 | bVar18;
  uVar27 = (int)piVar39 + *piVar39;
  pcVar44 = (char *)(uVar27 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + (char)uVar27;
  uVar26 = uVar27 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar27 >> 8) + *(char *)(uVar27 + 2),(char)uVar27);
  uVar27 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar5 = *(int *)(uVar26 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar26 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar26 = (uint)puVar23 & 0xffffff00;
  pcVar44 = (char *)(uVar26 | (uint)bVar18);
  pbVar41[7] = pbVar41[7] ^ bVar51;
  *(byte *)((int)unaff_EBX + (int)pcVar44) = *(byte *)((int)unaff_EBX + (int)pcVar44) | bVar21;
  *pcVar44 = *pcVar44 + bVar18;
  bVar18 = (char)puVar23 - 0x28;
  uVar28 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar26 >> 8) + *(char *)((uVar26 | (uint)bVar18) + 2),bVar18);
  uVar26 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar6 = *(int *)(uVar28 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar28 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  piVar39 = (int *)(((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8)) ^ 0x7a);
  *(byte *)piVar39 = *(byte *)piVar39 | bVar50;
  uVar28 = (int)piVar39 + *piVar39;
  pcVar44 = (char *)(uVar28 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + (char)uVar28;
  uVar29 = uVar28 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar28 >> 8) + *(char *)(uVar28 + 2),(char)uVar28);
  uVar28 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar7 = *(int *)(uVar29 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar29 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar29 = (uint)puVar23 & 0xffffff00;
  pcVar44 = (char *)(uVar29 | (uint)bVar18);
  bVar20 = (byte)(uVar29 >> 8);
  *(byte *)((int)unaff_EBX + (int)pcVar44) = *(byte *)((int)unaff_EBX + (int)pcVar44) | bVar20;
  *pcVar44 = *pcVar44 + bVar18;
  bVar18 = (char)puVar23 - 0x28;
  uVar30 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11(bVar20 + *(char *)((uVar29 | (uint)bVar18) + 2),bVar18);
  uVar29 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar8 = *(int *)(uVar30 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar30 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
  *(byte *)piVar39 = *(byte *)piVar39 | bVar49;
  uVar30 = (int)piVar39 + *piVar39;
  pcVar44 = (char *)(uVar30 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + (char)uVar30;
  uVar31 = uVar30 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar30 >> 8) + *(char *)(uVar30 + 2),(char)uVar30);
  uVar30 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar9 = *(int *)(uVar31 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar31 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  pcVar44 = (char *)(((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8)) + 1);
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + (int)pcVar44) = *(byte *)((int)unaff_EBX + (int)pcVar44) | bVar51;
    *pcVar44 = *pcVar44 + (char)pcVar44;
    pcVar44 = (char *)((uint)pcVar44 & 0xffffff00 | (uint)(byte)((char)pcVar44 - 0x30));
  }
  uVar32 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
  uVar31 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar10 = *(int *)(uVar32 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar32 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
  if (!in_PF) {
    pcVar44[3] = pcVar44[3] | bVar21;
    *pcVar44 = *pcVar44 + bVar18;
    pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 - 0x28));
  }
  uVar33 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
  uVar32 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar11 = *(int *)(uVar33 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar33 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar33 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
  uVar34 = uVar33 - 1;
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar34) = *(byte *)((int)unaff_EBX + uVar34) | bVar47;
    pcVar44 = (char *)(uVar34 + (int)pbVar41 * 8);
    *pcVar44 = *pcVar44 + (char)uVar34;
  }
  uVar34 = uVar34 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar34 >> 8) + *(char *)(uVar33 + 1),(char)uVar34);
  uVar33 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar12 = *(int *)(uVar34 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar34 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar34 = (uint)puVar23 & 0xffffff00;
  pcVar44 = (char *)(uVar34 | (uint)bVar18);
  if (!in_PF) {
    pcVar44[3] = pcVar44[3] | (byte)(uVar34 >> 8);
    *pcVar44 = *pcVar44 + bVar18;
    pcVar44 = (char *)(uVar34 | (uint)(byte)((char)puVar23 - 0x28));
  }
  uVar35 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
  uVar34 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar34 = (uint)((uVar34 & 1) != 0);
  iVar13 = *(int *)(uVar35 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar35 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar35 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  *(uint *)(puVar15 + iVar13 + (uint)((uVar33 & 1) != 0) +
                               iVar12 + (uint)((uVar32 & 1) != 0) +
                                        iVar11 + (uint)((uVar31 & 1) != 0) +
                                                 iVar10 + (uint)((uVar30 & 1) != 0) +
                                                          iVar9 + (uint)((uVar29 & 1) != 0) +
                                                                  iVar8 + (uint)((uVar28 & 1) != 0)
                                                                          + iVar7 + (uint)((uVar26 &
                                                                                           1) != 0)
                                                                                    + iVar6 + (uint)
                                                  ((uVar27 & 1) != 0) +
                                                  iVar5 + (uint)((uVar25 & 1) != 0) +
                                                          iVar4 + (uint)((uVar40 & 1) != 0) +
                                                                  iVar3 + (uint)((uVar48 & 1) != 0)
                                                                          + iVar43 + (uint)((uVar37 
                                                  & 1) != 0) +
                                                  iVar42 + (uint)((uVar38 & 1) != 0) +
                                                           iVar24 + (uVar14 - 0x3e) + uVar34 + 6) =
       uVar35;
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar35) = *(byte *)((int)unaff_EBX + uVar35) | bVar46;
    pcVar44 = (char *)(uVar35 + (int)pbVar41 * 8);
    *pcVar44 = *pcVar44 + bVar18;
  }
  uVar36 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar35 + 2),bVar18);
  uVar35 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar35 = (uint)((uVar35 & 1) != 0);
  puVar15 = puVar15 + iVar13 + (uint)((uVar33 & 1) != 0) +
                               iVar12 + (uint)((uVar32 & 1) != 0) +
                                        iVar11 + (uint)((uVar31 & 1) != 0) +
                                                 iVar10 + (uint)((uVar30 & 1) != 0) +
                                                          iVar9 + (uint)((uVar29 & 1) != 0) +
                                                                  iVar8 + (uint)((uVar28 & 1) != 0)
                                                                          + iVar7 + (uint)((uVar26 &
                                                                                           1) != 0)
                                                                                    + iVar6 + (uint)
                                                  ((uVar27 & 1) != 0) +
                                                  iVar5 + (uint)((uVar25 & 1) != 0) +
                                                          iVar4 + (uint)((uVar40 & 1) != 0) +
                                                                  iVar3 + (uint)((uVar48 & 1) != 0)
                                                                          + iVar43 + (uint)((uVar37 
                                                  & 1) != 0) +
                                                  iVar42 + (uint)((uVar38 & 1) != 0) +
                                                           iVar24 + (uVar14 - 0x3e) +
            *(int *)(uVar36 + 4) + uVar34 + 6;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar36 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
  *(undefined **)(puVar15 + uVar35 + -4) = puVar15 + uVar35;
  if (!in_PF) {
    pcVar44[3] = pcVar44[3] | bVar51;
    *pcVar44 = *pcVar44 + bVar18;
    pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 - 0x28));
  }
  uVar37 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar38 = (uint)((uVar38 & 1) != 0);
  iVar24 = *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar37 = *(uint *)((int)(puVar15 + iVar24 + uVar35 + -4) + uVar38);
  if (!in_PF) {
    pbVar1 = (byte *)((int)unaff_EBX + uVar37 + 0xd0040000);
    *pbVar1 = *pbVar1 | (byte)uVar37;
  }
  uVar48 = uVar37 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar37 >> 8) + *(char *)(uVar37 + 2),(byte)uVar37);
  uVar37 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar42 = *(int *)(uVar48 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar48 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar48 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  iVar52 = *(int *)((int)(puVar15 + iVar24 + uVar35 + -4) + uVar38 + 4 + iVar42 +
                   (uint)((uVar37 & 1) != 0));
  puVar53 = (undefined *)(iVar52 + 4);
  if (in_PF) {
    uVar37 = (uint)puVar23 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar48 + 2),bVar18
                           );
    uVar38 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar53 = (undefined *)(iVar52 + 4 + *(int *)(uVar37 + 4) + (uint)((uVar38 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar37 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    uVar48 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
  }
  *(byte *)(uVar48 + 0x4000003) = *(byte *)(uVar48 + 0x4000003) | bVar47;
  *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
  *(uint *)(puVar53 + -4) = uVar48;
  *(int *)(puVar53 + -8) = iParm3;
  *(byte **)(puVar53 + -0xc) = pbVar41;
  *(uint **)(puVar53 + -0x10) = unaff_EBX;
  *(undefined **)(puVar53 + -0x14) = puVar53;
  *(undefined4 **)(puVar53 + -0x18) = unaff_EBP;
  *(undefined **)(puVar53 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar53 + -0x20) = unaff_EDI;
  uVar38 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)(bVar47 + bVar21);
  iVar24 = uVar48 - *(int *)(uVar48 + 0x13);
  *(int *)(puVar53 + -0x24) = iVar24;
  *(int *)(puVar53 + -0x28) = iParm3;
  *(uint *)(puVar53 + -0x2c) = uVar38;
  *(uint **)(puVar53 + -0x30) = unaff_EBX;
  *(undefined **)(puVar53 + -0x34) = puVar53 + -0x20;
  *(undefined4 **)(puVar53 + -0x38) = unaff_EBP;
  *(undefined **)(puVar53 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar53 + -0x40) = unaff_EDI;
  pbVar41 = (byte *)(uVar38 + iParm3);
  pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
  *pcVar44 = *pcVar44 + bVar51;
  pcVar44[iParm3] = pcVar44[iParm3] & (byte)pcVar44;
  *(char **)(puVar53 + -0x44) = pcVar44;
  *(int *)(puVar53 + -0x48) = iParm3;
  *(byte **)(puVar53 + -0x4c) = pbVar41;
  *(uint **)(puVar53 + -0x50) = unaff_EBX;
  *(undefined **)(puVar53 + -0x54) = puVar53 + -0x40;
  *(undefined4 **)(puVar53 + -0x58) = unaff_EBP;
  *(undefined **)(puVar53 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar53 + -0x60) = unaff_EDI;
  if (!in_PF) {
    pbVar1 = (byte *)((int)((int)unaff_EBX + -0x2ffc0000) + (int)pcVar44);
    *pbVar1 = *pbVar1 | bVar50;
  }
  uVar37 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(byte)pcVar44);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar38 = (uint)((uVar38 & 1) != 0);
  iVar24 = *(int *)(uVar37 + 4);
  puVar54 = puVar53 + iVar24 + -0x60 + uVar38;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar37 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  if (in_PF) {
    uVar48 = (uint)puVar23 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar37 + 2),bVar18
                           );
    uVar37 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar54 = puVar53 + iVar24 + -0x60 + (uint)((uVar37 & 1) != 0) + *(int *)(uVar48 + 4) + uVar38;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar48 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    uVar37 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
  }
  *(byte *)(uVar37 + 0x4000003) = *(byte *)(uVar37 + 0x4000003) | bVar46;
  *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
  *(uint *)(puVar54 + -4) = uVar37;
  *(int *)(puVar54 + -8) = iParm3;
  *(byte **)(puVar54 + -0xc) = pbVar41;
  *(uint **)(puVar54 + -0x10) = unaff_EBX;
  *(undefined **)(puVar54 + -0x14) = puVar54;
  *(undefined4 **)(puVar54 + -0x18) = unaff_EBP;
  *(undefined **)(puVar54 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar54 + -0x20) = unaff_EDI;
  uVar48 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((char)pbVar41 + bVar21);
  iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
  *(int *)(puVar54 + -0x24) = iVar24;
  *(int *)(puVar54 + -0x28) = iParm3;
  *(uint *)(puVar54 + -0x2c) = uVar48;
  *(uint **)(puVar54 + -0x30) = unaff_EBX;
  *(undefined **)(puVar54 + -0x34) = puVar54 + -0x20;
  *(undefined4 **)(puVar54 + -0x38) = unaff_EBP;
  *(undefined **)(puVar54 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar54 + -0x40) = unaff_EDI;
  uVar48 = uVar48 + iParm3;
  piVar39 = (int *)(iVar24 - *(int *)(iVar24 + 9));
  *(byte *)piVar39 = *(char *)piVar39 + bVar51;
  *(byte *)((int)piVar39 + iParm3) = *(byte *)((int)piVar39 + iParm3) & (byte)piVar39;
  *(undefined4 *)(puVar54 + -0x44) = 0xb408077a;
  uVar38 = (int)piVar39 + *piVar39;
  pcVar44 = (char *)(uVar38 + uVar48 * 8);
  *pcVar44 = *pcVar44 + (char)uVar38;
  uVar37 = uVar38 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar38 >> 8) + *(char *)(uVar38 + 2),(char)uVar38);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar24 = *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
  puVar15 = unaff_EDI + 1;
  uVar2 = in((short)uVar48);
  *unaff_EDI = uVar2;
  if (!in_PF) {
    piVar39 = (int *)((int)piVar39 + *piVar39);
    *(char *)(piVar39 + uVar48 * 2) = *(char *)(piVar39 + uVar48 * 2) + (char)piVar39;
  }
  uVar40 = (uint)piVar39 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)piVar39 >> 8) + *(char *)((int)piVar39 + 2),(char)piVar39);
  uVar37 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar37 = (uint)((uVar37 & 1) != 0);
  puVar16 = puVar54 + *(int *)(uVar40 + 4) + (uint)((uVar38 & 1) != 0) + iVar24 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar40 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar38 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  cVar19 = (char)uVar48;
  if (SCARRY1((char)puVar23,'\b')) {
    uVar48 = uVar48 & 0xffffff00 | (uint)(byte)(cVar19 + bVar21);
    iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
    *(int *)(puVar16 + (uVar37 - 4)) = iVar24;
    *(int *)(puVar16 + (uVar37 - 8)) = iParm3;
    *(uint *)(puVar16 + (uVar37 - 0xc)) = uVar48;
    *(uint **)(puVar16 + (uVar37 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar16 + (int)(&DAT_ffffffec + uVar37)) = puVar16 + uVar37;
    *(undefined4 **)(puVar16 + (uVar37 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar16 + (uVar37 - 0x1c)) = unaff_ESI;
    puVar55 = puVar16 + (uVar37 - 0x20);
    *(undefined **)(puVar16 + (uVar37 - 0x20)) = puVar15;
    uVar48 = uVar48 + iParm3;
    pbVar41 = (byte *)(iVar24 - *(int *)(iVar24 + 9));
    *pbVar41 = *pbVar41 + bVar51;
    pbVar41[iParm3] = pbVar41[iParm3] & (byte)pbVar41;
  }
  else {
    piVar39 = (int *)((uint)puVar23 & 0xffff0000 |
                     (uint)CONCAT11((byte)(((uint)puVar23 & 0xffffff00) >> 8) | bVar21,bVar18));
    uVar38 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar38 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar38;
    uVar40 = uVar38 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar38 >> 8) + *(char *)(uVar38 + 2),(char)uVar38);
    uVar38 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar38 = (uint)((uVar38 & 1) != 0);
    puVar16 = puVar16 + *(int *)(uVar40 + 4) + uVar37 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar40 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    bVar18 = (char)puVar23 + 8;
    uVar37 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
    if (bVar18 == 0) {
      uVar48 = uVar48 & 0xffffff00 | (uint)(byte)(cVar19 + bVar21);
      iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
      *(int *)(puVar16 + (uVar38 - 4)) = iVar24;
      *(int *)(puVar16 + (uVar38 - 8)) = iParm3;
      *(uint *)(puVar16 + (uVar38 - 0xc)) = uVar48;
      *(uint **)(puVar16 + (uVar38 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar16 + (int)(&DAT_ffffffec + uVar38)) = puVar16 + uVar38;
      *(undefined4 **)(puVar16 + (uVar38 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar16 + (uVar38 - 0x1c)) = unaff_ESI;
      puVar56 = puVar16 + (uVar38 - 0x20);
      *(undefined **)(puVar16 + (uVar38 - 0x20)) = puVar15;
      uVar48 = uVar48 + iParm3;
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      pcVar44[iParm3] = pcVar44[iParm3] & (byte)pcVar44;
      goto code_r0x080429ec;
    }
    piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(bVar18 | bVar50));
    uVar37 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar37 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar37;
    uVar40 = uVar37 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar37 >> 8) + *(char *)(uVar37 + 2),(char)uVar37);
    uVar37 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar37 = (uint)((uVar37 & 1) != 0);
    puVar16 = puVar16 + *(int *)(uVar40 + 4) + uVar38 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar40 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    bVar18 = (char)puVar23 + 8;
    uVar38 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
    if ((char)bVar18 < 0) {
      iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
      *(int *)(puVar16 + (uVar37 - 4)) = iVar24;
      *(int *)(puVar16 + (uVar37 - 8)) = iParm3;
      *(uint *)(puVar16 + (uVar37 - 0xc)) = uVar48 & 0xffffff00 | (uint)(byte)(cVar19 + bVar21);
      *(uint **)(puVar16 + (uVar37 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar16 + (uVar37 - 0x14)) = puVar16 + uVar37;
      *(undefined4 **)(puVar16 + (uVar37 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar16 + (uVar37 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar16 + (uVar37 - 0x20)) = puVar15;
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      pcVar44[iParm3] = pcVar44[iParm3] & (byte)pcVar44;
      return;
    }
    piVar39 = (int *)((uint)puVar23 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8),bVar18));
    uVar38 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar38 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar38;
    uVar40 = uVar38 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar38 >> 8) + *(char *)(uVar38 + 2),(char)uVar38);
    uVar38 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar38 = (uint)((uVar38 & 1) != 0);
    puVar16 = puVar16 + *(int *)(uVar40 + 4) + uVar37 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar40 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    bVar18 = (char)puVar23 + 8;
    uVar37 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
    if (SCARRY1((char)puVar23,'\b') != (char)bVar18 < 0) {
      uVar48 = uVar48 & 0xffffff00 | (uint)(byte)(cVar19 + bVar21);
      iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
      *(int *)(puVar16 + (uVar38 - 4)) = iVar24;
      *(int *)(puVar16 + (uVar38 - 8)) = iParm3;
      *(uint *)(puVar16 + (uVar38 - 0xc)) = uVar48;
      *(uint **)(puVar16 + (uVar38 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar16 + (uVar38 - 0x14)) = puVar16 + uVar38;
      *(undefined4 **)(puVar16 + (uVar38 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar16 + (uVar38 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar16 + (uVar38 - 0x20)) = puVar15;
      pbVar41 = (byte *)(uVar48 + iParm3);
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      bVar18 = (byte)pcVar44;
      pcVar44[iParm3] = pcVar44[iParm3] & bVar18;
      if (!in_PF) {
        pcVar44[(int)(puVar16 + (uVar38 - 0x20))] =
             pcVar44[(int)(puVar16 + (uVar38 - 0x20))] | bVar46;
        *pcVar44 = *pcVar44 + bVar18;
        pcVar44 = (char *)((uint)pcVar44 & 0xffffff00 | (uint)(byte)(bVar18 - 0x30));
      }
      uVar48 = (uint)pcVar44 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
      bVar59 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar37 = (uint)bVar59;
      puVar16 = puVar16 + *(int *)(uVar48 + 4) + (uVar38 - 0x20);
      cVar19 = (char)puVar16 + bVar59;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar48 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      if (!in_PF) {
        puVar16[uVar37] = puVar16[uVar37] | bVar51;
        puVar16[(int)pbVar41 * 8 + uVar37] = puVar16[(int)pbVar41 * 8 + uVar37] + cVar19;
      }
      uVar37 = (uint)(puVar16 + uVar37) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar16 + uVar37) >> 8) + puVar16[uVar37 + 2],cVar19);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar38 = (uint)((uVar38 & 1) != 0);
      iVar24 = ((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8)) + *(int *)(uVar37 + 4)
      ;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      uVar22 = (ushort)puVar23 & 0xff00 | (ushort)bVar18;
      iVar42 = (int)(short)uVar22;
      if (!in_PF) {
        pbVar1 = (byte *)(iVar24 + uVar38 + iVar42);
        *pbVar1 = *pbVar1 | bVar18;
        pcVar44 = (char *)(iVar42 + (int)pbVar41 * 8);
        *pcVar44 = *pcVar44 + bVar18;
      }
      iVar43 = CONCAT22((short)uVar22 >> 0xf,
                        CONCAT11((char)((uint)iVar42 >> 8) + *(char *)(iVar42 + 2),bVar18));
      uVar37 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(iVar43 + 4);
      uVar48 = (uint)((uVar37 & 1) != 0);
      uVar37 = *puVar23;
      iVar42 = iVar24 + uVar38 + *puVar23;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(iVar43 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (byte)puVar23;
      bVar20 = bVar18 + 8;
      pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)bVar20);
      *(uint *)(iVar42 + uVar48 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar18,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar20 < 0) * 0x80 |
           (uint)(bVar20 == 0) * 0x40 |
           (uint)(((iVar24 + uVar38 & 0xfffffff) + (uVar37 & 0xfffffff) + uVar48 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar18) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if (!in_PF) {
        pcVar44[4] = pcVar44[4] | (byte)pbVar41;
        *pcVar44 = *pcVar44 + bVar20;
        pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)(bVar18 - 0x28));
      }
      uVar37 = (uint)pcVar44 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar24 = *(int *)(uVar37 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = DAT_5c08077a;
      uVar37 = (uint)puVar23 & 0xffffff00 | (uint)DAT_5c08077a;
      pcVar44 = (char *)(uVar37 + (int)pbVar41 * 8);
      *pcVar44 = *pcVar44 + DAT_5c08077a;
      uVar40 = (uint)puVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar23 >> 8) + *(char *)(uVar37 + 2),bVar18);
      uVar37 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar43 = *(int *)(uVar40 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar40 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
      _DAT_03ffffc4 = unaff_EDI + 2;
      *puVar15 = *unaff_ESI;
      if (!in_PF) {
        pcVar44[4] = pcVar44[4] | bVar46;
        *pcVar44 = *pcVar44 + bVar18;
        pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 - 0x28));
      }
      uVar25 = (uint)pcVar44 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
      uVar40 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar40 = (uint)((uVar40 & 1) != 0);
      iVar24 = iVar42 + uVar48 + -4 + iVar24 + (uint)((uVar38 & 1) != 0) + iVar43 +
               (uint)((uVar37 & 1) != 0) + *(int *)(uVar25 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar25 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      uVar38 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
      pbVar1 = (byte *)(iVar24 + uVar40 + 2 + uVar38);
      *pbVar1 = *pbVar1 | (byte)((uint)pbVar41 >> 8);
      pcVar44 = (char *)(uVar38 + (int)pbVar41 * 8);
      *pcVar44 = *pcVar44 + bVar18;
      uVar37 = (uint)puVar23 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar38 + 2),
                              bVar18);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar38 = (uint)((uVar38 & 1) != 0);
      iVar24 = iVar24 + uVar40 + 2 + *(int *)(uVar37 + 4);
      puVar57 = (undefined *)(iVar24 + uVar38);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      _DAT_03ffffc8 = unaff_ESI + 2;
      uVar37 = (uint)puVar23 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (in_PF) {
        uVar48 = (uint)puVar23 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar23 >> 8) + *(char *)(uVar37 + 2),unaff_ESI[1]);
        uVar37 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar57 = (undefined *)(iVar24 + uVar38 + *(int *)(uVar48 + 4) + (uint)((uVar37 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar23 = (uint *)(uVar48 + 2);
        *puVar23 = *puVar23 | (uint)puVar23;
        uVar37 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
      }
      *(byte *)(uVar37 + 0x4000004) = *(byte *)(uVar37 + 0x4000004) | (byte)uVar37;
      *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
      *(uint *)(puVar57 + -4) = uVar37;
      *(int *)(puVar57 + -8) = iParm3;
      *(byte **)(puVar57 + -0xc) = pbVar41;
      *(uint **)(puVar57 + -0x10) = unaff_EBX;
      *(undefined **)(puVar57 + -0x14) = puVar57;
      *(undefined4 **)(puVar57 + -0x18) = unaff_EBP;
      *(undefined **)(puVar57 + -0x1c) = _DAT_03ffffc8;
      *(undefined **)(puVar57 + -0x20) = _DAT_03ffffc4;
      uVar38 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((byte)pbVar41 + bVar21);
      iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
      *(int *)(puVar57 + -0x24) = iVar24;
      *(int *)(puVar57 + -0x28) = iParm3;
      *(uint *)(puVar57 + -0x2c) = uVar38;
      *(uint **)(puVar57 + -0x30) = unaff_EBX;
      *(undefined **)(puVar57 + -0x34) = puVar57 + -0x20;
      *(undefined4 **)(puVar57 + -0x38) = unaff_EBP;
      *(undefined **)(puVar57 + -0x3c) = _DAT_03ffffc8;
      *(undefined **)(puVar57 + -0x40) = _DAT_03ffffc4;
      pbVar41 = (byte *)(uVar38 + iParm3);
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      pcVar44[iParm3] = pcVar44[iParm3] & (byte)pcVar44;
      iVar24 = CONCAT31((int3)((uint)pcVar44 >> 8),0x7a);
      puVar57[iVar24 + -0x2ffc003e] = puVar57[iVar24 + -0x2ffc003e] | bVar21;
      uVar37 = (uint)pcVar44 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar44 >> 8) + *(char *)(iVar24 + 2),0x7a);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar38 = (uint)((uVar38 & 1) != 0);
      puVar15 = puVar57 + *(int *)(uVar37 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      uVar37 = (uint)puVar23 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar23 + '\b');
      *(byte *)(uVar37 + 0x4000004) = *(byte *)(uVar37 + 0x4000004) | bVar50;
      *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
      *(uint *)(puVar15 + uVar38) = uVar37;
      *(int *)(puVar15 + (uVar38 - 4)) = iParm3;
      *(byte **)(puVar15 + (uVar38 - 8)) = pbVar41;
      *(uint **)(puVar15 + (uVar38 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar15 + (uVar38 - 0x10)) = puVar15 + uVar38 + 4;
      *(undefined4 **)(puVar15 + (int)(&DAT_ffffffec + uVar38)) = unaff_EBP;
      *(undefined **)(puVar15 + (uVar38 - 0x18)) = _DAT_03ffffc8;
      *(undefined **)(puVar15 + (uVar38 - 0x1c)) = _DAT_03ffffc4;
      uVar48 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((char)pbVar41 + bVar21);
      iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
      *(int *)(puVar15 + (uVar38 - 0x20)) = iVar24;
      *(int *)(puVar15 + (uVar38 - 0x24)) = iParm3;
      *(uint *)(puVar15 + (uVar38 - 0x28)) = uVar48;
      *(uint **)(puVar15 + (uVar38 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar15 + (uVar38 - 0x30)) = puVar15 + (uVar38 - 0x1c);
      *(undefined4 **)(puVar15 + (uVar38 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar15 + (uVar38 - 0x38)) = _DAT_03ffffc8;
      *(undefined **)(puVar15 + (uVar38 - 0x3c)) = _DAT_03ffffc4;
      _DAT_03fffff8 = (byte *)(uVar48 + iParm3);
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      pcVar44[iParm3] = pcVar44[iParm3] & (byte)pcVar44;
      pcVar44 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
      *pcVar44 = *pcVar44 + 'z';
      cVar19 = DAT_a408077c + '\a';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar19,0x7a)) + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      uVar38 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
      pcVar44 = (char *)(uVar38 + (int)_DAT_03fffff8 * 8);
      *pcVar44 = *pcVar44 + bVar18;
      cVar19 = *(char *)(uVar38 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(((uint)puVar23 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + cVar19,bVar18))
                        + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      _DAT_04000000 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
      _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
      *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
      _DAT_03fffff0 = 0x4000004;
      _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar21);
      _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
      _DAT_03ffffd0 = &DAT_03ffffe4;
      iVar24 = _DAT_03ffffd8 + iParm3;
      pcVar45 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
      _DAT_03ffffcc = unaff_EBP;
      _DAT_03ffffd4 = unaff_EBX;
      _DAT_03ffffdc = iParm3;
      _DAT_03ffffe4 = _DAT_03ffffc4;
      _DAT_03ffffe8 = _DAT_03ffffc8;
      _DAT_03ffffec = unaff_EBP;
      _DAT_03fffff4 = unaff_EBX;
      _DAT_03fffffc = iParm3;
      *pcVar45 = *pcVar45 + bVar51;
      pcVar45[iParm3] = pcVar45[iParm3] & (byte)pcVar45;
      bVar21 = (byte)pcVar45 | bVar21;
      uVar38 = (uint)pcVar45 & 0xffffff00 | (uint)bVar21;
      pcVar44 = (char *)(uVar38 + iVar24 * 8);
      *pcVar44 = *pcVar44 + bVar21;
      uVar37 = (uint)pcVar45 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar45 & 0xffffff00) >> 8) + *(char *)(uVar38 + 2),
                              bVar21);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar38 = (uint)((uVar38 & 1) != 0);
      iVar24 = *(int *)(uVar37 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      puVar58 = (undefined4 *)(iVar24 + uVar38 + 0x3ffffc0);
      *(undefined4 **)(iVar24 + uVar38 + 0x3ffffc0) = unaff_EBP;
      cVar19 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar58 = puVar58 + -1;
        *puVar58 = *unaff_EBP;
        cVar19 = cVar19 + -1;
      } while (0 < cVar19);
      *(uint *)(iVar24 + uVar38 + 0x3ffffa0) = iVar24 + uVar38 + 0x3ffffc0;
      uVar37 = (uint)CONCAT11(bVar18 / 4,bVar18) & 0xffffff00;
      uVar38 = (uint)puVar23 & 0xffff0000 | uVar37;
      pcVar44 = (char *)(uVar38 | (uint)bVar18 & 0xffffff04);
      cVar19 = (char)((uint)bVar18 & 0xffffff04);
      *pcVar44 = *pcVar44 + cVar19;
      bVar18 = cVar19 - 0x30;
      cVar19 = *(char *)((uVar38 | (uint)bVar18) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(((uint)puVar23 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar37 >> 8) + cVar19,bVar18)) + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      pcVar17 = (code *)swi(3);
      (*pcVar17)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
      return;
    }
    piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(byte)(bVar18 | (byte)(uVar48 >> 8)));
    uVar37 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar37 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar37;
    uVar40 = uVar37 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar37 >> 8) + *(char *)(uVar37 + 2),(char)uVar37);
    uVar37 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar24 = *(int *)(uVar40 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar40 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
    uVar40 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar40 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar40;
    uVar25 = uVar40 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar40 >> 8) + *(char *)(uVar40 + 2),(char)uVar40);
    uVar40 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar55 = puVar16 + (uint)((uVar40 & 1) != 0) +
                        *(int *)(uVar25 + 4) + (uint)((uVar37 & 1) != 0) + iVar24 + uVar38 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar25 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    pbVar41 = (byte *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
  }
  *pbVar41 = *pbVar41 | bVar21;
  pbVar41[uVar48 * 8] = pbVar41[uVar48 * 8] + (char)pbVar41;
  uVar37 = (uint)pbVar41 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar41 >> 8) + pbVar41[2],(char)pbVar41);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar56 = puVar55 + (uint)((uVar38 & 1) != 0) + *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
code_r0x080429ec:
  *(byte *)(uVar48 + 7) = bVar51;
  puVar56[(int)pcVar44] = puVar56[(int)pcVar44] | (byte)uVar48;
  *pcVar44 = *pcVar44 + (char)pcVar44;
  bVar18 = (char)pcVar44 - 0x30;
  cVar19 = *(char *)(((uint)pcVar44 & 0xffffff00 | (uint)bVar18) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(((uint)pcVar44 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar44 & 0xffffff00) >> 8) + cVar19,bVar18)) + 2)
  ;
  *puVar23 = *puVar23 | (uint)puVar23;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int chdir(char *__path)

{
  byte *pbVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  uint uVar14;
  undefined *puVar15;
  undefined *puVar16;
  code *pcVar17;
  byte bVar18;
  char cVar19;
  byte bVar20;
  byte bVar21;
  ushort uVar22;
  uint *puVar23;
  int iVar24;
  uint uVar25;
  uint uVar26;
  uint uVar27;
  uint uVar28;
  uint uVar29;
  uint uVar30;
  uint uVar31;
  uint uVar32;
  uint uVar33;
  uint uVar34;
  uint uVar35;
  uint uVar36;
  uint uVar37;
  uint uVar38;
  int *piVar39;
  uint uVar40;
  byte *pbVar41;
  int iVar42;
  int iVar43;
  char *pcVar44;
  char *pcVar45;
  byte bVar46;
  int in_ECX;
  byte bVar47;
  byte bVar49;
  byte *in_EDX;
  uint uVar48;
  byte bVar50;
  byte bVar51;
  uint *unaff_EBX;
  int iVar52;
  undefined *puVar53;
  undefined *puVar54;
  undefined *puVar55;
  undefined *puVar56;
  undefined *puVar57;
  undefined4 *puVar58;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar59;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack186 [12];
  undefined auStack174 [4];
  undefined auStack170 [4];
  undefined auStack166 [4];
  undefined auStack162 [4];
  undefined auStack158 [4];
  undefined auStack154 [4];
  undefined auStack150 [4];
  undefined auStack146 [4];
  undefined auStack142 [4];
  undefined auStack138 [4];
  undefined auStack134 [4];
  undefined auStack130 [4];
  undefined auStack126 [10];
  undefined auStack116 [4];
  undefined auStack112 [4];
  undefined auStack108 [4];
  undefined auStack104 [4];
  undefined auStack100 [4];
  undefined auStack96 [4];
  undefined auStack92 [4];
  undefined auStack88 [4];
  undefined auStack84 [4];
  undefined auStack80 [4];
  undefined auStack76 [4];
  undefined auStack72 [4];
  undefined auStack68 [4];
  undefined auStack64 [10];
  undefined auStack54 [4];
  undefined auStack50 [4];
  undefined auStack46 [4];
  undefined auStack42 [4];
  undefined auStack38 [4];
  undefined auStack34 [4];
  undefined auStack30 [4];
  undefined auStack26 [4];
  undefined auStack22 [4];
  undefined auStack18 [4];
  undefined auStack14 [8];
  undefined auStack6 [4];
  undefined auStack2 [2];
  
  bVar18 = (char)__path - 0x30;
  uVar37 = (uint)__path & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__path & 0xffffff00) >> 8) +
                          *(char *)(((uint)__path & 0xffffff00 | (uint)bVar18) + 2),bVar18);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar24 = *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar37 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  bVar51 = (byte)((uint)unaff_EBX >> 8);
  in_EDX[7] = in_EDX[7] + bVar51;
  in_EDX[uVar37] = in_EDX[uVar37] | bVar51;
  pcVar44 = (char *)(uVar37 + (int)in_EDX * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar48 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar37 + 2),bVar18);
  uVar37 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar37 = (uint)((uVar37 & 1) != 0);
  puVar15 = &stack0x00000000 + *(int *)(uVar48 + 4) + (uint)((uVar38 & 1) != 0) + iVar24;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar48 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar38 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 0x82);
  bVar21 = (byte)in_ECX;
  *(byte *)(uVar38 + 0x4000002) = *(byte *)(uVar38 + 0x4000002) | bVar21;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar15 + (uVar37 - 2)) = uVar38;
  *(int *)(puVar15 + (uVar37 - 6)) = in_ECX;
  *(byte **)(puVar15 + (int)(&DAT_fffffff6 + uVar37)) = in_EDX;
  *(uint **)(puVar15 + (uVar37 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar37 - 0x12)) = puVar15 + uVar37 + 2;
  *(undefined4 **)(puVar15 + (uVar37 - 0x16)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar37 - 0x1a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar37 - 0x1e)) = unaff_EDI;
  uVar48 = (uint)in_EDX & 0xffffff00 | (uint)(byte)((char)in_EDX + bVar21);
  iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
  *(int *)(puVar15 + (uVar37 - 0x22)) = iVar24;
  *(int *)(puVar15 + (uVar37 - 0x26)) = in_ECX;
  *(uint *)(puVar15 + (uVar37 - 0x2a)) = uVar48;
  *(uint **)(puVar15 + (uVar37 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar37 - 0x32)) = puVar15 + (uVar37 - 0x1e);
  *(undefined4 **)(puVar15 + (uVar37 - 0x36)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar37 - 0x3a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar37 - 0x3e)) = unaff_EDI;
  pbVar41 = (byte *)(uVar48 + in_ECX);
  pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
  *pcVar44 = *pcVar44 + bVar51;
  pcVar44[in_ECX] = pcVar44[in_ECX] & (byte)pcVar44;
  pbVar41[7] = pbVar41[7] | bVar51;
  (pbVar41 + -0x2ffc0000)[(int)pcVar44] = (pbVar41 + -0x2ffc0000)[(int)pcVar44] | (byte)pbVar41;
  uVar40 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(byte)pcVar44);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar48 = (uint)((uVar38 & 1) != 0);
  puVar15 = puVar15 + *(int *)(uVar40 + 4) + (uVar37 - 0x3e);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar40 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar38 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8) | 0x7a;
  *(byte *)(uVar38 + 0x4000002) =
       *(byte *)(uVar38 + 0x4000002) | (byte)(((uint)puVar23 & 0xffffff00) >> 8);
  *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
  *(uint *)(puVar15 + (uVar48 - 2)) = uVar38;
  *(int *)(puVar15 + (uVar48 - 6)) = in_ECX;
  *(byte **)(puVar15 + (uVar48 - 10)) = pbVar41;
  *(uint **)(puVar15 + (uVar48 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar48 - 0x12)) = puVar15 + uVar48 + 2;
  *(undefined4 **)(puVar15 + (uVar48 - 0x16)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar48 - 0x1a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar48 - 0x1e)) = unaff_EDI;
  uVar37 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((byte)pbVar41 + bVar21);
  iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
  *(int *)(puVar15 + (uVar48 - 0x22)) = iVar24;
  *(int *)(puVar15 + (uVar48 - 0x26)) = in_ECX;
  *(uint *)(puVar15 + (uVar48 - 0x2a)) = uVar37;
  *(uint **)(puVar15 + (uVar48 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar48 - 0x32)) = puVar15 + (uVar48 - 0x1e);
  *(undefined4 **)(puVar15 + (uVar48 - 0x36)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar48 - 0x3a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar48 - 0x3e)) = unaff_EDI;
  pbVar41 = (byte *)(uVar37 + in_ECX);
  pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
  *pcVar44 = *pcVar44 + bVar51;
  pcVar44[in_ECX] = pcVar44[in_ECX] & (byte)pcVar44;
  pbVar41[7] = pbVar41[7] + bVar51;
  bVar46 = (byte)((uint)in_ECX >> 8);
  (pbVar41 + -0x2ffc0000)[(int)pcVar44] = (pbVar41 + -0x2ffc0000)[(int)pcVar44] | bVar46;
  uVar37 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(byte)pcVar44);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar38 & 1) != 0);
  puVar15 = puVar15 + *(int *)(uVar37 + 4) + (uVar48 - 0x3e);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar38 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((byte)puVar23 + 0x82 + (0xf7 < (byte)puVar23));
  *(byte *)(uVar38 + 0x4000002) = *(byte *)(uVar38 + 0x4000002) | bVar51;
  *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
  *(uint *)(puVar15 + (uVar14 - 2)) = uVar38;
  *(int *)(puVar15 + (uVar14 - 6)) = in_ECX;
  *(byte **)(puVar15 + (uVar14 - 10)) = pbVar41;
  *(uint **)(puVar15 + (uVar14 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar14 - 0x12)) = puVar15 + uVar14 + 2;
  *(undefined4 **)(puVar15 + (uVar14 - 0x16)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar14 - 0x1a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar14 - 0x1e)) = unaff_EDI;
  uVar37 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((char)pbVar41 + bVar21);
  iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
  *(int *)(puVar15 + (uVar14 - 0x22)) = iVar24;
  *(int *)(puVar15 + (uVar14 - 0x26)) = in_ECX;
  *(uint *)(puVar15 + (uVar14 - 0x2a)) = uVar37;
  *(uint **)(puVar15 + (uVar14 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar15 + (uVar14 - 0x32)) = puVar15 + (uVar14 - 0x1e);
  *(undefined4 **)(puVar15 + (uVar14 - 0x36)) = unaff_EBP;
  *(undefined **)(puVar15 + (uVar14 - 0x3a)) = unaff_ESI;
  *(undefined **)(puVar15 + (uVar14 - 0x3e)) = unaff_EDI;
  pbVar41 = (byte *)(uVar37 + in_ECX);
  pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
  *pcVar44 = *pcVar44 + bVar51;
  bVar18 = (byte)pcVar44;
  pcVar44[in_ECX] = pcVar44[in_ECX] & bVar18;
  pbVar41[7] = pbVar41[7] - bVar51;
  uVar37 = (uint)pcVar44 & 0xffff0000;
  uVar38 = (uint)CONCAT11((byte)((uint)pcVar44 >> 8) | bVar18,bVar18);
  bVar18 = bVar18 + *(char *)(uVar37 | uVar38);
  uVar38 = uVar38 & 0xffffff00;
  uVar48 = uVar37 | uVar38 | (uint)bVar18;
  pcVar44 = (char *)(uVar48 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar37 = uVar37 | (uint)CONCAT11((char)(uVar38 >> 8) + *(char *)(uVar48 + 2),bVar18);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar24 = *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar37 = (uint)puVar23 & 0xffffff00;
  bVar47 = (byte)pbVar41;
  bVar18 = ((byte)puVar23 + 0x8e) - (0xf7 < (byte)puVar23) | bVar47;
  bVar18 = bVar18 + *(char *)(uVar37 | (uint)bVar18);
  pcVar44 = (char *)((uVar37 | (uint)bVar18) + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar48 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar37 >> 8) + *(char *)((uVar37 | (uint)bVar18) + 2),bVar18);
  uVar37 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar42 = *(int *)(uVar48 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar48 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  cVar19 = (char)puVar23 + '\b';
  pbVar41[7] = pbVar41[7] & bVar51;
  bVar50 = (byte)unaff_EBX;
  uVar40 = (uint)puVar23 & 0xffff0000;
  uVar48 = (uint)CONCAT11((byte)((uint)puVar23 >> 8) | bVar50,cVar19);
  bVar18 = cVar19 + *(char *)(uVar40 | uVar48);
  uVar48 = uVar48 & 0xffffff00;
  uVar25 = uVar40 | uVar48 | (uint)bVar18;
  pcVar44 = (char *)(uVar25 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar40 = uVar40 | (uint)CONCAT11((char)(uVar48 >> 8) + *(char *)(uVar25 + 2),bVar18);
  uVar48 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar43 = *(int *)(uVar40 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar40 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar40 = (uint)puVar23 & 0xffffff00;
  bVar18 = (char)puVar23 + 8U & 0x7a | bVar46;
  bVar18 = bVar18 + *(char *)(uVar40 | (uint)bVar18);
  pcVar44 = (char *)((uVar40 | (uint)bVar18) + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar25 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar40 >> 8) + *(char *)((uVar40 | (uint)bVar18) + 2),bVar18);
  uVar40 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar25 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar25 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  cVar19 = (char)puVar23 + '\b';
  pbVar41[7] = pbVar41[7] - bVar51;
  bVar49 = (byte)((uint)pbVar41 >> 8);
  uVar27 = (uint)puVar23 & 0xffff0000;
  uVar25 = (uint)CONCAT11((byte)((uint)puVar23 >> 8) | bVar49,cVar19);
  bVar18 = cVar19 + *(char *)(uVar27 | uVar25);
  uVar25 = uVar25 & 0xffffff00;
  uVar26 = uVar27 | uVar25 | (uint)bVar18;
  pcVar44 = (char *)(uVar26 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + bVar18;
  uVar27 = uVar27 | (uint)CONCAT11((char)(uVar25 >> 8) + *(char *)(uVar26 + 2),bVar18);
  uVar25 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar4 = *(int *)(uVar27 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar27 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 0x8e;
  piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
  *(byte *)piVar39 = *(byte *)piVar39 | bVar18;
  uVar27 = (int)piVar39 + *piVar39;
  pcVar44 = (char *)(uVar27 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + (char)uVar27;
  uVar26 = uVar27 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar27 >> 8) + *(char *)(uVar27 + 2),(char)uVar27);
  uVar27 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar5 = *(int *)(uVar26 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar26 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar26 = (uint)puVar23 & 0xffffff00;
  pcVar44 = (char *)(uVar26 | (uint)bVar18);
  pbVar41[7] = pbVar41[7] ^ bVar51;
  *(byte *)((int)unaff_EBX + (int)pcVar44) = *(byte *)((int)unaff_EBX + (int)pcVar44) | bVar21;
  *pcVar44 = *pcVar44 + bVar18;
  bVar18 = (char)puVar23 - 0x28;
  uVar28 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar26 >> 8) + *(char *)((uVar26 | (uint)bVar18) + 2),bVar18);
  uVar26 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar6 = *(int *)(uVar28 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar28 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  piVar39 = (int *)(((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8)) ^ 0x7a);
  *(byte *)piVar39 = *(byte *)piVar39 | bVar50;
  uVar28 = (int)piVar39 + *piVar39;
  pcVar44 = (char *)(uVar28 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + (char)uVar28;
  uVar29 = uVar28 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar28 >> 8) + *(char *)(uVar28 + 2),(char)uVar28);
  uVar28 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar7 = *(int *)(uVar29 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar29 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar29 = (uint)puVar23 & 0xffffff00;
  pcVar44 = (char *)(uVar29 | (uint)bVar18);
  bVar20 = (byte)(uVar29 >> 8);
  *(byte *)((int)unaff_EBX + (int)pcVar44) = *(byte *)((int)unaff_EBX + (int)pcVar44) | bVar20;
  *pcVar44 = *pcVar44 + bVar18;
  bVar18 = (char)puVar23 - 0x28;
  uVar30 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11(bVar20 + *(char *)((uVar29 | (uint)bVar18) + 2),bVar18);
  uVar29 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar8 = *(int *)(uVar30 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar30 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
  *(byte *)piVar39 = *(byte *)piVar39 | bVar49;
  uVar30 = (int)piVar39 + *piVar39;
  pcVar44 = (char *)(uVar30 + (int)pbVar41 * 8);
  *pcVar44 = *pcVar44 + (char)uVar30;
  uVar31 = uVar30 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar30 >> 8) + *(char *)(uVar30 + 2),(char)uVar30);
  uVar30 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar9 = *(int *)(uVar31 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar31 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  pcVar44 = (char *)(((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8)) + 1);
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + (int)pcVar44) = *(byte *)((int)unaff_EBX + (int)pcVar44) | bVar51;
    *pcVar44 = *pcVar44 + (char)pcVar44;
    pcVar44 = (char *)((uint)pcVar44 & 0xffffff00 | (uint)(byte)((char)pcVar44 - 0x30));
  }
  uVar32 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
  uVar31 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar10 = *(int *)(uVar32 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar32 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
  if (!in_PF) {
    pcVar44[3] = pcVar44[3] | bVar21;
    *pcVar44 = *pcVar44 + bVar18;
    pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 - 0x28));
  }
  uVar33 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
  uVar32 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar11 = *(int *)(uVar33 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar33 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar33 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
  uVar34 = uVar33 - 1;
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar34) = *(byte *)((int)unaff_EBX + uVar34) | bVar47;
    pcVar44 = (char *)(uVar34 + (int)pbVar41 * 8);
    *pcVar44 = *pcVar44 + (char)uVar34;
  }
  uVar34 = uVar34 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar34 >> 8) + *(char *)(uVar33 + 1),(char)uVar34);
  uVar33 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar12 = *(int *)(uVar34 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar34 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar34 = (uint)puVar23 & 0xffffff00;
  pcVar44 = (char *)(uVar34 | (uint)bVar18);
  if (!in_PF) {
    pcVar44[3] = pcVar44[3] | (byte)(uVar34 >> 8);
    *pcVar44 = *pcVar44 + bVar18;
    pcVar44 = (char *)(uVar34 | (uint)(byte)((char)puVar23 - 0x28));
  }
  uVar35 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
  uVar34 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar34 = (uint)((uVar34 & 1) != 0);
  iVar13 = *(int *)(uVar35 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar35 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar35 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  *(uint *)(puVar15 + iVar13 + (uint)((uVar33 & 1) != 0) +
                               iVar12 + (uint)((uVar32 & 1) != 0) +
                                        iVar11 + (uint)((uVar31 & 1) != 0) +
                                                 iVar10 + (uint)((uVar30 & 1) != 0) +
                                                          iVar9 + (uint)((uVar29 & 1) != 0) +
                                                                  iVar8 + (uint)((uVar28 & 1) != 0)
                                                                          + iVar7 + (uint)((uVar26 &
                                                                                           1) != 0)
                                                                                    + iVar6 + (uint)
                                                  ((uVar27 & 1) != 0) +
                                                  iVar5 + (uint)((uVar25 & 1) != 0) +
                                                          iVar4 + (uint)((uVar40 & 1) != 0) +
                                                                  iVar3 + (uint)((uVar48 & 1) != 0)
                                                                          + iVar43 + (uint)((uVar37 
                                                  & 1) != 0) +
                                                  iVar42 + (uint)((uVar38 & 1) != 0) +
                                                           iVar24 + (uVar14 - 0x3e) + uVar34 + 6) =
       uVar35;
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar35) = *(byte *)((int)unaff_EBX + uVar35) | bVar46;
    pcVar44 = (char *)(uVar35 + (int)pbVar41 * 8);
    *pcVar44 = *pcVar44 + bVar18;
  }
  uVar36 = (uint)puVar23 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar35 + 2),bVar18);
  uVar35 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar35 = (uint)((uVar35 & 1) != 0);
  puVar15 = puVar15 + iVar13 + (uint)((uVar33 & 1) != 0) +
                               iVar12 + (uint)((uVar32 & 1) != 0) +
                                        iVar11 + (uint)((uVar31 & 1) != 0) +
                                                 iVar10 + (uint)((uVar30 & 1) != 0) +
                                                          iVar9 + (uint)((uVar29 & 1) != 0) +
                                                                  iVar8 + (uint)((uVar28 & 1) != 0)
                                                                          + iVar7 + (uint)((uVar26 &
                                                                                           1) != 0)
                                                                                    + iVar6 + (uint)
                                                  ((uVar27 & 1) != 0) +
                                                  iVar5 + (uint)((uVar25 & 1) != 0) +
                                                          iVar4 + (uint)((uVar40 & 1) != 0) +
                                                                  iVar3 + (uint)((uVar48 & 1) != 0)
                                                                          + iVar43 + (uint)((uVar37 
                                                  & 1) != 0) +
                                                  iVar42 + (uint)((uVar38 & 1) != 0) +
                                                           iVar24 + (uVar14 - 0x3e) +
            *(int *)(uVar36 + 4) + uVar34 + 6;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar36 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
  *(undefined **)(puVar15 + uVar35 + -4) = puVar15 + uVar35;
  if (!in_PF) {
    pcVar44[3] = pcVar44[3] | bVar51;
    *pcVar44 = *pcVar44 + bVar18;
    pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 - 0x28));
  }
  uVar37 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar38 = (uint)((uVar38 & 1) != 0);
  iVar24 = *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  uVar37 = *(uint *)((int)(puVar15 + iVar24 + uVar35 + -4) + uVar38);
  if (!in_PF) {
    pbVar1 = (byte *)((int)unaff_EBX + uVar37 + 0xd0040000);
    *pbVar1 = *pbVar1 | (byte)uVar37;
  }
  uVar48 = uVar37 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar37 >> 8) + *(char *)(uVar37 + 2),(byte)uVar37);
  uVar37 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar42 = *(int *)(uVar48 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar48 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar48 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  iVar52 = *(int *)((int)(puVar15 + iVar24 + uVar35 + -4) + uVar38 + 4 + iVar42 +
                   (uint)((uVar37 & 1) != 0));
  puVar53 = (undefined *)(iVar52 + 4);
  if (in_PF) {
    uVar37 = (uint)puVar23 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar48 + 2),bVar18
                           );
    uVar38 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar53 = (undefined *)(iVar52 + 4 + *(int *)(uVar37 + 4) + (uint)((uVar38 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar37 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    uVar48 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
  }
  *(byte *)(uVar48 + 0x4000003) = *(byte *)(uVar48 + 0x4000003) | bVar47;
  *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
  *(uint *)(puVar53 + -4) = uVar48;
  *(int *)(puVar53 + -8) = in_ECX;
  *(byte **)(puVar53 + -0xc) = pbVar41;
  *(uint **)(puVar53 + -0x10) = unaff_EBX;
  *(undefined **)(puVar53 + -0x14) = puVar53;
  *(undefined4 **)(puVar53 + -0x18) = unaff_EBP;
  *(undefined **)(puVar53 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar53 + -0x20) = unaff_EDI;
  uVar38 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)(bVar47 + bVar21);
  iVar24 = uVar48 - *(int *)(uVar48 + 0x13);
  *(int *)(puVar53 + -0x24) = iVar24;
  *(int *)(puVar53 + -0x28) = in_ECX;
  *(uint *)(puVar53 + -0x2c) = uVar38;
  *(uint **)(puVar53 + -0x30) = unaff_EBX;
  *(undefined **)(puVar53 + -0x34) = puVar53 + -0x20;
  *(undefined4 **)(puVar53 + -0x38) = unaff_EBP;
  *(undefined **)(puVar53 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar53 + -0x40) = unaff_EDI;
  pbVar41 = (byte *)(uVar38 + in_ECX);
  pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
  *pcVar44 = *pcVar44 + bVar51;
  pcVar44[in_ECX] = pcVar44[in_ECX] & (byte)pcVar44;
  *(char **)(puVar53 + -0x44) = pcVar44;
  *(int *)(puVar53 + -0x48) = in_ECX;
  *(byte **)(puVar53 + -0x4c) = pbVar41;
  *(uint **)(puVar53 + -0x50) = unaff_EBX;
  *(undefined **)(puVar53 + -0x54) = puVar53 + -0x40;
  *(undefined4 **)(puVar53 + -0x58) = unaff_EBP;
  *(undefined **)(puVar53 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar53 + -0x60) = unaff_EDI;
  if (!in_PF) {
    pbVar1 = (byte *)((int)((int)unaff_EBX + -0x2ffc0000) + (int)pcVar44);
    *pbVar1 = *pbVar1 | bVar50;
  }
  uVar37 = (uint)pcVar44 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(byte)pcVar44);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar38 = (uint)((uVar38 & 1) != 0);
  iVar24 = *(int *)(uVar37 + 4);
  puVar54 = puVar53 + iVar24 + -0x60 + uVar38;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar37 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  if (in_PF) {
    uVar48 = (uint)puVar23 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar37 + 2),bVar18
                           );
    uVar37 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar54 = puVar53 + iVar24 + -0x60 + (uint)((uVar37 & 1) != 0) + *(int *)(uVar48 + 4) + uVar38;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar48 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    uVar37 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
  }
  *(byte *)(uVar37 + 0x4000003) = *(byte *)(uVar37 + 0x4000003) | bVar46;
  *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
  *(uint *)(puVar54 + -4) = uVar37;
  *(int *)(puVar54 + -8) = in_ECX;
  *(byte **)(puVar54 + -0xc) = pbVar41;
  *(uint **)(puVar54 + -0x10) = unaff_EBX;
  *(undefined **)(puVar54 + -0x14) = puVar54;
  *(undefined4 **)(puVar54 + -0x18) = unaff_EBP;
  *(undefined **)(puVar54 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar54 + -0x20) = unaff_EDI;
  uVar48 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((char)pbVar41 + bVar21);
  iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
  *(int *)(puVar54 + -0x24) = iVar24;
  *(int *)(puVar54 + -0x28) = in_ECX;
  *(uint *)(puVar54 + -0x2c) = uVar48;
  *(uint **)(puVar54 + -0x30) = unaff_EBX;
  *(undefined **)(puVar54 + -0x34) = puVar54 + -0x20;
  *(undefined4 **)(puVar54 + -0x38) = unaff_EBP;
  *(undefined **)(puVar54 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar54 + -0x40) = unaff_EDI;
  uVar48 = uVar48 + in_ECX;
  piVar39 = (int *)(iVar24 - *(int *)(iVar24 + 9));
  *(byte *)piVar39 = *(char *)piVar39 + bVar51;
  *(byte *)((int)piVar39 + in_ECX) = *(byte *)((int)piVar39 + in_ECX) & (byte)piVar39;
  *(undefined4 *)(puVar54 + -0x44) = 0xb408077a;
  uVar38 = (int)piVar39 + *piVar39;
  pcVar44 = (char *)(uVar38 + uVar48 * 8);
  *pcVar44 = *pcVar44 + (char)uVar38;
  uVar37 = uVar38 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar38 >> 8) + *(char *)(uVar38 + 2),(char)uVar38);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar24 = *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
  puVar15 = unaff_EDI + 1;
  uVar2 = in((short)uVar48);
  *unaff_EDI = uVar2;
  if (!in_PF) {
    piVar39 = (int *)((int)piVar39 + *piVar39);
    *(char *)(piVar39 + uVar48 * 2) = *(char *)(piVar39 + uVar48 * 2) + (char)piVar39;
  }
  uVar40 = (uint)piVar39 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)piVar39 >> 8) + *(char *)((int)piVar39 + 2),(char)piVar39);
  uVar37 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar37 = (uint)((uVar37 & 1) != 0);
  puVar16 = puVar54 + *(int *)(uVar40 + 4) + (uint)((uVar38 & 1) != 0) + iVar24 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar40 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  bVar18 = (char)puVar23 + 8;
  uVar38 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
  cVar19 = (char)uVar48;
  if (SCARRY1((char)puVar23,'\b')) {
    uVar48 = uVar48 & 0xffffff00 | (uint)(byte)(cVar19 + bVar21);
    iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
    *(int *)(puVar16 + (uVar37 - 4)) = iVar24;
    *(int *)(puVar16 + (uVar37 - 8)) = in_ECX;
    *(uint *)(puVar16 + (uVar37 - 0xc)) = uVar48;
    *(uint **)(puVar16 + (uVar37 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar16 + (int)(&DAT_ffffffec + uVar37)) = puVar16 + uVar37;
    *(undefined4 **)(puVar16 + (uVar37 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar16 + (uVar37 - 0x1c)) = unaff_ESI;
    puVar55 = puVar16 + (uVar37 - 0x20);
    *(undefined **)(puVar16 + (uVar37 - 0x20)) = puVar15;
    uVar48 = uVar48 + in_ECX;
    pbVar41 = (byte *)(iVar24 - *(int *)(iVar24 + 9));
    *pbVar41 = *pbVar41 + bVar51;
    pbVar41[in_ECX] = pbVar41[in_ECX] & (byte)pbVar41;
  }
  else {
    piVar39 = (int *)((uint)puVar23 & 0xffff0000 |
                     (uint)CONCAT11((byte)(((uint)puVar23 & 0xffffff00) >> 8) | bVar21,bVar18));
    uVar38 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar38 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar38;
    uVar40 = uVar38 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar38 >> 8) + *(char *)(uVar38 + 2),(char)uVar38);
    uVar38 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar38 = (uint)((uVar38 & 1) != 0);
    puVar16 = puVar16 + *(int *)(uVar40 + 4) + uVar37 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar40 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    bVar18 = (char)puVar23 + 8;
    uVar37 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
    if (bVar18 == 0) {
      uVar48 = uVar48 & 0xffffff00 | (uint)(byte)(cVar19 + bVar21);
      iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
      *(int *)(puVar16 + (uVar38 - 4)) = iVar24;
      *(int *)(puVar16 + (uVar38 - 8)) = in_ECX;
      *(uint *)(puVar16 + (uVar38 - 0xc)) = uVar48;
      *(uint **)(puVar16 + (uVar38 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar16 + (int)(&DAT_ffffffec + uVar38)) = puVar16 + uVar38;
      *(undefined4 **)(puVar16 + (uVar38 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar16 + (uVar38 - 0x1c)) = unaff_ESI;
      puVar56 = puVar16 + (uVar38 - 0x20);
      *(undefined **)(puVar16 + (uVar38 - 0x20)) = puVar15;
      uVar48 = uVar48 + in_ECX;
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      pcVar44[in_ECX] = pcVar44[in_ECX] & (byte)pcVar44;
      goto code_r0x080429ec;
    }
    piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(bVar18 | bVar50));
    uVar37 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar37 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar37;
    uVar40 = uVar37 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar37 >> 8) + *(char *)(uVar37 + 2),(char)uVar37);
    uVar37 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar37 = (uint)((uVar37 & 1) != 0);
    puVar16 = puVar16 + *(int *)(uVar40 + 4) + uVar38 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar40 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    bVar18 = (char)puVar23 + 8;
    uVar38 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
    if ((char)bVar18 < 0) {
      iVar24 = uVar38 - *(int *)(uVar38 + 0x13);
      *(int *)(puVar16 + (uVar37 - 4)) = iVar24;
      *(int *)(puVar16 + (uVar37 - 8)) = in_ECX;
      *(uint *)(puVar16 + (uVar37 - 0xc)) = uVar48 & 0xffffff00 | (uint)(byte)(cVar19 + bVar21);
      *(uint **)(puVar16 + (uVar37 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar16 + (uVar37 - 0x14)) = puVar16 + uVar37;
      *(undefined4 **)(puVar16 + (uVar37 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar16 + (uVar37 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar16 + (uVar37 - 0x20)) = puVar15;
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      pcVar44[in_ECX] = pcVar44[in_ECX] & (byte)pcVar44;
      return;
    }
    piVar39 = (int *)((uint)puVar23 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8),bVar18));
    uVar38 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar38 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar38;
    uVar40 = uVar38 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar38 >> 8) + *(char *)(uVar38 + 2),(char)uVar38);
    uVar38 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar38 = (uint)((uVar38 & 1) != 0);
    puVar16 = puVar16 + *(int *)(uVar40 + 4) + uVar37 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar40 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    bVar18 = (char)puVar23 + 8;
    uVar37 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
    if (SCARRY1((char)puVar23,'\b') != (char)bVar18 < 0) {
      uVar48 = uVar48 & 0xffffff00 | (uint)(byte)(cVar19 + bVar21);
      iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
      *(int *)(puVar16 + (uVar38 - 4)) = iVar24;
      *(int *)(puVar16 + (uVar38 - 8)) = in_ECX;
      *(uint *)(puVar16 + (uVar38 - 0xc)) = uVar48;
      *(uint **)(puVar16 + (uVar38 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar16 + (uVar38 - 0x14)) = puVar16 + uVar38;
      *(undefined4 **)(puVar16 + (uVar38 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar16 + (uVar38 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar16 + (uVar38 - 0x20)) = puVar15;
      pbVar41 = (byte *)(uVar48 + in_ECX);
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      bVar18 = (byte)pcVar44;
      pcVar44[in_ECX] = pcVar44[in_ECX] & bVar18;
      if (!in_PF) {
        pcVar44[(int)(puVar16 + (uVar38 - 0x20))] =
             pcVar44[(int)(puVar16 + (uVar38 - 0x20))] | bVar46;
        *pcVar44 = *pcVar44 + bVar18;
        pcVar44 = (char *)((uint)pcVar44 & 0xffffff00 | (uint)(byte)(bVar18 - 0x30));
      }
      uVar48 = (uint)pcVar44 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
      bVar59 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar37 = (uint)bVar59;
      puVar16 = puVar16 + *(int *)(uVar48 + 4) + (uVar38 - 0x20);
      cVar19 = (char)puVar16 + bVar59;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar48 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      if (!in_PF) {
        puVar16[uVar37] = puVar16[uVar37] | bVar51;
        puVar16[(int)pbVar41 * 8 + uVar37] = puVar16[(int)pbVar41 * 8 + uVar37] + cVar19;
      }
      uVar37 = (uint)(puVar16 + uVar37) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar16 + uVar37) >> 8) + puVar16[uVar37 + 2],cVar19);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar38 = (uint)((uVar38 & 1) != 0);
      iVar24 = ((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8)) + *(int *)(uVar37 + 4)
      ;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      uVar22 = (ushort)puVar23 & 0xff00 | (ushort)bVar18;
      iVar42 = (int)(short)uVar22;
      if (!in_PF) {
        pbVar1 = (byte *)(iVar24 + uVar38 + iVar42);
        *pbVar1 = *pbVar1 | bVar18;
        pcVar44 = (char *)(iVar42 + (int)pbVar41 * 8);
        *pcVar44 = *pcVar44 + bVar18;
      }
      iVar43 = CONCAT22((short)uVar22 >> 0xf,
                        CONCAT11((char)((uint)iVar42 >> 8) + *(char *)(iVar42 + 2),bVar18));
      uVar37 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(iVar43 + 4);
      uVar48 = (uint)((uVar37 & 1) != 0);
      uVar37 = *puVar23;
      iVar42 = iVar24 + uVar38 + *puVar23;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(iVar43 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar20 = (byte)puVar23;
      bVar18 = bVar20 + 8;
      pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
      *(uint *)(iVar42 + uVar48 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar20,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar18 < 0) * 0x80 |
           (uint)(bVar18 == 0) * 0x40 |
           (uint)(((iVar24 + uVar38 & 0xfffffff) + (uVar37 & 0xfffffff) + uVar48 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar20) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if (!in_PF) {
        pcVar44[4] = pcVar44[4] | (byte)pbVar41;
        *pcVar44 = *pcVar44 + bVar18;
        pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)(bVar20 - 0x28));
      }
      uVar37 = (uint)pcVar44 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar24 = *(int *)(uVar37 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = DAT_5c08077a;
      uVar37 = (uint)puVar23 & 0xffffff00 | (uint)DAT_5c08077a;
      pcVar44 = (char *)(uVar37 + (int)pbVar41 * 8);
      *pcVar44 = *pcVar44 + DAT_5c08077a;
      uVar40 = (uint)puVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar23 >> 8) + *(char *)(uVar37 + 2),bVar18);
      uVar37 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar43 = *(int *)(uVar40 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar40 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)bVar18);
      _DAT_03ffffc4 = unaff_EDI + 2;
      *puVar15 = *unaff_ESI;
      if (!in_PF) {
        pcVar44[4] = pcVar44[4] | bVar46;
        *pcVar44 = *pcVar44 + bVar18;
        pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 - 0x28));
      }
      uVar25 = (uint)pcVar44 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar44 >> 8) + pcVar44[2],(char)pcVar44);
      uVar40 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar40 = (uint)((uVar40 & 1) != 0);
      iVar24 = iVar42 + uVar48 + -4 + iVar24 + (uint)((uVar38 & 1) != 0) + iVar43 +
               (uint)((uVar37 & 1) != 0) + *(int *)(uVar25 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar25 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      uVar38 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
      pbVar1 = (byte *)(iVar24 + uVar40 + 2 + uVar38);
      *pbVar1 = *pbVar1 | (byte)((uint)pbVar41 >> 8);
      pcVar44 = (char *)(uVar38 + (int)pbVar41 * 8);
      *pcVar44 = *pcVar44 + bVar18;
      uVar37 = (uint)puVar23 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + *(char *)(uVar38 + 2),
                              bVar18);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar38 = (uint)((uVar38 & 1) != 0);
      iVar24 = iVar24 + uVar40 + 2 + *(int *)(uVar37 + 4);
      puVar57 = (undefined *)(iVar24 + uVar38);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      _DAT_03ffffc8 = unaff_ESI + 2;
      uVar37 = (uint)puVar23 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (in_PF) {
        uVar48 = (uint)puVar23 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar23 >> 8) + *(char *)(uVar37 + 2),unaff_ESI[1]);
        uVar37 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar57 = (undefined *)(iVar24 + uVar38 + *(int *)(uVar48 + 4) + (uint)((uVar37 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar23 = (uint *)(uVar48 + 2);
        *puVar23 = *puVar23 | (uint)puVar23;
        uVar37 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
      }
      *(byte *)(uVar37 + 0x4000004) = *(byte *)(uVar37 + 0x4000004) | (byte)uVar37;
      *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
      *(uint *)(puVar57 + -4) = uVar37;
      *(int *)(puVar57 + -8) = in_ECX;
      *(byte **)(puVar57 + -0xc) = pbVar41;
      *(uint **)(puVar57 + -0x10) = unaff_EBX;
      *(undefined **)(puVar57 + -0x14) = puVar57;
      *(undefined4 **)(puVar57 + -0x18) = unaff_EBP;
      *(undefined **)(puVar57 + -0x1c) = _DAT_03ffffc8;
      *(undefined **)(puVar57 + -0x20) = _DAT_03ffffc4;
      uVar38 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((byte)pbVar41 + bVar21);
      iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
      *(int *)(puVar57 + -0x24) = iVar24;
      *(int *)(puVar57 + -0x28) = in_ECX;
      *(uint *)(puVar57 + -0x2c) = uVar38;
      *(uint **)(puVar57 + -0x30) = unaff_EBX;
      *(undefined **)(puVar57 + -0x34) = puVar57 + -0x20;
      *(undefined4 **)(puVar57 + -0x38) = unaff_EBP;
      *(undefined **)(puVar57 + -0x3c) = _DAT_03ffffc8;
      *(undefined **)(puVar57 + -0x40) = _DAT_03ffffc4;
      pbVar41 = (byte *)(uVar38 + in_ECX);
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      pcVar44[in_ECX] = pcVar44[in_ECX] & (byte)pcVar44;
      iVar24 = CONCAT31((int3)((uint)pcVar44 >> 8),0x7a);
      puVar57[iVar24 + -0x2ffc003e] = puVar57[iVar24 + -0x2ffc003e] | bVar21;
      uVar37 = (uint)pcVar44 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar44 >> 8) + *(char *)(iVar24 + 2),0x7a);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar38 = (uint)((uVar38 & 1) != 0);
      puVar15 = puVar57 + *(int *)(uVar37 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      uVar37 = (uint)puVar23 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar23 + '\b');
      *(byte *)(uVar37 + 0x4000004) = *(byte *)(uVar37 + 0x4000004) | bVar50;
      *pbVar41 = *pbVar41 << 1 | (char)*pbVar41 < 0;
      *(uint *)(puVar15 + uVar38) = uVar37;
      *(int *)(puVar15 + (uVar38 - 4)) = in_ECX;
      *(byte **)(puVar15 + (uVar38 - 8)) = pbVar41;
      *(uint **)(puVar15 + (uVar38 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar15 + (uVar38 - 0x10)) = puVar15 + uVar38 + 4;
      *(undefined4 **)(puVar15 + (int)(&DAT_ffffffec + uVar38)) = unaff_EBP;
      *(undefined **)(puVar15 + (uVar38 - 0x18)) = _DAT_03ffffc8;
      *(undefined **)(puVar15 + (uVar38 - 0x1c)) = _DAT_03ffffc4;
      uVar48 = (uint)pbVar41 & 0xffffff00 | (uint)(byte)((char)pbVar41 + bVar21);
      iVar24 = uVar37 - *(int *)(uVar37 + 0x13);
      *(int *)(puVar15 + (uVar38 - 0x20)) = iVar24;
      *(int *)(puVar15 + (uVar38 - 0x24)) = in_ECX;
      *(uint *)(puVar15 + (uVar38 - 0x28)) = uVar48;
      *(uint **)(puVar15 + (uVar38 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar15 + (uVar38 - 0x30)) = puVar15 + (uVar38 - 0x1c);
      *(undefined4 **)(puVar15 + (uVar38 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar15 + (uVar38 - 0x38)) = _DAT_03ffffc8;
      *(undefined **)(puVar15 + (uVar38 - 0x3c)) = _DAT_03ffffc4;
      _DAT_03fffff8 = (byte *)(uVar48 + in_ECX);
      pcVar44 = (char *)(iVar24 - *(int *)(iVar24 + 9));
      *pcVar44 = *pcVar44 + bVar51;
      pcVar44[in_ECX] = pcVar44[in_ECX] & (byte)pcVar44;
      pcVar44 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
      *pcVar44 = *pcVar44 + 'z';
      cVar19 = DAT_a408077c + '\a';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar19,0x7a)) + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      uVar38 = (uint)puVar23 & 0xffffff00 | (uint)bVar18;
      pcVar44 = (char *)(uVar38 + (int)_DAT_03fffff8 * 8);
      *pcVar44 = *pcVar44 + bVar18;
      cVar19 = *(char *)(uVar38 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(((uint)puVar23 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar23 & 0xffffff00) >> 8) + cVar19,bVar18))
                        + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      _DAT_04000000 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8);
      _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
      *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
      _DAT_03fffff0 = 0x4000004;
      _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar21);
      _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
      _DAT_03ffffd0 = &DAT_03ffffe4;
      iVar24 = _DAT_03ffffd8 + in_ECX;
      pcVar45 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
      _DAT_03ffffcc = unaff_EBP;
      _DAT_03ffffd4 = unaff_EBX;
      _DAT_03ffffdc = in_ECX;
      _DAT_03ffffe4 = _DAT_03ffffc4;
      _DAT_03ffffe8 = _DAT_03ffffc8;
      _DAT_03ffffec = unaff_EBP;
      _DAT_03fffff4 = unaff_EBX;
      _DAT_03fffffc = in_ECX;
      *pcVar45 = *pcVar45 + bVar51;
      pcVar45[in_ECX] = pcVar45[in_ECX] & (byte)pcVar45;
      bVar21 = (byte)pcVar45 | bVar21;
      uVar38 = (uint)pcVar45 & 0xffffff00 | (uint)bVar21;
      pcVar44 = (char *)(uVar38 + iVar24 * 8);
      *pcVar44 = *pcVar44 + bVar21;
      uVar37 = (uint)pcVar45 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar45 & 0xffffff00) >> 8) + *(char *)(uVar38 + 2),
                              bVar21);
      uVar38 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar38 = (uint)((uVar38 & 1) != 0);
      iVar24 = *(int *)(uVar37 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(uVar37 + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      bVar18 = (char)puVar23 + 8;
      puVar58 = (undefined4 *)(iVar24 + uVar38 + 0x3ffffc0);
      *(undefined4 **)(iVar24 + uVar38 + 0x3ffffc0) = unaff_EBP;
      cVar19 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar58 = puVar58 + -1;
        *puVar58 = *unaff_EBP;
        cVar19 = cVar19 + -1;
      } while (0 < cVar19);
      *(uint *)(iVar24 + uVar38 + 0x3ffffa0) = iVar24 + uVar38 + 0x3ffffc0;
      uVar37 = (uint)CONCAT11(bVar18 / 4,bVar18) & 0xffffff00;
      uVar38 = (uint)puVar23 & 0xffff0000 | uVar37;
      pcVar44 = (char *)(uVar38 | (uint)bVar18 & 0xffffff04);
      cVar19 = (char)((uint)bVar18 & 0xffffff04);
      *pcVar44 = *pcVar44 + cVar19;
      bVar18 = cVar19 - 0x30;
      cVar19 = *(char *)((uVar38 | (uint)bVar18) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar23 = (uint *)(((uint)puVar23 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar37 >> 8) + cVar19,bVar18)) + 2);
      *puVar23 = *puVar23 | (uint)puVar23;
      pcVar17 = (code *)swi(3);
      iVar24 = (*pcVar17)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
      return iVar24;
    }
    piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(byte)(bVar18 | (byte)(uVar48 >> 8)));
    uVar37 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar37 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar37;
    uVar40 = uVar37 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar37 >> 8) + *(char *)(uVar37 + 2),(char)uVar37);
    uVar37 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar24 = *(int *)(uVar40 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar40 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    piVar39 = (int *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
    uVar40 = (int)piVar39 + *piVar39;
    pcVar44 = (char *)(uVar40 + uVar48 * 8);
    *pcVar44 = *pcVar44 + (char)uVar40;
    uVar25 = uVar40 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar40 >> 8) + *(char *)(uVar40 + 2),(char)uVar40);
    uVar40 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar55 = puVar16 + (uint)((uVar40 & 1) != 0) +
                        *(int *)(uVar25 + 4) + (uint)((uVar37 & 1) != 0) + iVar24 + uVar38 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar23 = (uint *)(uVar25 + 2);
    *puVar23 = *puVar23 | (uint)puVar23;
    pbVar41 = (byte *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
  }
  *pbVar41 = *pbVar41 | bVar21;
  pbVar41[uVar48 * 8] = pbVar41[uVar48 * 8] + (char)pbVar41;
  uVar37 = (uint)pbVar41 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar41 >> 8) + pbVar41[2],(char)pbVar41);
  uVar38 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar56 = puVar55 + (uint)((uVar38 & 1) != 0) + *(int *)(uVar37 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(uVar37 + 2);
  *puVar23 = *puVar23 | (uint)puVar23;
  pcVar44 = (char *)((uint)puVar23 & 0xffffff00 | (uint)(byte)((char)puVar23 + 8));
code_r0x080429ec:
  *(byte *)(uVar48 + 7) = bVar51;
  puVar56[(int)pcVar44] = puVar56[(int)pcVar44] | (byte)uVar48;
  *pcVar44 = *pcVar44 + (char)pcVar44;
  bVar18 = (char)pcVar44 - 0x30;
  cVar19 = *(char *)(((uint)pcVar44 & 0xffffff00 | (uint)bVar18) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar23 = (uint *)(((uint)pcVar44 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar44 & 0xffffff00) >> 8) + cVar19,bVar18)) + 2)
  ;
  *puVar23 = *puVar23 | (uint)puVar23;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_kill(pthread_t __threadid,int __signo)

{
  byte *pbVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined *puVar8;
  undefined *puVar9;
  code *pcVar10;
  byte bVar11;
  byte bVar12;
  byte bVar13;
  byte bVar14;
  ushort uVar15;
  uint *puVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  uint uVar24;
  int iVar25;
  uint uVar26;
  int *piVar27;
  byte *pbVar28;
  int iVar29;
  int iVar30;
  char *pcVar31;
  char cVar33;
  char *pcVar32;
  byte bVar34;
  int in_ECX;
  uint uVar35;
  byte bVar36;
  uint *unaff_EBX;
  int iVar37;
  undefined *puVar38;
  undefined *puVar39;
  undefined *puVar40;
  undefined *puVar41;
  undefined *puVar42;
  undefined4 *puVar43;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar44;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack4 [4];
  
  bVar11 = (char)__threadid - 0x30;
  uVar17 = __threadid & 0xffff0000 |
           (uint)CONCAT11((char)((__threadid & 0xffffff00) >> 8) +
                          *(char *)((__threadid & 0xffffff00 | (uint)bVar11) + 2),bVar11);
  uVar26 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar25 = *(int *)(uVar17 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar17 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  piVar27 = (int *)(((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8)) ^ 0x7a);
  bVar36 = (byte)unaff_EBX;
  *(byte *)piVar27 = *(byte *)piVar27 | bVar36;
  uVar17 = (int)piVar27 + *piVar27;
  pcVar31 = (char *)(uVar17 + __signo * 8);
  *pcVar31 = *pcVar31 + (char)uVar17;
  uVar35 = uVar17 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar17 >> 8) + *(char *)(uVar17 + 2),(char)uVar17);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar29 = *(int *)(uVar35 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar35 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  bVar11 = (char)puVar16 + 8;
  uVar35 = (uint)puVar16 & 0xffffff00;
  pcVar31 = (char *)(uVar35 | (uint)bVar11);
  bVar12 = (byte)(uVar35 >> 8);
  *(byte *)((int)unaff_EBX + (int)pcVar31) = *(byte *)((int)unaff_EBX + (int)pcVar31) | bVar12;
  *pcVar31 = *pcVar31 + bVar11;
  bVar11 = (char)puVar16 - 0x28;
  uVar18 = (uint)puVar16 & 0xffff0000 |
           (uint)CONCAT11(bVar12 + *(char *)((uVar35 | (uint)bVar11) + 2),bVar11);
  uVar35 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar30 = *(int *)(uVar18 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar18 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  piVar27 = (int *)((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8));
  *(byte *)piVar27 = *(byte *)piVar27 | (byte)((uint)__signo >> 8);
  uVar18 = (int)piVar27 + *piVar27;
  pcVar31 = (char *)(uVar18 + __signo * 8);
  *pcVar31 = *pcVar31 + (char)uVar18;
  uVar19 = uVar18 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar18 >> 8) + *(char *)(uVar18 + 2),(char)uVar18);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar19 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar19 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  pcVar31 = (char *)(((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8)) + 1);
  bVar11 = (byte)((uint)unaff_EBX >> 8);
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + (int)pcVar31) = *(byte *)((int)unaff_EBX + (int)pcVar31) | bVar11;
    *pcVar31 = *pcVar31 + (char)pcVar31;
    pcVar31 = (char *)((uint)pcVar31 & 0xffffff00 | (uint)(byte)((char)pcVar31 - 0x30));
  }
  uVar20 = (uint)pcVar31 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar31 >> 8) + pcVar31[2],(char)pcVar31);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar4 = *(int *)(uVar20 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar20 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  bVar12 = (char)puVar16 + 8;
  pcVar31 = (char *)((uint)puVar16 & 0xffffff00 | (uint)bVar12);
  bVar14 = (byte)in_ECX;
  if (!in_PF) {
    pcVar31[3] = pcVar31[3] | bVar14;
    *pcVar31 = *pcVar31 + bVar12;
    pcVar31 = (char *)((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 - 0x28));
  }
  uVar21 = (uint)pcVar31 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar31 >> 8) + pcVar31[2],(char)pcVar31);
  uVar20 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar5 = *(int *)(uVar21 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar21 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  uVar21 = (uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8);
  uVar22 = uVar21 - 1;
  bVar12 = (byte)__signo;
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar22) = *(byte *)((int)unaff_EBX + uVar22) | bVar12;
    pcVar31 = (char *)(uVar22 + __signo * 8);
    *pcVar31 = *pcVar31 + (char)uVar22;
  }
  uVar22 = uVar22 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar22 >> 8) + *(char *)(uVar21 + 1),(char)uVar22);
  uVar21 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar6 = *(int *)(uVar22 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar22 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  bVar13 = (char)puVar16 + 8;
  uVar22 = (uint)puVar16 & 0xffffff00;
  pcVar31 = (char *)(uVar22 | (uint)bVar13);
  if (!in_PF) {
    pcVar31[3] = pcVar31[3] | (byte)(uVar22 >> 8);
    *pcVar31 = *pcVar31 + bVar13;
    pcVar31 = (char *)(uVar22 | (uint)(byte)((char)puVar16 - 0x28));
  }
  uVar23 = (uint)pcVar31 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar31 >> 8) + pcVar31[2],(char)pcVar31);
  uVar22 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar22 = (uint)((uVar22 & 1) != 0);
  iVar7 = *(int *)(uVar23 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar23 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  bVar13 = (char)puVar16 + 8;
  uVar23 = (uint)puVar16 & 0xffffff00 | (uint)bVar13;
  *(uint *)(&stack0x00000000 +
            iVar7 + (uint)((uVar21 & 1) != 0) +
                    iVar6 + (uint)((uVar20 & 1) != 0) +
                            iVar5 + (uint)((uVar19 & 1) != 0) +
                                    iVar4 + (uint)((uVar18 & 1) != 0) +
                                            iVar3 + (uint)((uVar35 & 1) != 0) +
                                                    iVar30 + (uint)((uVar17 & 1) != 0) +
                                                             iVar29 + (uint)((uVar26 & 1) != 0) +
                                                                      iVar25 + uVar22) = uVar23;
  bVar34 = (byte)((uint)in_ECX >> 8);
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar23) = *(byte *)((int)unaff_EBX + uVar23) | bVar34;
    pcVar31 = (char *)(uVar23 + __signo * 8);
    *pcVar31 = *pcVar31 + bVar13;
  }
  uVar24 = (uint)puVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar16 & 0xffffff00) >> 8) + *(char *)(uVar23 + 2),bVar13);
  uVar23 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar23 = (uint)((uVar23 & 1) != 0);
  puVar8 = &stack0x00000000 +
           iVar7 + (uint)((uVar21 & 1) != 0) +
                   iVar6 + (uint)((uVar20 & 1) != 0) +
                           iVar5 + (uint)((uVar19 & 1) != 0) +
                                   iVar4 + (uint)((uVar18 & 1) != 0) +
                                           iVar3 + (uint)((uVar35 & 1) != 0) +
                                                   iVar30 + (uint)((uVar17 & 1) != 0) +
                                                            iVar29 + (uint)((uVar26 & 1) != 0) +
                                                                     iVar25 +
           *(int *)(uVar24 + 4) + uVar22;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar24 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  bVar13 = (char)puVar16 + 8;
  pcVar31 = (char *)((uint)puVar16 & 0xffffff00 | (uint)bVar13);
  *(undefined **)(puVar8 + (uVar23 - 4)) = puVar8 + uVar23;
  if (!in_PF) {
    pcVar31[3] = pcVar31[3] | bVar11;
    *pcVar31 = *pcVar31 + bVar13;
    pcVar31 = (char *)((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 - 0x28));
  }
  uVar17 = (uint)pcVar31 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar31 >> 8) + pcVar31[2],(char)pcVar31);
  uVar26 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar26 = (uint)((uVar26 & 1) != 0);
  iVar25 = *(int *)(uVar17 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar17 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  uVar17 = *(uint *)(puVar8 + iVar25 + (uVar23 - 4) + uVar26);
  if (!in_PF) {
    pbVar28 = (byte *)((int)unaff_EBX + uVar17 + 0xd0040000);
    *pbVar28 = *pbVar28 | (byte)uVar17;
  }
  uVar35 = uVar17 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar17 >> 8) + *(char *)(uVar17 + 2),(byte)uVar17);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar29 = *(int *)(uVar35 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar35 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  bVar13 = (char)puVar16 + 8;
  uVar35 = (uint)puVar16 & 0xffffff00 | (uint)bVar13;
  iVar37 = *(int *)(puVar8 + iVar25 + (uVar23 - 4) + (uint)((uVar17 & 1) != 0) + iVar29 + uVar26 + 4
                   );
  puVar38 = (undefined *)(iVar37 + 4);
  if (in_PF) {
    uVar17 = (uint)puVar16 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar16 & 0xffffff00) >> 8) + *(char *)(uVar35 + 2),bVar13
                           );
    uVar26 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar38 = (undefined *)(iVar37 + 4 + *(int *)(uVar17 + 4) + (uint)((uVar26 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = (uint *)(uVar17 + 2);
    *puVar16 = *puVar16 | (uint)puVar16;
    uVar35 = (uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8);
  }
  *(byte *)(uVar35 + 0x4000003) = *(byte *)(uVar35 + 0x4000003) | bVar12;
  *(char *)__signo = *(char *)__signo << 1 | *(char *)__signo < 0;
  *(uint *)(puVar38 + -4) = uVar35;
  *(int *)(puVar38 + -8) = in_ECX;
  *(int *)(puVar38 + -0xc) = __signo;
  *(uint **)(puVar38 + -0x10) = unaff_EBX;
  *(undefined **)(puVar38 + -0x14) = puVar38;
  *(undefined4 **)(puVar38 + -0x18) = unaff_EBP;
  *(undefined **)(puVar38 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar38 + -0x20) = unaff_EDI;
  uVar26 = __signo & 0xffffff00U | (uint)(byte)(bVar12 + bVar14);
  iVar25 = uVar35 - *(int *)(uVar35 + 0x13);
  *(int *)(puVar38 + -0x24) = iVar25;
  *(int *)(puVar38 + -0x28) = in_ECX;
  *(uint *)(puVar38 + -0x2c) = uVar26;
  *(uint **)(puVar38 + -0x30) = unaff_EBX;
  *(undefined **)(puVar38 + -0x34) = puVar38 + -0x20;
  *(undefined4 **)(puVar38 + -0x38) = unaff_EBP;
  *(undefined **)(puVar38 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar38 + -0x40) = unaff_EDI;
  pbVar28 = (byte *)(uVar26 + in_ECX);
  pcVar31 = (char *)(iVar25 - *(int *)(iVar25 + 9));
  *pcVar31 = *pcVar31 + bVar11;
  pcVar31[in_ECX] = pcVar31[in_ECX] & (byte)pcVar31;
  *(char **)(puVar38 + -0x44) = pcVar31;
  *(int *)(puVar38 + -0x48) = in_ECX;
  *(byte **)(puVar38 + -0x4c) = pbVar28;
  *(uint **)(puVar38 + -0x50) = unaff_EBX;
  *(undefined **)(puVar38 + -0x54) = puVar38 + -0x40;
  *(undefined4 **)(puVar38 + -0x58) = unaff_EBP;
  *(undefined **)(puVar38 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar38 + -0x60) = unaff_EDI;
  if (!in_PF) {
    pbVar1 = (byte *)((int)((int)unaff_EBX + -0x2ffc0000) + (int)pcVar31);
    *pbVar1 = *pbVar1 | bVar36;
  }
  uVar17 = (uint)pcVar31 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar31 >> 8) + pcVar31[2],(byte)pcVar31);
  uVar26 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar26 = (uint)((uVar26 & 1) != 0);
  iVar25 = *(int *)(uVar17 + 4);
  puVar39 = puVar38 + iVar25 + -0x60 + uVar26;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar17 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  bVar12 = (char)puVar16 + 8;
  uVar17 = (uint)puVar16 & 0xffffff00 | (uint)bVar12;
  if (in_PF) {
    uVar35 = (uint)puVar16 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar16 & 0xffffff00) >> 8) + *(char *)(uVar17 + 2),bVar12
                           );
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar39 = puVar38 + iVar25 + -0x60 + (uint)((uVar17 & 1) != 0) + *(int *)(uVar35 + 4) + uVar26;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = (uint *)(uVar35 + 2);
    *puVar16 = *puVar16 | (uint)puVar16;
    uVar17 = (uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8);
  }
  *(byte *)(uVar17 + 0x4000003) = *(byte *)(uVar17 + 0x4000003) | bVar34;
  *pbVar28 = *pbVar28 << 1 | (char)*pbVar28 < 0;
  *(uint *)(puVar39 + -4) = uVar17;
  *(int *)(puVar39 + -8) = in_ECX;
  *(byte **)(puVar39 + -0xc) = pbVar28;
  *(uint **)(puVar39 + -0x10) = unaff_EBX;
  *(undefined **)(puVar39 + -0x14) = puVar39;
  *(undefined4 **)(puVar39 + -0x18) = unaff_EBP;
  *(undefined **)(puVar39 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar39 + -0x20) = unaff_EDI;
  uVar35 = (uint)pbVar28 & 0xffffff00 | (uint)(byte)((char)pbVar28 + bVar14);
  iVar25 = uVar17 - *(int *)(uVar17 + 0x13);
  *(int *)(puVar39 + -0x24) = iVar25;
  *(int *)(puVar39 + -0x28) = in_ECX;
  *(uint *)(puVar39 + -0x2c) = uVar35;
  *(uint **)(puVar39 + -0x30) = unaff_EBX;
  *(undefined **)(puVar39 + -0x34) = puVar39 + -0x20;
  *(undefined4 **)(puVar39 + -0x38) = unaff_EBP;
  *(undefined **)(puVar39 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar39 + -0x40) = unaff_EDI;
  uVar35 = uVar35 + in_ECX;
  piVar27 = (int *)(iVar25 - *(int *)(iVar25 + 9));
  *(byte *)piVar27 = *(char *)piVar27 + bVar11;
  *(byte *)((int)piVar27 + in_ECX) = *(byte *)((int)piVar27 + in_ECX) & (byte)piVar27;
  *(undefined4 *)(puVar39 + -0x44) = 0xb408077a;
  uVar26 = (int)piVar27 + *piVar27;
  pcVar31 = (char *)(uVar26 + uVar35 * 8);
  *pcVar31 = *pcVar31 + (char)uVar26;
  uVar17 = uVar26 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar26 >> 8) + *(char *)(uVar26 + 2),(char)uVar26);
  uVar26 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar25 = *(int *)(uVar17 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar17 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  piVar27 = (int *)((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8));
  puVar8 = unaff_EDI + 1;
  uVar2 = in((short)uVar35);
  *unaff_EDI = uVar2;
  if (!in_PF) {
    piVar27 = (int *)((int)piVar27 + *piVar27);
    *(char *)(piVar27 + uVar35 * 2) = *(char *)(piVar27 + uVar35 * 2) + (char)piVar27;
  }
  uVar18 = (uint)piVar27 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)piVar27 >> 8) + *(char *)((int)piVar27 + 2),(char)piVar27);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  puVar9 = puVar39 + *(int *)(uVar18 + 4) + (uint)((uVar26 & 1) != 0) + iVar25 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar18 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  bVar12 = (char)puVar16 + 8;
  uVar26 = (uint)puVar16 & 0xffffff00 | (uint)bVar12;
  cVar33 = (char)uVar35;
  if (SCARRY1((char)puVar16,'\b')) {
    uVar35 = uVar35 & 0xffffff00 | (uint)(byte)(cVar33 + bVar14);
    iVar25 = uVar26 - *(int *)(uVar26 + 0x13);
    *(int *)(puVar9 + (uVar17 - 4)) = iVar25;
    *(int *)(puVar9 + (uVar17 - 8)) = in_ECX;
    *(uint *)(puVar9 + (uVar17 - 0xc)) = uVar35;
    *(uint **)(puVar9 + (uVar17 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar9 + (int)(&DAT_ffffffec + uVar17)) = puVar9 + uVar17;
    *(undefined4 **)(puVar9 + (uVar17 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar9 + (uVar17 - 0x1c)) = unaff_ESI;
    puVar40 = puVar9 + (uVar17 - 0x20);
    *(undefined **)(puVar9 + (uVar17 - 0x20)) = puVar8;
    uVar35 = uVar35 + in_ECX;
    pbVar28 = (byte *)(iVar25 - *(int *)(iVar25 + 9));
    *pbVar28 = *pbVar28 + bVar11;
    pbVar28[in_ECX] = pbVar28[in_ECX] & (byte)pbVar28;
  }
  else {
    piVar27 = (int *)((uint)puVar16 & 0xffff0000 |
                     (uint)CONCAT11((byte)(((uint)puVar16 & 0xffffff00) >> 8) | bVar14,bVar12));
    uVar26 = (int)piVar27 + *piVar27;
    pcVar31 = (char *)(uVar26 + uVar35 * 8);
    *pcVar31 = *pcVar31 + (char)uVar26;
    uVar18 = uVar26 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar26 >> 8) + *(char *)(uVar26 + 2),(char)uVar26);
    uVar26 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar26 = (uint)((uVar26 & 1) != 0);
    puVar9 = puVar9 + *(int *)(uVar18 + 4) + uVar17 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = (uint *)(uVar18 + 2);
    *puVar16 = *puVar16 | (uint)puVar16;
    bVar12 = (char)puVar16 + 8;
    uVar17 = (uint)puVar16 & 0xffffff00 | (uint)bVar12;
    if (bVar12 == 0) {
      uVar35 = uVar35 & 0xffffff00 | (uint)(byte)(cVar33 + bVar14);
      iVar25 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar9 + (uVar26 - 4)) = iVar25;
      *(int *)(puVar9 + (uVar26 - 8)) = in_ECX;
      *(uint *)(puVar9 + (uVar26 - 0xc)) = uVar35;
      *(uint **)(puVar9 + (uVar26 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar9 + (int)(&DAT_ffffffec + uVar26)) = puVar9 + uVar26;
      *(undefined4 **)(puVar9 + (uVar26 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar9 + (uVar26 - 0x1c)) = unaff_ESI;
      puVar41 = puVar9 + (uVar26 - 0x20);
      *(undefined **)(puVar9 + (uVar26 - 0x20)) = puVar8;
      uVar35 = uVar35 + in_ECX;
      pcVar31 = (char *)(iVar25 - *(int *)(iVar25 + 9));
      *pcVar31 = *pcVar31 + bVar11;
      pcVar31[in_ECX] = pcVar31[in_ECX] & (byte)pcVar31;
      goto code_r0x080429ec;
    }
    piVar27 = (int *)((uint)puVar16 & 0xffffff00 | (uint)(bVar12 | bVar36));
    uVar17 = (int)piVar27 + *piVar27;
    pcVar31 = (char *)(uVar17 + uVar35 * 8);
    *pcVar31 = *pcVar31 + (char)uVar17;
    uVar18 = uVar17 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar17 >> 8) + *(char *)(uVar17 + 2),(char)uVar17);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar17 = (uint)((uVar17 & 1) != 0);
    puVar9 = puVar9 + *(int *)(uVar18 + 4) + uVar26 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = (uint *)(uVar18 + 2);
    *puVar16 = *puVar16 | (uint)puVar16;
    bVar12 = (char)puVar16 + 8;
    uVar26 = (uint)puVar16 & 0xffffff00 | (uint)bVar12;
    if ((char)bVar12 < 0) {
      iVar25 = uVar26 - *(int *)(uVar26 + 0x13);
      *(int *)(puVar9 + (uVar17 - 4)) = iVar25;
      *(int *)(puVar9 + (uVar17 - 8)) = in_ECX;
      *(uint *)(puVar9 + (uVar17 - 0xc)) = uVar35 & 0xffffff00 | (uint)(byte)(cVar33 + bVar14);
      *(uint **)(puVar9 + (uVar17 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar9 + (uVar17 - 0x14)) = puVar9 + uVar17;
      *(undefined4 **)(puVar9 + (uVar17 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar9 + (uVar17 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar9 + (uVar17 - 0x20)) = puVar8;
      pcVar31 = (char *)(iVar25 - *(int *)(iVar25 + 9));
      *pcVar31 = *pcVar31 + bVar11;
      pcVar31[in_ECX] = pcVar31[in_ECX] & (byte)pcVar31;
      return;
    }
    piVar27 = (int *)((uint)puVar16 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar16 & 0xffffff00) >> 8),bVar12));
    uVar26 = (int)piVar27 + *piVar27;
    pcVar31 = (char *)(uVar26 + uVar35 * 8);
    *pcVar31 = *pcVar31 + (char)uVar26;
    uVar18 = uVar26 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar26 >> 8) + *(char *)(uVar26 + 2),(char)uVar26);
    uVar26 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar26 = (uint)((uVar26 & 1) != 0);
    puVar9 = puVar9 + *(int *)(uVar18 + 4) + uVar17 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = (uint *)(uVar18 + 2);
    *puVar16 = *puVar16 | (uint)puVar16;
    bVar12 = (char)puVar16 + 8;
    uVar17 = (uint)puVar16 & 0xffffff00 | (uint)bVar12;
    if (SCARRY1((char)puVar16,'\b') != (char)bVar12 < 0) {
      uVar35 = uVar35 & 0xffffff00 | (uint)(byte)(cVar33 + bVar14);
      iVar25 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar9 + (uVar26 - 4)) = iVar25;
      *(int *)(puVar9 + (uVar26 - 8)) = in_ECX;
      *(uint *)(puVar9 + (uVar26 - 0xc)) = uVar35;
      *(uint **)(puVar9 + (uVar26 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar9 + (uVar26 - 0x14)) = puVar9 + uVar26;
      *(undefined4 **)(puVar9 + (uVar26 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar9 + (uVar26 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar9 + (uVar26 - 0x20)) = puVar8;
      pbVar28 = (byte *)(uVar35 + in_ECX);
      pcVar31 = (char *)(iVar25 - *(int *)(iVar25 + 9));
      *pcVar31 = *pcVar31 + bVar11;
      bVar12 = (byte)pcVar31;
      pcVar31[in_ECX] = pcVar31[in_ECX] & bVar12;
      if (!in_PF) {
        pcVar31[(int)(puVar9 + (uVar26 - 0x20))] = pcVar31[(int)(puVar9 + (uVar26 - 0x20))] | bVar34
        ;
        *pcVar31 = *pcVar31 + bVar12;
        pcVar31 = (char *)((uint)pcVar31 & 0xffffff00 | (uint)(byte)(bVar12 - 0x30));
      }
      uVar35 = (uint)pcVar31 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar31 >> 8) + pcVar31[2],(char)pcVar31);
      bVar44 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)bVar44;
      puVar9 = puVar9 + *(int *)(uVar35 + 4) + (uVar26 - 0x20);
      cVar33 = (char)puVar9 + bVar44;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(uVar35 + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      if (!in_PF) {
        puVar9[uVar17] = puVar9[uVar17] | bVar11;
        puVar9[(int)pbVar28 * 8 + uVar17] = puVar9[(int)pbVar28 * 8 + uVar17] + cVar33;
      }
      uVar17 = (uint)(puVar9 + uVar17) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar9 + uVar17) >> 8) + puVar9[uVar17 + 2],cVar33);
      uVar26 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar26 = (uint)((uVar26 & 1) != 0);
      iVar25 = ((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8)) + *(int *)(uVar17 + 4)
      ;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(uVar17 + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      bVar12 = (char)puVar16 + 8;
      uVar15 = (ushort)puVar16 & 0xff00 | (ushort)bVar12;
      iVar29 = (int)(short)uVar15;
      if (!in_PF) {
        pbVar1 = (byte *)(iVar25 + uVar26 + iVar29);
        *pbVar1 = *pbVar1 | bVar12;
        pcVar31 = (char *)(iVar29 + (int)pbVar28 * 8);
        *pcVar31 = *pcVar31 + bVar12;
      }
      iVar30 = CONCAT22((short)uVar15 >> 0xf,
                        CONCAT11((char)((uint)iVar29 >> 8) + *(char *)(iVar29 + 2),bVar12));
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(iVar30 + 4);
      uVar35 = (uint)((uVar17 & 1) != 0);
      uVar17 = *puVar16;
      iVar29 = iVar25 + uVar26 + *puVar16;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(iVar30 + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      bVar12 = (byte)puVar16;
      bVar13 = bVar12 + 8;
      pcVar31 = (char *)((uint)puVar16 & 0xffffff00 | (uint)bVar13);
      *(uint *)(iVar29 + uVar35 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar12,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar13 < 0) * 0x80 |
           (uint)(bVar13 == 0) * 0x40 |
           (uint)(((iVar25 + uVar26 & 0xfffffff) + (uVar17 & 0xfffffff) + uVar35 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar12) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if (!in_PF) {
        pcVar31[4] = pcVar31[4] | (byte)pbVar28;
        *pcVar31 = *pcVar31 + bVar13;
        pcVar31 = (char *)((uint)puVar16 & 0xffffff00 | (uint)(byte)(bVar12 - 0x28));
      }
      uVar17 = (uint)pcVar31 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar31 >> 8) + pcVar31[2],(char)pcVar31);
      uVar26 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar25 = *(int *)(uVar17 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(uVar17 + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      bVar12 = DAT_5c08077a;
      uVar17 = (uint)puVar16 & 0xffffff00 | (uint)DAT_5c08077a;
      pcVar31 = (char *)(uVar17 + (int)pbVar28 * 8);
      *pcVar31 = *pcVar31 + DAT_5c08077a;
      uVar18 = (uint)puVar16 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar16 >> 8) + *(char *)(uVar17 + 2),bVar12);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar30 = *(int *)(uVar18 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(uVar18 + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      bVar12 = (char)puVar16 + 8;
      pcVar31 = (char *)((uint)puVar16 & 0xffffff00 | (uint)bVar12);
      _DAT_03ffffc4 = unaff_EDI + 2;
      *puVar8 = *unaff_ESI;
      if (!in_PF) {
        pcVar31[4] = pcVar31[4] | bVar34;
        *pcVar31 = *pcVar31 + bVar12;
        pcVar31 = (char *)((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 - 0x28));
      }
      uVar19 = (uint)pcVar31 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar31 >> 8) + pcVar31[2],(char)pcVar31);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      iVar25 = iVar29 + uVar35 + -4 + iVar25 + (uint)((uVar26 & 1) != 0) + iVar30 +
               (uint)((uVar17 & 1) != 0) + *(int *)(uVar19 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(uVar19 + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      bVar12 = (char)puVar16 + 8;
      uVar26 = (uint)puVar16 & 0xffffff00 | (uint)bVar12;
      pbVar1 = (byte *)(iVar25 + uVar18 + 2 + uVar26);
      *pbVar1 = *pbVar1 | (byte)((uint)pbVar28 >> 8);
      pcVar31 = (char *)(uVar26 + (int)pbVar28 * 8);
      *pcVar31 = *pcVar31 + bVar12;
      uVar17 = (uint)puVar16 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar16 & 0xffffff00) >> 8) + *(char *)(uVar26 + 2),
                              bVar12);
      uVar26 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar26 = (uint)((uVar26 & 1) != 0);
      iVar25 = iVar25 + uVar18 + 2 + *(int *)(uVar17 + 4);
      puVar42 = (undefined *)(iVar25 + uVar26);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(uVar17 + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      _DAT_03ffffc8 = unaff_ESI + 2;
      uVar17 = (uint)puVar16 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (in_PF) {
        uVar35 = (uint)puVar16 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar16 >> 8) + *(char *)(uVar17 + 2),unaff_ESI[1]);
        uVar17 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar42 = (undefined *)(iVar25 + uVar26 + *(int *)(uVar35 + 4) + (uint)((uVar17 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar16 = (uint *)(uVar35 + 2);
        *puVar16 = *puVar16 | (uint)puVar16;
        uVar17 = (uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8);
      }
      *(byte *)(uVar17 + 0x4000004) = *(byte *)(uVar17 + 0x4000004) | (byte)uVar17;
      *pbVar28 = *pbVar28 << 1 | (char)*pbVar28 < 0;
      *(uint *)(puVar42 + -4) = uVar17;
      *(int *)(puVar42 + -8) = in_ECX;
      *(byte **)(puVar42 + -0xc) = pbVar28;
      *(uint **)(puVar42 + -0x10) = unaff_EBX;
      *(undefined **)(puVar42 + -0x14) = puVar42;
      *(undefined4 **)(puVar42 + -0x18) = unaff_EBP;
      *(undefined **)(puVar42 + -0x1c) = _DAT_03ffffc8;
      *(undefined **)(puVar42 + -0x20) = _DAT_03ffffc4;
      uVar26 = (uint)pbVar28 & 0xffffff00 | (uint)(byte)((byte)pbVar28 + bVar14);
      iVar25 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar42 + -0x24) = iVar25;
      *(int *)(puVar42 + -0x28) = in_ECX;
      *(uint *)(puVar42 + -0x2c) = uVar26;
      *(uint **)(puVar42 + -0x30) = unaff_EBX;
      *(undefined **)(puVar42 + -0x34) = puVar42 + -0x20;
      *(undefined4 **)(puVar42 + -0x38) = unaff_EBP;
      *(undefined **)(puVar42 + -0x3c) = _DAT_03ffffc8;
      *(undefined **)(puVar42 + -0x40) = _DAT_03ffffc4;
      pbVar28 = (byte *)(uVar26 + in_ECX);
      pcVar31 = (char *)(iVar25 - *(int *)(iVar25 + 9));
      *pcVar31 = *pcVar31 + bVar11;
      pcVar31[in_ECX] = pcVar31[in_ECX] & (byte)pcVar31;
      iVar25 = CONCAT31((int3)((uint)pcVar31 >> 8),0x7a);
      puVar42[iVar25 + -0x2ffc003e] = puVar42[iVar25 + -0x2ffc003e] | bVar14;
      uVar17 = (uint)pcVar31 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar31 >> 8) + *(char *)(iVar25 + 2),0x7a);
      uVar26 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar26 = (uint)((uVar26 & 1) != 0);
      puVar8 = puVar42 + *(int *)(uVar17 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(uVar17 + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      uVar17 = (uint)puVar16 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar16 + '\b');
      *(byte *)(uVar17 + 0x4000004) = *(byte *)(uVar17 + 0x4000004) | bVar36;
      *pbVar28 = *pbVar28 << 1 | (char)*pbVar28 < 0;
      *(uint *)(puVar8 + uVar26) = uVar17;
      *(int *)(puVar8 + (uVar26 - 4)) = in_ECX;
      *(byte **)(puVar8 + (uVar26 - 8)) = pbVar28;
      *(uint **)(puVar8 + (uVar26 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar8 + (uVar26 - 0x10)) = puVar8 + uVar26 + 4;
      *(undefined4 **)(puVar8 + (int)(&DAT_ffffffec + uVar26)) = unaff_EBP;
      *(undefined **)(puVar8 + (uVar26 - 0x18)) = _DAT_03ffffc8;
      *(undefined **)(puVar8 + (uVar26 - 0x1c)) = _DAT_03ffffc4;
      uVar35 = (uint)pbVar28 & 0xffffff00 | (uint)(byte)((char)pbVar28 + bVar14);
      iVar25 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar8 + (uVar26 - 0x20)) = iVar25;
      *(int *)(puVar8 + (uVar26 - 0x24)) = in_ECX;
      *(uint *)(puVar8 + (uVar26 - 0x28)) = uVar35;
      *(uint **)(puVar8 + (uVar26 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar8 + (uVar26 - 0x30)) = puVar8 + (uVar26 - 0x1c);
      *(undefined4 **)(puVar8 + (uVar26 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar8 + (uVar26 - 0x38)) = _DAT_03ffffc8;
      *(undefined **)(puVar8 + (uVar26 - 0x3c)) = _DAT_03ffffc4;
      _DAT_03fffff8 = (byte *)(uVar35 + in_ECX);
      pcVar31 = (char *)(iVar25 - *(int *)(iVar25 + 9));
      *pcVar31 = *pcVar31 + bVar11;
      pcVar31[in_ECX] = pcVar31[in_ECX] & (byte)pcVar31;
      pcVar31 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
      *pcVar31 = *pcVar31 + 'z';
      cVar33 = DAT_a408077c + '\a';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar33,0x7a)) + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      bVar12 = (char)puVar16 + 8;
      uVar26 = (uint)puVar16 & 0xffffff00 | (uint)bVar12;
      pcVar31 = (char *)(uVar26 + (int)_DAT_03fffff8 * 8);
      *pcVar31 = *pcVar31 + bVar12;
      cVar33 = *(char *)(uVar26 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(((uint)puVar16 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar16 & 0xffffff00) >> 8) + cVar33,bVar12))
                        + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      _DAT_04000000 = (uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8);
      _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
      *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
      _DAT_03fffff0 = 0x4000004;
      _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar14);
      _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
      _DAT_03ffffd0 = &DAT_03ffffe4;
      iVar25 = _DAT_03ffffd8 + in_ECX;
      pcVar32 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
      _DAT_03ffffcc = unaff_EBP;
      _DAT_03ffffd4 = unaff_EBX;
      _DAT_03ffffdc = in_ECX;
      _DAT_03ffffe4 = _DAT_03ffffc4;
      _DAT_03ffffe8 = _DAT_03ffffc8;
      _DAT_03ffffec = unaff_EBP;
      _DAT_03fffff4 = unaff_EBX;
      _DAT_03fffffc = in_ECX;
      *pcVar32 = *pcVar32 + bVar11;
      pcVar32[in_ECX] = pcVar32[in_ECX] & (byte)pcVar32;
      bVar14 = (byte)pcVar32 | bVar14;
      uVar26 = (uint)pcVar32 & 0xffffff00 | (uint)bVar14;
      pcVar31 = (char *)(uVar26 + iVar25 * 8);
      *pcVar31 = *pcVar31 + bVar14;
      uVar17 = (uint)pcVar32 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar32 & 0xffffff00) >> 8) + *(char *)(uVar26 + 2),
                              bVar14);
      uVar26 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar26 = (uint)((uVar26 & 1) != 0);
      iVar25 = *(int *)(uVar17 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(uVar17 + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      bVar11 = (char)puVar16 + 8;
      puVar43 = (undefined4 *)(iVar25 + uVar26 + 0x3ffffc0);
      *(undefined4 **)(iVar25 + uVar26 + 0x3ffffc0) = unaff_EBP;
      cVar33 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar43 = puVar43 + -1;
        *puVar43 = *unaff_EBP;
        cVar33 = cVar33 + -1;
      } while (0 < cVar33);
      *(uint *)(iVar25 + uVar26 + 0x3ffffa0) = iVar25 + uVar26 + 0x3ffffc0;
      uVar17 = (uint)CONCAT11(bVar11 / 4,bVar11) & 0xffffff00;
      uVar26 = (uint)puVar16 & 0xffff0000 | uVar17;
      pcVar31 = (char *)(uVar26 | (uint)bVar11 & 0xffffff04);
      cVar33 = (char)((uint)bVar11 & 0xffffff04);
      *pcVar31 = *pcVar31 + cVar33;
      bVar11 = cVar33 - 0x30;
      cVar33 = *(char *)((uVar26 | (uint)bVar11) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar16 = (uint *)(((uint)puVar16 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar17 >> 8) + cVar33,bVar11)) + 2);
      *puVar16 = *puVar16 | (uint)puVar16;
      pcVar10 = (code *)swi(3);
      iVar25 = (*pcVar10)((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8));
      return iVar25;
    }
    piVar27 = (int *)((uint)puVar16 & 0xffffff00 | (uint)(byte)(bVar12 | (byte)(uVar35 >> 8)));
    uVar17 = (int)piVar27 + *piVar27;
    pcVar31 = (char *)(uVar17 + uVar35 * 8);
    *pcVar31 = *pcVar31 + (char)uVar17;
    uVar18 = uVar17 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar17 >> 8) + *(char *)(uVar17 + 2),(char)uVar17);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar25 = *(int *)(uVar18 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = (uint *)(uVar18 + 2);
    *puVar16 = *puVar16 | (uint)puVar16;
    piVar27 = (int *)((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8));
    uVar18 = (int)piVar27 + *piVar27;
    pcVar31 = (char *)(uVar18 + uVar35 * 8);
    *pcVar31 = *pcVar31 + (char)uVar18;
    uVar19 = uVar18 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar18 >> 8) + *(char *)(uVar18 + 2),(char)uVar18);
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar40 = puVar9 + (uint)((uVar18 & 1) != 0) +
                       *(int *)(uVar19 + 4) + (uint)((uVar17 & 1) != 0) + iVar25 + uVar26 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = (uint *)(uVar19 + 2);
    *puVar16 = *puVar16 | (uint)puVar16;
    pbVar28 = (byte *)((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8));
  }
  *pbVar28 = *pbVar28 | bVar14;
  pbVar28[uVar35 * 8] = pbVar28[uVar35 * 8] + (char)pbVar28;
  uVar17 = (uint)pbVar28 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar28 >> 8) + pbVar28[2],(char)pbVar28);
  uVar26 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar41 = puVar40 + (uint)((uVar26 & 1) != 0) + *(int *)(uVar17 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(uVar17 + 2);
  *puVar16 = *puVar16 | (uint)puVar16;
  pcVar31 = (char *)((uint)puVar16 & 0xffffff00 | (uint)(byte)((char)puVar16 + 8));
code_r0x080429ec:
  *(byte *)(uVar35 + 7) = bVar11;
  puVar41[(int)pcVar31] = puVar41[(int)pcVar31] | (byte)uVar35;
  *pcVar31 = *pcVar31 + (char)pcVar31;
  bVar11 = (char)pcVar31 - 0x30;
  cVar33 = *(char *)(((uint)pcVar31 & 0xffffff00 | (uint)bVar11) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar16 = (uint *)(((uint)pcVar31 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar31 & 0xffffff00) >> 8) + cVar33,bVar11)) + 2)
  ;
  *puVar16 = *puVar16 | (uint)puVar16;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_attr_setstacksize(pthread_attr_t *__attr,size_t __stacksize)

{
  byte *pbVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  undefined *puVar7;
  code *pcVar8;
  byte bVar9;
  byte bVar10;
  byte bVar11;
  byte bVar12;
  byte bVar13;
  ushort uVar14;
  uint *puVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  int iVar21;
  uint uVar22;
  int *piVar23;
  uint uVar24;
  byte *pbVar25;
  int iVar26;
  int iVar27;
  char *pcVar28;
  char cVar30;
  char *pcVar29;
  byte bVar31;
  int in_ECX;
  uint uVar32;
  uint *unaff_EBX;
  int iVar33;
  undefined *puVar34;
  undefined *puVar35;
  undefined *puVar36;
  undefined *puVar37;
  undefined *puVar38;
  undefined4 *puVar39;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar40;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack6 [4];
  undefined auStack2 [2];
  
  bVar9 = (char)__attr - 0x30;
  uVar16 = (uint)__attr & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__attr & 0xffffff00) >> 8) +
                          *(char *)(((uint)__attr & 0xffffff00 | (uint)bVar9) + 2),bVar9);
  uVar22 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar21 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar16 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  piVar23 = (int *)((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8));
  *(byte *)piVar23 = *(byte *)piVar23 | (byte)(__stacksize >> 8);
  uVar16 = (int)piVar23 + *piVar23;
  pcVar28 = (char *)(uVar16 + __stacksize * 8);
  *pcVar28 = *pcVar28 + (char)uVar16;
  uVar32 = uVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(char)uVar16);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar26 = *(int *)(uVar32 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar32 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  pcVar28 = (char *)(((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8)) + 1);
  bVar9 = (byte)((uint)unaff_EBX >> 8);
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + (int)pcVar28) = *(byte *)((int)unaff_EBX + (int)pcVar28) | bVar9;
    *pcVar28 = *pcVar28 + (char)pcVar28;
    pcVar28 = (char *)((uint)pcVar28 & 0xffffff00 | (uint)(byte)((char)pcVar28 - 0x30));
  }
  uVar24 = (uint)pcVar28 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar28 >> 8) + pcVar28[2],(char)pcVar28);
  uVar32 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar27 = *(int *)(uVar24 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar24 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  bVar10 = (char)puVar15 + 8;
  pcVar28 = (char *)((uint)puVar15 & 0xffffff00 | (uint)bVar10);
  bVar13 = (byte)in_ECX;
  if (!in_PF) {
    pcVar28[3] = pcVar28[3] | bVar13;
    *pcVar28 = *pcVar28 + bVar10;
    pcVar28 = (char *)((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 - 0x28));
  }
  uVar17 = (uint)pcVar28 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar28 >> 8) + pcVar28[2],(char)pcVar28);
  uVar24 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar17 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar17 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  uVar17 = (uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8);
  uVar18 = uVar17 - 1;
  bVar10 = (byte)__stacksize;
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar18) = *(byte *)((int)unaff_EBX + uVar18) | bVar10;
    pcVar28 = (char *)(uVar18 + __stacksize * 8);
    *pcVar28 = *pcVar28 + (char)uVar18;
  }
  uVar18 = uVar18 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar18 >> 8) + *(char *)(uVar17 + 1),(char)uVar18);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar4 = *(int *)(uVar18 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar18 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  bVar11 = (char)puVar15 + 8;
  uVar18 = (uint)puVar15 & 0xffffff00;
  pcVar28 = (char *)(uVar18 | (uint)bVar11);
  if (!in_PF) {
    pcVar28[3] = pcVar28[3] | (byte)(uVar18 >> 8);
    *pcVar28 = *pcVar28 + bVar11;
    pcVar28 = (char *)(uVar18 | (uint)(byte)((char)puVar15 - 0x28));
  }
  uVar19 = (uint)pcVar28 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar28 >> 8) + pcVar28[2],(char)pcVar28);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar5 = *(int *)(uVar19 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar19 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  bVar11 = (char)puVar15 + 8;
  uVar19 = (uint)puVar15 & 0xffffff00 | (uint)bVar11;
  *(uint *)(&stack0x00000000 +
            iVar5 + (uint)((uVar17 & 1) != 0) +
                    iVar4 + (uint)((uVar24 & 1) != 0) +
                            iVar3 + (uint)((uVar32 & 1) != 0) +
                                    iVar27 + (uint)((uVar16 & 1) != 0) +
                                             iVar26 + (uint)((uVar22 & 1) != 0) + iVar21 +
           (uVar18 - 2)) = uVar19;
  bVar31 = (byte)((uint)in_ECX >> 8);
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar19) = *(byte *)((int)unaff_EBX + uVar19) | bVar31;
    pcVar28 = (char *)(uVar19 + __stacksize * 8);
    *pcVar28 = *pcVar28 + bVar11;
  }
  uVar20 = (uint)puVar15 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar15 & 0xffffff00) >> 8) + *(char *)(uVar19 + 2),bVar11);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar19 = (uint)((uVar19 & 1) != 0);
  puVar6 = &stack0x00000000 +
           iVar5 + (uint)((uVar17 & 1) != 0) +
                   iVar4 + (uint)((uVar24 & 1) != 0) +
                           iVar3 + (uint)((uVar32 & 1) != 0) +
                                   iVar27 + (uint)((uVar16 & 1) != 0) +
                                            iVar26 + (uint)((uVar22 & 1) != 0) + iVar21 +
           *(int *)(uVar20 + 4) + (uVar18 - 2);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar20 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  bVar11 = (char)puVar15 + 8;
  pcVar28 = (char *)((uint)puVar15 & 0xffffff00 | (uint)bVar11);
  *(undefined **)(puVar6 + (uVar19 - 4)) = puVar6 + uVar19;
  if (!in_PF) {
    pcVar28[3] = pcVar28[3] | bVar9;
    *pcVar28 = *pcVar28 + bVar11;
    pcVar28 = (char *)((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 - 0x28));
  }
  uVar16 = (uint)pcVar28 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar28 >> 8) + pcVar28[2],(char)pcVar28);
  uVar22 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar22 = (uint)((uVar22 & 1) != 0);
  iVar21 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar16 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  uVar16 = *(uint *)(puVar6 + iVar21 + (uVar19 - 4) + uVar22);
  if (!in_PF) {
    pbVar25 = (byte *)((int)unaff_EBX + uVar16 + 0xd0040000);
    *pbVar25 = *pbVar25 | (byte)uVar16;
  }
  uVar32 = uVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(byte)uVar16);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar26 = *(int *)(uVar32 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar32 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  bVar11 = (char)puVar15 + 8;
  uVar32 = (uint)puVar15 & 0xffffff00 | (uint)bVar11;
  iVar33 = *(int *)(puVar6 + iVar21 + (uVar19 - 4) + (uint)((uVar16 & 1) != 0) + iVar26 + uVar22 + 4
                   );
  puVar34 = (undefined *)(iVar33 + 4);
  if (in_PF) {
    uVar16 = (uint)puVar15 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar15 & 0xffffff00) >> 8) + *(char *)(uVar32 + 2),bVar11
                           );
    uVar22 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar34 = (undefined *)(iVar33 + 4 + *(int *)(uVar16 + 4) + (uint)((uVar22 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar15 = (uint *)(uVar16 + 2);
    *puVar15 = *puVar15 | (uint)puVar15;
    uVar32 = (uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8);
  }
  *(byte *)(uVar32 + 0x4000003) = *(byte *)(uVar32 + 0x4000003) | bVar10;
  *(char *)__stacksize = *(char *)__stacksize << 1 | *(char *)__stacksize < 0;
  *(uint *)(puVar34 + -4) = uVar32;
  *(int *)(puVar34 + -8) = in_ECX;
  *(size_t *)(puVar34 + -0xc) = __stacksize;
  *(uint **)(puVar34 + -0x10) = unaff_EBX;
  *(undefined **)(puVar34 + -0x14) = puVar34;
  *(undefined4 **)(puVar34 + -0x18) = unaff_EBP;
  *(undefined **)(puVar34 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar34 + -0x20) = unaff_EDI;
  uVar22 = __stacksize & 0xffffff00 | (uint)(byte)(bVar10 + bVar13);
  iVar21 = uVar32 - *(int *)(uVar32 + 0x13);
  *(int *)(puVar34 + -0x24) = iVar21;
  *(int *)(puVar34 + -0x28) = in_ECX;
  *(uint *)(puVar34 + -0x2c) = uVar22;
  *(uint **)(puVar34 + -0x30) = unaff_EBX;
  *(undefined **)(puVar34 + -0x34) = puVar34 + -0x20;
  *(undefined4 **)(puVar34 + -0x38) = unaff_EBP;
  *(undefined **)(puVar34 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar34 + -0x40) = unaff_EDI;
  pbVar25 = (byte *)(uVar22 + in_ECX);
  pcVar28 = (char *)(iVar21 - *(int *)(iVar21 + 9));
  *pcVar28 = *pcVar28 + bVar9;
  pcVar28[in_ECX] = pcVar28[in_ECX] & (byte)pcVar28;
  *(char **)(puVar34 + -0x44) = pcVar28;
  *(int *)(puVar34 + -0x48) = in_ECX;
  *(byte **)(puVar34 + -0x4c) = pbVar25;
  *(uint **)(puVar34 + -0x50) = unaff_EBX;
  *(undefined **)(puVar34 + -0x54) = puVar34 + -0x40;
  *(undefined4 **)(puVar34 + -0x58) = unaff_EBP;
  *(undefined **)(puVar34 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar34 + -0x60) = unaff_EDI;
  bVar10 = (byte)unaff_EBX;
  if (!in_PF) {
    pbVar1 = (byte *)((int)((int)unaff_EBX + -0x2ffc0000) + (int)pcVar28);
    *pbVar1 = *pbVar1 | bVar10;
  }
  uVar16 = (uint)pcVar28 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar28 >> 8) + pcVar28[2],(byte)pcVar28);
  uVar22 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar22 = (uint)((uVar22 & 1) != 0);
  iVar21 = *(int *)(uVar16 + 4);
  puVar35 = puVar34 + iVar21 + -0x60 + uVar22;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar16 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  bVar11 = (char)puVar15 + 8;
  uVar16 = (uint)puVar15 & 0xffffff00 | (uint)bVar11;
  if (in_PF) {
    uVar32 = (uint)puVar15 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar15 & 0xffffff00) >> 8) + *(char *)(uVar16 + 2),bVar11
                           );
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar35 = puVar34 + iVar21 + -0x60 + (uint)((uVar16 & 1) != 0) + *(int *)(uVar32 + 4) + uVar22;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar15 = (uint *)(uVar32 + 2);
    *puVar15 = *puVar15 | (uint)puVar15;
    uVar16 = (uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8);
  }
  *(byte *)(uVar16 + 0x4000003) = *(byte *)(uVar16 + 0x4000003) | bVar31;
  *pbVar25 = *pbVar25 << 1 | (char)*pbVar25 < 0;
  *(uint *)(puVar35 + -4) = uVar16;
  *(int *)(puVar35 + -8) = in_ECX;
  *(byte **)(puVar35 + -0xc) = pbVar25;
  *(uint **)(puVar35 + -0x10) = unaff_EBX;
  *(undefined **)(puVar35 + -0x14) = puVar35;
  *(undefined4 **)(puVar35 + -0x18) = unaff_EBP;
  *(undefined **)(puVar35 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar35 + -0x20) = unaff_EDI;
  uVar32 = (uint)pbVar25 & 0xffffff00 | (uint)(byte)((char)pbVar25 + bVar13);
  iVar21 = uVar16 - *(int *)(uVar16 + 0x13);
  *(int *)(puVar35 + -0x24) = iVar21;
  *(int *)(puVar35 + -0x28) = in_ECX;
  *(uint *)(puVar35 + -0x2c) = uVar32;
  *(uint **)(puVar35 + -0x30) = unaff_EBX;
  *(undefined **)(puVar35 + -0x34) = puVar35 + -0x20;
  *(undefined4 **)(puVar35 + -0x38) = unaff_EBP;
  *(undefined **)(puVar35 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar35 + -0x40) = unaff_EDI;
  uVar32 = uVar32 + in_ECX;
  piVar23 = (int *)(iVar21 - *(int *)(iVar21 + 9));
  *(byte *)piVar23 = *(char *)piVar23 + bVar9;
  *(byte *)((int)piVar23 + in_ECX) = *(byte *)((int)piVar23 + in_ECX) & (byte)piVar23;
  *(undefined4 *)(puVar35 + -0x44) = 0xb408077a;
  uVar22 = (int)piVar23 + *piVar23;
  pcVar28 = (char *)(uVar22 + uVar32 * 8);
  *pcVar28 = *pcVar28 + (char)uVar22;
  uVar16 = uVar22 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar22 >> 8) + *(char *)(uVar22 + 2),(char)uVar22);
  uVar22 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar21 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar16 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  piVar23 = (int *)((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8));
  puVar6 = unaff_EDI + 1;
  uVar2 = in((short)uVar32);
  *unaff_EDI = uVar2;
  if (!in_PF) {
    piVar23 = (int *)((int)piVar23 + *piVar23);
    *(char *)(piVar23 + uVar32 * 2) = *(char *)(piVar23 + uVar32 * 2) + (char)piVar23;
  }
  uVar24 = (uint)piVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)piVar23 >> 8) + *(char *)((int)piVar23 + 2),(char)piVar23);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar7 = puVar35 + *(int *)(uVar24 + 4) + (uint)((uVar22 & 1) != 0) + iVar21 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar24 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  bVar11 = (char)puVar15 + 8;
  uVar22 = (uint)puVar15 & 0xffffff00 | (uint)bVar11;
  cVar30 = (char)uVar32;
  if (SCARRY1((char)puVar15,'\b')) {
    uVar32 = uVar32 & 0xffffff00 | (uint)(byte)(cVar30 + bVar13);
    iVar21 = uVar22 - *(int *)(uVar22 + 0x13);
    *(int *)(puVar7 + (uVar16 - 4)) = iVar21;
    *(int *)(puVar7 + (uVar16 - 8)) = in_ECX;
    *(uint *)(puVar7 + (uVar16 - 0xc)) = uVar32;
    *(uint **)(puVar7 + (uVar16 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar7 + (int)(&DAT_ffffffec + uVar16)) = puVar7 + uVar16;
    *(undefined4 **)(puVar7 + (uVar16 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar7 + (uVar16 - 0x1c)) = unaff_ESI;
    puVar36 = puVar7 + (uVar16 - 0x20);
    *(undefined **)(puVar7 + (uVar16 - 0x20)) = puVar6;
    uVar32 = uVar32 + in_ECX;
    pbVar25 = (byte *)(iVar21 - *(int *)(iVar21 + 9));
    *pbVar25 = *pbVar25 + bVar9;
    pbVar25[in_ECX] = pbVar25[in_ECX] & (byte)pbVar25;
  }
  else {
    piVar23 = (int *)((uint)puVar15 & 0xffff0000 |
                     (uint)CONCAT11((byte)(((uint)puVar15 & 0xffffff00) >> 8) | bVar13,bVar11));
    uVar22 = (int)piVar23 + *piVar23;
    pcVar28 = (char *)(uVar22 + uVar32 * 8);
    *pcVar28 = *pcVar28 + (char)uVar22;
    uVar24 = uVar22 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar22 >> 8) + *(char *)(uVar22 + 2),(char)uVar22);
    uVar22 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar22 = (uint)((uVar22 & 1) != 0);
    puVar7 = puVar7 + *(int *)(uVar24 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar15 = (uint *)(uVar24 + 2);
    *puVar15 = *puVar15 | (uint)puVar15;
    bVar11 = (char)puVar15 + 8;
    uVar16 = (uint)puVar15 & 0xffffff00 | (uint)bVar11;
    if (bVar11 == 0) {
      uVar32 = uVar32 & 0xffffff00 | (uint)(byte)(cVar30 + bVar13);
      iVar21 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar7 + (uVar22 - 4)) = iVar21;
      *(int *)(puVar7 + (uVar22 - 8)) = in_ECX;
      *(uint *)(puVar7 + (uVar22 - 0xc)) = uVar32;
      *(uint **)(puVar7 + (uVar22 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar7 + (int)(&DAT_ffffffec + uVar22)) = puVar7 + uVar22;
      *(undefined4 **)(puVar7 + (uVar22 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar7 + (uVar22 - 0x1c)) = unaff_ESI;
      puVar37 = puVar7 + (uVar22 - 0x20);
      *(undefined **)(puVar7 + (uVar22 - 0x20)) = puVar6;
      uVar32 = uVar32 + in_ECX;
      pcVar28 = (char *)(iVar21 - *(int *)(iVar21 + 9));
      *pcVar28 = *pcVar28 + bVar9;
      pcVar28[in_ECX] = pcVar28[in_ECX] & (byte)pcVar28;
      goto code_r0x080429ec;
    }
    piVar23 = (int *)((uint)puVar15 & 0xffffff00 | (uint)(bVar11 | bVar10));
    uVar16 = (int)piVar23 + *piVar23;
    pcVar28 = (char *)(uVar16 + uVar32 * 8);
    *pcVar28 = *pcVar28 + (char)uVar16;
    uVar24 = uVar16 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(char)uVar16);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar16 = (uint)((uVar16 & 1) != 0);
    puVar7 = puVar7 + *(int *)(uVar24 + 4) + uVar22 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar15 = (uint *)(uVar24 + 2);
    *puVar15 = *puVar15 | (uint)puVar15;
    bVar11 = (char)puVar15 + 8;
    uVar22 = (uint)puVar15 & 0xffffff00 | (uint)bVar11;
    if ((char)bVar11 < 0) {
      iVar21 = uVar22 - *(int *)(uVar22 + 0x13);
      *(int *)(puVar7 + (uVar16 - 4)) = iVar21;
      *(int *)(puVar7 + (uVar16 - 8)) = in_ECX;
      *(uint *)(puVar7 + (uVar16 - 0xc)) = uVar32 & 0xffffff00 | (uint)(byte)(cVar30 + bVar13);
      *(uint **)(puVar7 + (uVar16 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar7 + (uVar16 - 0x14)) = puVar7 + uVar16;
      *(undefined4 **)(puVar7 + (uVar16 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar7 + (uVar16 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar7 + (uVar16 - 0x20)) = puVar6;
      pcVar28 = (char *)(iVar21 - *(int *)(iVar21 + 9));
      *pcVar28 = *pcVar28 + bVar9;
      pcVar28[in_ECX] = pcVar28[in_ECX] & (byte)pcVar28;
      return;
    }
    piVar23 = (int *)((uint)puVar15 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar15 & 0xffffff00) >> 8),bVar11));
    uVar22 = (int)piVar23 + *piVar23;
    pcVar28 = (char *)(uVar22 + uVar32 * 8);
    *pcVar28 = *pcVar28 + (char)uVar22;
    uVar24 = uVar22 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar22 >> 8) + *(char *)(uVar22 + 2),(char)uVar22);
    uVar22 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar22 = (uint)((uVar22 & 1) != 0);
    puVar7 = puVar7 + *(int *)(uVar24 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar15 = (uint *)(uVar24 + 2);
    *puVar15 = *puVar15 | (uint)puVar15;
    bVar11 = (char)puVar15 + 8;
    uVar16 = (uint)puVar15 & 0xffffff00 | (uint)bVar11;
    if (SCARRY1((char)puVar15,'\b') != (char)bVar11 < 0) {
      uVar32 = uVar32 & 0xffffff00 | (uint)(byte)(cVar30 + bVar13);
      iVar21 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar7 + (uVar22 - 4)) = iVar21;
      *(int *)(puVar7 + (uVar22 - 8)) = in_ECX;
      *(uint *)(puVar7 + (uVar22 - 0xc)) = uVar32;
      *(uint **)(puVar7 + (uVar22 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar7 + (uVar22 - 0x14)) = puVar7 + uVar22;
      *(undefined4 **)(puVar7 + (uVar22 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar7 + (uVar22 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar7 + (uVar22 - 0x20)) = puVar6;
      pbVar25 = (byte *)(uVar32 + in_ECX);
      pcVar28 = (char *)(iVar21 - *(int *)(iVar21 + 9));
      *pcVar28 = *pcVar28 + bVar9;
      bVar11 = (byte)pcVar28;
      pcVar28[in_ECX] = pcVar28[in_ECX] & bVar11;
      if (!in_PF) {
        pcVar28[(int)(puVar7 + (uVar22 - 0x20))] = pcVar28[(int)(puVar7 + (uVar22 - 0x20))] | bVar31
        ;
        *pcVar28 = *pcVar28 + bVar11;
        pcVar28 = (char *)((uint)pcVar28 & 0xffffff00 | (uint)(byte)(bVar11 - 0x30));
      }
      uVar32 = (uint)pcVar28 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar28 >> 8) + pcVar28[2],(char)pcVar28);
      bVar40 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar16 = (uint)bVar40;
      puVar7 = puVar7 + *(int *)(uVar32 + 4) + (uVar22 - 0x20);
      cVar30 = (char)puVar7 + bVar40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(uVar32 + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      if (!in_PF) {
        puVar7[uVar16] = puVar7[uVar16] | bVar9;
        puVar7[(int)pbVar25 * 8 + uVar16] = puVar7[(int)pbVar25 * 8 + uVar16] + cVar30;
      }
      uVar16 = (uint)(puVar7 + uVar16) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar7 + uVar16) >> 8) + puVar7[uVar16 + 2],cVar30);
      uVar22 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar22 = (uint)((uVar22 & 1) != 0);
      iVar21 = ((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8)) + *(int *)(uVar16 + 4)
      ;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(uVar16 + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      bVar11 = (char)puVar15 + 8;
      uVar14 = (ushort)puVar15 & 0xff00 | (ushort)bVar11;
      iVar26 = (int)(short)uVar14;
      if (!in_PF) {
        pbVar1 = (byte *)(iVar21 + uVar22 + iVar26);
        *pbVar1 = *pbVar1 | bVar11;
        pcVar28 = (char *)(iVar26 + (int)pbVar25 * 8);
        *pcVar28 = *pcVar28 + bVar11;
      }
      iVar27 = CONCAT22((short)uVar14 >> 0xf,
                        CONCAT11((char)((uint)iVar26 >> 8) + *(char *)(iVar26 + 2),bVar11));
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(iVar27 + 4);
      uVar32 = (uint)((uVar16 & 1) != 0);
      uVar16 = *puVar15;
      iVar26 = iVar21 + uVar22 + *puVar15;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(iVar27 + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      bVar11 = (byte)puVar15;
      bVar12 = bVar11 + 8;
      pcVar28 = (char *)((uint)puVar15 & 0xffffff00 | (uint)bVar12);
      *(uint *)(iVar26 + uVar32 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar11,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar12 < 0) * 0x80 |
           (uint)(bVar12 == 0) * 0x40 |
           (uint)(((iVar21 + uVar22 & 0xfffffff) + (uVar16 & 0xfffffff) + uVar32 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar11) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if (!in_PF) {
        pcVar28[4] = pcVar28[4] | (byte)pbVar25;
        *pcVar28 = *pcVar28 + bVar12;
        pcVar28 = (char *)((uint)puVar15 & 0xffffff00 | (uint)(byte)(bVar11 - 0x28));
      }
      uVar16 = (uint)pcVar28 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar28 >> 8) + pcVar28[2],(char)pcVar28);
      uVar22 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar21 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(uVar16 + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      bVar11 = DAT_5c08077a;
      uVar16 = (uint)puVar15 & 0xffffff00 | (uint)DAT_5c08077a;
      pcVar28 = (char *)(uVar16 + (int)pbVar25 * 8);
      *pcVar28 = *pcVar28 + DAT_5c08077a;
      uVar24 = (uint)puVar15 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar15 >> 8) + *(char *)(uVar16 + 2),bVar11);
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar27 = *(int *)(uVar24 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(uVar24 + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      bVar11 = (char)puVar15 + 8;
      pcVar28 = (char *)((uint)puVar15 & 0xffffff00 | (uint)bVar11);
      _DAT_03ffffc4 = unaff_EDI + 2;
      *puVar6 = *unaff_ESI;
      if (!in_PF) {
        pcVar28[4] = pcVar28[4] | bVar31;
        *pcVar28 = *pcVar28 + bVar11;
        pcVar28 = (char *)((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 - 0x28));
      }
      uVar17 = (uint)pcVar28 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar28 >> 8) + pcVar28[2],(char)pcVar28);
      uVar24 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar24 = (uint)((uVar24 & 1) != 0);
      iVar21 = iVar26 + uVar32 + -4 + iVar21 + (uint)((uVar22 & 1) != 0) + iVar27 +
               (uint)((uVar16 & 1) != 0) + *(int *)(uVar17 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(uVar17 + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      bVar11 = (char)puVar15 + 8;
      uVar22 = (uint)puVar15 & 0xffffff00 | (uint)bVar11;
      pbVar1 = (byte *)(iVar21 + uVar24 + 2 + uVar22);
      *pbVar1 = *pbVar1 | (byte)((uint)pbVar25 >> 8);
      pcVar28 = (char *)(uVar22 + (int)pbVar25 * 8);
      *pcVar28 = *pcVar28 + bVar11;
      uVar16 = (uint)puVar15 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar15 & 0xffffff00) >> 8) + *(char *)(uVar22 + 2),
                              bVar11);
      uVar22 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar22 = (uint)((uVar22 & 1) != 0);
      iVar21 = iVar21 + uVar24 + 2 + *(int *)(uVar16 + 4);
      puVar38 = (undefined *)(iVar21 + uVar22);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(uVar16 + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      _DAT_03ffffc8 = unaff_ESI + 2;
      uVar16 = (uint)puVar15 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (in_PF) {
        uVar32 = (uint)puVar15 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar15 >> 8) + *(char *)(uVar16 + 2),unaff_ESI[1]);
        uVar16 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar38 = (undefined *)(iVar21 + uVar22 + *(int *)(uVar32 + 4) + (uint)((uVar16 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar15 = (uint *)(uVar32 + 2);
        *puVar15 = *puVar15 | (uint)puVar15;
        uVar16 = (uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8);
      }
      *(byte *)(uVar16 + 0x4000004) = *(byte *)(uVar16 + 0x4000004) | (byte)uVar16;
      *pbVar25 = *pbVar25 << 1 | (char)*pbVar25 < 0;
      *(uint *)(puVar38 + -4) = uVar16;
      *(int *)(puVar38 + -8) = in_ECX;
      *(byte **)(puVar38 + -0xc) = pbVar25;
      *(uint **)(puVar38 + -0x10) = unaff_EBX;
      *(undefined **)(puVar38 + -0x14) = puVar38;
      *(undefined4 **)(puVar38 + -0x18) = unaff_EBP;
      *(undefined **)(puVar38 + -0x1c) = _DAT_03ffffc8;
      *(undefined **)(puVar38 + -0x20) = _DAT_03ffffc4;
      uVar22 = (uint)pbVar25 & 0xffffff00 | (uint)(byte)((byte)pbVar25 + bVar13);
      iVar21 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar38 + -0x24) = iVar21;
      *(int *)(puVar38 + -0x28) = in_ECX;
      *(uint *)(puVar38 + -0x2c) = uVar22;
      *(uint **)(puVar38 + -0x30) = unaff_EBX;
      *(undefined **)(puVar38 + -0x34) = puVar38 + -0x20;
      *(undefined4 **)(puVar38 + -0x38) = unaff_EBP;
      *(undefined **)(puVar38 + -0x3c) = _DAT_03ffffc8;
      *(undefined **)(puVar38 + -0x40) = _DAT_03ffffc4;
      pbVar25 = (byte *)(uVar22 + in_ECX);
      pcVar28 = (char *)(iVar21 - *(int *)(iVar21 + 9));
      *pcVar28 = *pcVar28 + bVar9;
      pcVar28[in_ECX] = pcVar28[in_ECX] & (byte)pcVar28;
      iVar21 = CONCAT31((int3)((uint)pcVar28 >> 8),0x7a);
      puVar38[iVar21 + -0x2ffc003e] = puVar38[iVar21 + -0x2ffc003e] | bVar13;
      uVar16 = (uint)pcVar28 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar28 >> 8) + *(char *)(iVar21 + 2),0x7a);
      uVar22 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar22 = (uint)((uVar22 & 1) != 0);
      puVar6 = puVar38 + *(int *)(uVar16 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(uVar16 + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      uVar16 = (uint)puVar15 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar15 + '\b');
      *(byte *)(uVar16 + 0x4000004) = *(byte *)(uVar16 + 0x4000004) | bVar10;
      *pbVar25 = *pbVar25 << 1 | (char)*pbVar25 < 0;
      *(uint *)(puVar6 + uVar22) = uVar16;
      *(int *)(puVar6 + (uVar22 - 4)) = in_ECX;
      *(byte **)(puVar6 + (uVar22 - 8)) = pbVar25;
      *(uint **)(puVar6 + (uVar22 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar6 + (uVar22 - 0x10)) = puVar6 + uVar22 + 4;
      *(undefined4 **)(puVar6 + (int)(&DAT_ffffffec + uVar22)) = unaff_EBP;
      *(undefined **)(puVar6 + (uVar22 - 0x18)) = _DAT_03ffffc8;
      *(undefined **)(puVar6 + (uVar22 - 0x1c)) = _DAT_03ffffc4;
      uVar32 = (uint)pbVar25 & 0xffffff00 | (uint)(byte)((char)pbVar25 + bVar13);
      iVar21 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar6 + (uVar22 - 0x20)) = iVar21;
      *(int *)(puVar6 + (uVar22 - 0x24)) = in_ECX;
      *(uint *)(puVar6 + (uVar22 - 0x28)) = uVar32;
      *(uint **)(puVar6 + (uVar22 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar6 + (uVar22 - 0x30)) = puVar6 + (uVar22 - 0x1c);
      *(undefined4 **)(puVar6 + (uVar22 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar6 + (uVar22 - 0x38)) = _DAT_03ffffc8;
      *(undefined **)(puVar6 + (uVar22 - 0x3c)) = _DAT_03ffffc4;
      _DAT_03fffff8 = (byte *)(uVar32 + in_ECX);
      pcVar28 = (char *)(iVar21 - *(int *)(iVar21 + 9));
      *pcVar28 = *pcVar28 + bVar9;
      pcVar28[in_ECX] = pcVar28[in_ECX] & (byte)pcVar28;
      pcVar28 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
      *pcVar28 = *pcVar28 + 'z';
      cVar30 = DAT_a408077c + '\a';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar30,0x7a)) + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      bVar10 = (char)puVar15 + 8;
      uVar22 = (uint)puVar15 & 0xffffff00 | (uint)bVar10;
      pcVar28 = (char *)(uVar22 + (int)_DAT_03fffff8 * 8);
      *pcVar28 = *pcVar28 + bVar10;
      cVar30 = *(char *)(uVar22 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(((uint)puVar15 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar15 & 0xffffff00) >> 8) + cVar30,bVar10))
                        + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      _DAT_04000000 = (uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8);
      _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
      *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
      _DAT_03fffff0 = 0x4000004;
      _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar13);
      _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
      _DAT_03ffffd0 = &DAT_03ffffe4;
      iVar21 = _DAT_03ffffd8 + in_ECX;
      pcVar29 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
      _DAT_03ffffcc = unaff_EBP;
      _DAT_03ffffd4 = unaff_EBX;
      _DAT_03ffffdc = in_ECX;
      _DAT_03ffffe4 = _DAT_03ffffc4;
      _DAT_03ffffe8 = _DAT_03ffffc8;
      _DAT_03ffffec = unaff_EBP;
      _DAT_03fffff4 = unaff_EBX;
      _DAT_03fffffc = in_ECX;
      *pcVar29 = *pcVar29 + bVar9;
      pcVar29[in_ECX] = pcVar29[in_ECX] & (byte)pcVar29;
      bVar13 = (byte)pcVar29 | bVar13;
      uVar22 = (uint)pcVar29 & 0xffffff00 | (uint)bVar13;
      pcVar28 = (char *)(uVar22 + iVar21 * 8);
      *pcVar28 = *pcVar28 + bVar13;
      uVar16 = (uint)pcVar29 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar29 & 0xffffff00) >> 8) + *(char *)(uVar22 + 2),
                              bVar13);
      uVar22 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar22 = (uint)((uVar22 & 1) != 0);
      iVar21 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(uVar16 + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      bVar9 = (char)puVar15 + 8;
      puVar39 = (undefined4 *)(iVar21 + uVar22 + 0x3ffffc0);
      *(undefined4 **)(iVar21 + uVar22 + 0x3ffffc0) = unaff_EBP;
      cVar30 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar39 = puVar39 + -1;
        *puVar39 = *unaff_EBP;
        cVar30 = cVar30 + -1;
      } while (0 < cVar30);
      *(uint *)(iVar21 + uVar22 + 0x3ffffa0) = iVar21 + uVar22 + 0x3ffffc0;
      uVar16 = (uint)CONCAT11(bVar9 / 4,bVar9) & 0xffffff00;
      uVar22 = (uint)puVar15 & 0xffff0000 | uVar16;
      pcVar28 = (char *)(uVar22 | (uint)bVar9 & 0xffffff04);
      cVar30 = (char)((uint)bVar9 & 0xffffff04);
      *pcVar28 = *pcVar28 + cVar30;
      bVar9 = cVar30 - 0x30;
      cVar30 = *(char *)((uVar22 | (uint)bVar9) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar15 = (uint *)(((uint)puVar15 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar16 >> 8) + cVar30,bVar9)) + 2);
      *puVar15 = *puVar15 | (uint)puVar15;
      pcVar8 = (code *)swi(3);
      iVar21 = (*pcVar8)((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8));
      return iVar21;
    }
    piVar23 = (int *)((uint)puVar15 & 0xffffff00 | (uint)(byte)(bVar11 | (byte)(uVar32 >> 8)));
    uVar16 = (int)piVar23 + *piVar23;
    pcVar28 = (char *)(uVar16 + uVar32 * 8);
    *pcVar28 = *pcVar28 + (char)uVar16;
    uVar24 = uVar16 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(char)uVar16);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar21 = *(int *)(uVar24 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar15 = (uint *)(uVar24 + 2);
    *puVar15 = *puVar15 | (uint)puVar15;
    piVar23 = (int *)((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8));
    uVar24 = (int)piVar23 + *piVar23;
    pcVar28 = (char *)(uVar24 + uVar32 * 8);
    *pcVar28 = *pcVar28 + (char)uVar24;
    uVar17 = uVar24 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar24 >> 8) + *(char *)(uVar24 + 2),(char)uVar24);
    uVar24 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar36 = puVar7 + (uint)((uVar24 & 1) != 0) +
                       *(int *)(uVar17 + 4) + (uint)((uVar16 & 1) != 0) + iVar21 + uVar22 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar15 = (uint *)(uVar17 + 2);
    *puVar15 = *puVar15 | (uint)puVar15;
    pbVar25 = (byte *)((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8));
  }
  *pbVar25 = *pbVar25 | bVar13;
  pbVar25[uVar32 * 8] = pbVar25[uVar32 * 8] + (char)pbVar25;
  uVar16 = (uint)pbVar25 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar25 >> 8) + pbVar25[2],(char)pbVar25);
  uVar22 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar37 = puVar36 + (uint)((uVar22 & 1) != 0) + *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(uVar16 + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
  pcVar28 = (char *)((uint)puVar15 & 0xffffff00 | (uint)(byte)((char)puVar15 + 8));
code_r0x080429ec:
  *(byte *)(uVar32 + 7) = bVar9;
  puVar37[(int)pcVar28] = puVar37[(int)pcVar28] | (byte)uVar32;
  *pcVar28 = *pcVar28 + (char)pcVar28;
  bVar9 = (char)pcVar28 - 0x30;
  cVar30 = *(char *)(((uint)pcVar28 & 0xffffff00 | (uint)bVar9) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar15 = (uint *)(((uint)pcVar28 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar28 & 0xffffff00) >> 8) + cVar30,bVar9)) + 2);
  *puVar15 = *puVar15 | (uint)puVar15;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

char * strncpy(char *__dest,char *__src,size_t __n)

{
  byte *pbVar1;
  undefined uVar2;
  int iVar3;
  undefined *puVar4;
  undefined *puVar5;
  code *pcVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  ushort uVar11;
  uint *puVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  int iVar17;
  uint uVar18;
  int *piVar19;
  byte *pbVar20;
  int iVar21;
  int iVar22;
  char *pcVar23;
  char cVar25;
  char *pcVar24;
  byte bVar26;
  uint uVar27;
  byte bVar28;
  uint *unaff_EBX;
  int iVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined *puVar32;
  undefined *puVar33;
  undefined *puVar34;
  undefined4 *puVar35;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar36;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar7 = (char)__dest - 0x30;
  uVar16 = (uint)__dest & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__dest & 0xffffff00) >> 8) +
                          *(char *)(((uint)__dest & 0xffffff00 | (uint)bVar7) + 2),bVar7);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar7);
  bVar10 = (byte)__n;
  if (!in_PF) {
    pcVar23[3] = pcVar23[3] | bVar10;
    *pcVar23 = *pcVar23 + bVar7;
    pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar27 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar21 = *(int *)(uVar27 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar27 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar27 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  uVar13 = uVar27 - 1;
  bVar7 = (byte)__src;
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar13) = *(byte *)((int)unaff_EBX + uVar13) | bVar7;
    pcVar23 = (char *)(uVar13 + (int)__src * 8);
    *pcVar23 = *pcVar23 + (char)uVar13;
  }
  uVar13 = uVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar27 + 1),(char)uVar13);
  uVar27 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar22 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar13 = (uint)puVar12 & 0xffffff00;
  pcVar23 = (char *)(uVar13 | (uint)bVar8);
  if (!in_PF) {
    pcVar23[3] = pcVar23[3] | (byte)(uVar13 >> 8);
    *pcVar23 = *pcVar23 + bVar8;
    pcVar23 = (char *)(uVar13 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar14 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar13 & 1) != 0);
  iVar3 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar14 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar14 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
  *(uint *)(&stack0x00000000 +
            iVar3 + (uint)((uVar27 & 1) != 0) +
                    iVar22 + (uint)((uVar16 & 1) != 0) + iVar21 + (uint)((uVar18 & 1) != 0) + iVar17
           + (uVar13 - 4)) = uVar14;
  bVar26 = (byte)(__n >> 8);
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar14) = *(byte *)((int)unaff_EBX + uVar14) | bVar26;
    pcVar23 = (char *)(uVar14 + (int)__src * 8);
    *pcVar23 = *pcVar23 + bVar8;
  }
  uVar15 = (uint)puVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),bVar8);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  puVar4 = &stack0x00000000 +
           iVar3 + (uint)((uVar27 & 1) != 0) +
                   iVar22 + (uint)((uVar16 & 1) != 0) + iVar21 + (uint)((uVar18 & 1) != 0) + iVar17
           + *(int *)(uVar15 + 4) + (uVar13 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar15 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
  *(undefined **)(puVar4 + (uVar14 - 4)) = puVar4 + uVar14;
  bVar28 = (byte)((uint)unaff_EBX >> 8);
  if (!in_PF) {
    pcVar23[3] = pcVar23[3] | bVar28;
    *pcVar23 = *pcVar23 + bVar8;
    pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar16 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar16 = *(uint *)(puVar4 + iVar17 + (uVar14 - 4) + uVar18);
  if (!in_PF) {
    pbVar20 = (byte *)((int)unaff_EBX + uVar16 + 0xd0040000);
    *pbVar20 = *pbVar20 | (byte)uVar16;
  }
  uVar27 = uVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(byte)uVar16);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar21 = *(int *)(uVar27 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar27 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar27 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
  iVar29 = *(int *)(puVar4 + iVar17 + (uVar14 - 4) + (uint)((uVar16 & 1) != 0) + iVar21 + uVar18 + 4
                   );
  puVar30 = (undefined *)(iVar29 + 4);
  if (in_PF) {
    uVar16 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar27 + 2),bVar8)
    ;
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = (undefined *)(iVar29 + 4 + *(int *)(uVar16 + 4) + (uint)((uVar18 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar16 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar27 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar27 + 0x4000003) = *(byte *)(uVar27 + 0x4000003) | bVar7;
  *__src = *__src << 1 | *__src < 0;
  *(uint *)(puVar30 + -4) = uVar27;
  *(size_t *)(puVar30 + -8) = __n;
  *(char **)(puVar30 + -0xc) = __src;
  *(uint **)(puVar30 + -0x10) = unaff_EBX;
  *(undefined **)(puVar30 + -0x14) = puVar30;
  *(undefined4 **)(puVar30 + -0x18) = unaff_EBP;
  *(undefined **)(puVar30 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x20) = unaff_EDI;
  uVar18 = (uint)__src & 0xffffff00 | (uint)(byte)(bVar7 + bVar10);
  iVar17 = uVar27 - *(int *)(uVar27 + 0x13);
  *(int *)(puVar30 + -0x24) = iVar17;
  *(size_t *)(puVar30 + -0x28) = __n;
  *(uint *)(puVar30 + -0x2c) = uVar18;
  *(uint **)(puVar30 + -0x30) = unaff_EBX;
  *(undefined **)(puVar30 + -0x34) = puVar30 + -0x20;
  *(undefined4 **)(puVar30 + -0x38) = unaff_EBP;
  *(undefined **)(puVar30 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x40) = unaff_EDI;
  pbVar20 = (byte *)(uVar18 + __n);
  pcVar23 = (char *)(iVar17 - *(int *)(iVar17 + 9));
  *pcVar23 = *pcVar23 + bVar28;
  pcVar23[__n] = pcVar23[__n] & (byte)pcVar23;
  *(char **)(puVar30 + -0x44) = pcVar23;
  *(size_t *)(puVar30 + -0x48) = __n;
  *(byte **)(puVar30 + -0x4c) = pbVar20;
  *(uint **)(puVar30 + -0x50) = unaff_EBX;
  *(undefined **)(puVar30 + -0x54) = puVar30 + -0x40;
  *(undefined4 **)(puVar30 + -0x58) = unaff_EBP;
  *(undefined **)(puVar30 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar30 + -0x60) = unaff_EDI;
  bVar7 = (byte)unaff_EBX;
  if (!in_PF) {
    pbVar1 = (byte *)((int)((int)unaff_EBX + -0x2ffc0000) + (int)pcVar23);
    *pbVar1 = *pbVar1 | bVar7;
  }
  uVar16 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(byte)pcVar23);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar18 = (uint)((uVar18 & 1) != 0);
  iVar17 = *(int *)(uVar16 + 4);
  puVar31 = puVar30 + iVar17 + -0x60 + uVar18;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar16 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
  if (in_PF) {
    uVar27 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar16 + 2),bVar8)
    ;
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar31 = puVar30 + iVar17 + -0x60 + (uint)((uVar16 & 1) != 0) + *(int *)(uVar27 + 4) + uVar18;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar27 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar16 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar16 + 0x4000003) = *(byte *)(uVar16 + 0x4000003) | bVar26;
  *pbVar20 = *pbVar20 << 1 | (char)*pbVar20 < 0;
  *(uint *)(puVar31 + -4) = uVar16;
  *(size_t *)(puVar31 + -8) = __n;
  *(byte **)(puVar31 + -0xc) = pbVar20;
  *(uint **)(puVar31 + -0x10) = unaff_EBX;
  *(undefined **)(puVar31 + -0x14) = puVar31;
  *(undefined4 **)(puVar31 + -0x18) = unaff_EBP;
  *(undefined **)(puVar31 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar31 + -0x20) = unaff_EDI;
  uVar27 = (uint)pbVar20 & 0xffffff00 | (uint)(byte)((char)pbVar20 + bVar10);
  iVar17 = uVar16 - *(int *)(uVar16 + 0x13);
  *(int *)(puVar31 + -0x24) = iVar17;
  *(size_t *)(puVar31 + -0x28) = __n;
  *(uint *)(puVar31 + -0x2c) = uVar27;
  *(uint **)(puVar31 + -0x30) = unaff_EBX;
  *(undefined **)(puVar31 + -0x34) = puVar31 + -0x20;
  *(undefined4 **)(puVar31 + -0x38) = unaff_EBP;
  *(undefined **)(puVar31 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar31 + -0x40) = unaff_EDI;
  uVar27 = uVar27 + __n;
  piVar19 = (int *)(iVar17 - *(int *)(iVar17 + 9));
  *(byte *)piVar19 = *(char *)piVar19 + bVar28;
  *(byte *)((int)piVar19 + __n) = *(byte *)((int)piVar19 + __n) & (byte)piVar19;
  *(undefined4 *)(puVar31 + -0x44) = 0xb408077a;
  uVar18 = (int)piVar19 + *piVar19;
  pcVar23 = (char *)(uVar18 + uVar27 * 8);
  *pcVar23 = *pcVar23 + (char)uVar18;
  uVar16 = uVar18 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar18 >> 8) + *(char *)(uVar18 + 2),(char)uVar18);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar17 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  piVar19 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
  puVar4 = unaff_EDI + 1;
  uVar2 = in((short)uVar27);
  *unaff_EDI = uVar2;
  if (!in_PF) {
    piVar19 = (int *)((int)piVar19 + *piVar19);
    *(char *)(piVar19 + uVar27 * 2) = *(char *)(piVar19 + uVar27 * 2) + (char)piVar19;
  }
  uVar13 = (uint)piVar19 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)piVar19 >> 8) + *(char *)((int)piVar19 + 2),(char)piVar19);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar5 = puVar31 + *(int *)(uVar13 + 4) + (uint)((uVar18 & 1) != 0) + iVar17 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar18 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
  cVar25 = (char)uVar27;
  if (SCARRY1((char)puVar12,'\b')) {
    uVar27 = uVar27 & 0xffffff00 | (uint)(byte)(cVar25 + bVar10);
    iVar17 = uVar18 - *(int *)(uVar18 + 0x13);
    *(int *)(puVar5 + (uVar16 - 4)) = iVar17;
    *(size_t *)(puVar5 + (uVar16 - 8)) = __n;
    *(uint *)(puVar5 + (uVar16 - 0xc)) = uVar27;
    *(uint **)(puVar5 + (uVar16 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar5 + (int)(&DAT_ffffffec + uVar16)) = puVar5 + uVar16;
    *(undefined4 **)(puVar5 + (uVar16 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar5 + (uVar16 - 0x1c)) = unaff_ESI;
    puVar32 = puVar5 + (uVar16 - 0x20);
    *(undefined **)(puVar5 + (uVar16 - 0x20)) = puVar4;
    uVar27 = uVar27 + __n;
    pbVar20 = (byte *)(iVar17 - *(int *)(iVar17 + 9));
    *pbVar20 = *pbVar20 + bVar28;
    pbVar20[__n] = pbVar20[__n] & (byte)pbVar20;
  }
  else {
    piVar19 = (int *)((uint)puVar12 & 0xffff0000 |
                     (uint)CONCAT11((byte)(((uint)puVar12 & 0xffffff00) >> 8) | bVar10,bVar8));
    uVar18 = (int)piVar19 + *piVar19;
    pcVar23 = (char *)(uVar18 + uVar27 * 8);
    *pcVar23 = *pcVar23 + (char)uVar18;
    uVar13 = uVar18 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar18 >> 8) + *(char *)(uVar18 + 2),(char)uVar18);
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar18 = (uint)((uVar18 & 1) != 0);
    puVar5 = puVar5 + *(int *)(uVar13 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar13 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar16 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if (bVar8 == 0) {
      uVar27 = uVar27 & 0xffffff00 | (uint)(byte)(cVar25 + bVar10);
      iVar17 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar5 + (uVar18 - 4)) = iVar17;
      *(size_t *)(puVar5 + (uVar18 - 8)) = __n;
      *(uint *)(puVar5 + (uVar18 - 0xc)) = uVar27;
      *(uint **)(puVar5 + (uVar18 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar5 + (int)(&DAT_ffffffec + uVar18)) = puVar5 + uVar18;
      *(undefined4 **)(puVar5 + (uVar18 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar5 + (uVar18 - 0x1c)) = unaff_ESI;
      puVar33 = puVar5 + (uVar18 - 0x20);
      *(undefined **)(puVar5 + (uVar18 - 0x20)) = puVar4;
      uVar27 = uVar27 + __n;
      pcVar23 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar23 = *pcVar23 + bVar28;
      pcVar23[__n] = pcVar23[__n] & (byte)pcVar23;
      goto code_r0x080429ec;
    }
    piVar19 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(bVar8 | bVar7));
    uVar16 = (int)piVar19 + *piVar19;
    pcVar23 = (char *)(uVar16 + uVar27 * 8);
    *pcVar23 = *pcVar23 + (char)uVar16;
    uVar13 = uVar16 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(char)uVar16);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar16 = (uint)((uVar16 & 1) != 0);
    puVar5 = puVar5 + *(int *)(uVar13 + 4) + uVar18 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar13 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar18 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if ((char)bVar8 < 0) {
      iVar17 = uVar18 - *(int *)(uVar18 + 0x13);
      *(int *)(puVar5 + (uVar16 - 4)) = iVar17;
      *(size_t *)(puVar5 + (uVar16 - 8)) = __n;
      *(uint *)(puVar5 + (uVar16 - 0xc)) = uVar27 & 0xffffff00 | (uint)(byte)(cVar25 + bVar10);
      *(uint **)(puVar5 + (uVar16 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar5 + (uVar16 - 0x14)) = puVar5 + uVar16;
      *(undefined4 **)(puVar5 + (uVar16 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar5 + (uVar16 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar5 + (uVar16 - 0x20)) = puVar4;
      pcVar23 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar23 = *pcVar23 + bVar28;
      pcVar23[__n] = pcVar23[__n] & (byte)pcVar23;
      return;
    }
    piVar19 = (int *)((uint)puVar12 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8),bVar8));
    uVar18 = (int)piVar19 + *piVar19;
    pcVar23 = (char *)(uVar18 + uVar27 * 8);
    *pcVar23 = *pcVar23 + (char)uVar18;
    uVar13 = uVar18 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar18 >> 8) + *(char *)(uVar18 + 2),(char)uVar18);
    uVar18 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar18 = (uint)((uVar18 & 1) != 0);
    puVar5 = puVar5 + *(int *)(uVar13 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar13 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar16 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if (SCARRY1((char)puVar12,'\b') != (char)bVar8 < 0) {
      uVar27 = uVar27 & 0xffffff00 | (uint)(byte)(cVar25 + bVar10);
      iVar17 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar5 + (uVar18 - 4)) = iVar17;
      *(size_t *)(puVar5 + (uVar18 - 8)) = __n;
      *(uint *)(puVar5 + (uVar18 - 0xc)) = uVar27;
      *(uint **)(puVar5 + (uVar18 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar5 + (uVar18 - 0x14)) = puVar5 + uVar18;
      *(undefined4 **)(puVar5 + (uVar18 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar5 + (uVar18 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar5 + (uVar18 - 0x20)) = puVar4;
      pbVar20 = (byte *)(uVar27 + __n);
      pcVar23 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar23 = *pcVar23 + bVar28;
      bVar8 = (byte)pcVar23;
      pcVar23[__n] = pcVar23[__n] & bVar8;
      if (!in_PF) {
        pcVar23[(int)(puVar5 + (uVar18 - 0x20))] = pcVar23[(int)(puVar5 + (uVar18 - 0x20))] | bVar26
        ;
        *pcVar23 = *pcVar23 + bVar8;
        pcVar23 = (char *)((uint)pcVar23 & 0xffffff00 | (uint)(byte)(bVar8 - 0x30));
      }
      uVar27 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
      bVar36 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar16 = (uint)bVar36;
      puVar5 = puVar5 + *(int *)(uVar27 + 4) + (uVar18 - 0x20);
      cVar25 = (char)puVar5 + bVar36;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar27 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      if (!in_PF) {
        puVar5[uVar16] = puVar5[uVar16] | bVar28;
        puVar5[(int)pbVar20 * 8 + uVar16] = puVar5[(int)pbVar20 * 8 + uVar16] + cVar25;
      }
      uVar16 = (uint)(puVar5 + uVar16) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar5 + uVar16) >> 8) + puVar5[uVar16 + 2],cVar25);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      iVar17 = ((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8)) + *(int *)(uVar16 + 4)
      ;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      uVar11 = (ushort)puVar12 & 0xff00 | (ushort)bVar8;
      iVar21 = (int)(short)uVar11;
      if (!in_PF) {
        pbVar1 = (byte *)(iVar17 + uVar18 + iVar21);
        *pbVar1 = *pbVar1 | bVar8;
        pcVar23 = (char *)(iVar21 + (int)pbVar20 * 8);
        *pcVar23 = *pcVar23 + bVar8;
      }
      iVar22 = CONCAT22((short)uVar11 >> 0xf,
                        CONCAT11((char)((uint)iVar21 >> 8) + *(char *)(iVar21 + 2),bVar8));
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar22 + 4);
      uVar27 = (uint)((uVar16 & 1) != 0);
      uVar16 = *puVar12;
      iVar21 = iVar17 + uVar18 + *puVar12;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar22 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (byte)puVar12;
      bVar9 = bVar8 + 8;
      pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar9);
      *(uint *)(iVar21 + uVar27 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar8,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar9 < 0) * 0x80 |
           (uint)(bVar9 == 0) * 0x40 |
           (uint)(((iVar17 + uVar18 & 0xfffffff) + (uVar16 & 0xfffffff) + uVar27 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar8) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if (!in_PF) {
        pcVar23[4] = pcVar23[4] | (byte)pbVar20;
        *pcVar23 = *pcVar23 + bVar9;
        pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)(bVar8 - 0x28));
      }
      uVar16 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar17 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = DAT_5c08077a;
      uVar16 = (uint)puVar12 & 0xffffff00 | (uint)DAT_5c08077a;
      pcVar23 = (char *)(uVar16 + (int)pbVar20 * 8);
      *pcVar23 = *pcVar23 + DAT_5c08077a;
      uVar13 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)(uVar16 + 2),bVar8);
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar22 = *(int *)(uVar13 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
      _DAT_03ffffc4 = unaff_EDI + 2;
      *puVar4 = *unaff_ESI;
      if (!in_PF) {
        pcVar23[4] = pcVar23[4] | bVar26;
        *pcVar23 = *pcVar23 + bVar8;
        pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
      }
      uVar14 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
      uVar13 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar13 = (uint)((uVar13 & 1) != 0);
      iVar17 = iVar21 + uVar27 + -4 + iVar17 + (uint)((uVar18 & 1) != 0) + iVar22 +
               (uint)((uVar16 & 1) != 0) + *(int *)(uVar14 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar14 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      uVar18 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
      pbVar1 = (byte *)(iVar17 + uVar13 + 2 + uVar18);
      *pbVar1 = *pbVar1 | (byte)((uint)pbVar20 >> 8);
      pcVar23 = (char *)(uVar18 + (int)pbVar20 * 8);
      *pcVar23 = *pcVar23 + bVar8;
      uVar16 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar18 + 2),
                              bVar8);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      iVar17 = iVar17 + uVar13 + 2 + *(int *)(uVar16 + 4);
      puVar34 = (undefined *)(iVar17 + uVar18);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_03ffffc8 = unaff_ESI + 2;
      uVar16 = (uint)puVar12 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (in_PF) {
        uVar27 = (uint)puVar12 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)(uVar16 + 2),unaff_ESI[1]);
        uVar16 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar34 = (undefined *)(iVar17 + uVar18 + *(int *)(uVar27 + 4) + (uint)((uVar16 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar12 = (uint *)(uVar27 + 2);
        *puVar12 = *puVar12 | (uint)puVar12;
        uVar16 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      }
      *(byte *)(uVar16 + 0x4000004) = *(byte *)(uVar16 + 0x4000004) | (byte)uVar16;
      *pbVar20 = *pbVar20 << 1 | (char)*pbVar20 < 0;
      *(uint *)(puVar34 + -4) = uVar16;
      *(size_t *)(puVar34 + -8) = __n;
      *(byte **)(puVar34 + -0xc) = pbVar20;
      *(uint **)(puVar34 + -0x10) = unaff_EBX;
      *(undefined **)(puVar34 + -0x14) = puVar34;
      *(undefined4 **)(puVar34 + -0x18) = unaff_EBP;
      *(undefined **)(puVar34 + -0x1c) = _DAT_03ffffc8;
      *(undefined **)(puVar34 + -0x20) = _DAT_03ffffc4;
      uVar18 = (uint)pbVar20 & 0xffffff00 | (uint)(byte)((byte)pbVar20 + bVar10);
      iVar17 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar34 + -0x24) = iVar17;
      *(size_t *)(puVar34 + -0x28) = __n;
      *(uint *)(puVar34 + -0x2c) = uVar18;
      *(uint **)(puVar34 + -0x30) = unaff_EBX;
      *(undefined **)(puVar34 + -0x34) = puVar34 + -0x20;
      *(undefined4 **)(puVar34 + -0x38) = unaff_EBP;
      *(undefined **)(puVar34 + -0x3c) = _DAT_03ffffc8;
      *(undefined **)(puVar34 + -0x40) = _DAT_03ffffc4;
      pbVar20 = (byte *)(uVar18 + __n);
      pcVar23 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar23 = *pcVar23 + bVar28;
      pcVar23[__n] = pcVar23[__n] & (byte)pcVar23;
      iVar17 = CONCAT31((int3)((uint)pcVar23 >> 8),0x7a);
      puVar34[iVar17 + -0x2ffc003e] = puVar34[iVar17 + -0x2ffc003e] | bVar10;
      uVar16 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + *(char *)(iVar17 + 2),0x7a);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      puVar4 = puVar34 + *(int *)(uVar16 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      uVar16 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar12 + '\b');
      *(byte *)(uVar16 + 0x4000004) = *(byte *)(uVar16 + 0x4000004) | bVar7;
      *pbVar20 = *pbVar20 << 1 | (char)*pbVar20 < 0;
      *(uint *)(puVar4 + uVar18) = uVar16;
      *(size_t *)(puVar4 + (uVar18 - 4)) = __n;
      *(byte **)(puVar4 + (uVar18 - 8)) = pbVar20;
      *(uint **)(puVar4 + (uVar18 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar18 - 0x10)) = puVar4 + uVar18 + 4;
      *(undefined4 **)(puVar4 + (int)(&DAT_ffffffec + uVar18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x18)) = _DAT_03ffffc8;
      *(undefined **)(puVar4 + (uVar18 - 0x1c)) = _DAT_03ffffc4;
      uVar27 = (uint)pbVar20 & 0xffffff00 | (uint)(byte)((char)pbVar20 + bVar10);
      iVar17 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar4 + (uVar18 - 0x20)) = iVar17;
      *(size_t *)(puVar4 + (uVar18 - 0x24)) = __n;
      *(uint *)(puVar4 + (uVar18 - 0x28)) = uVar27;
      *(uint **)(puVar4 + (uVar18 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar18 - 0x30)) = puVar4 + (uVar18 - 0x1c);
      *(undefined4 **)(puVar4 + (uVar18 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar18 - 0x38)) = _DAT_03ffffc8;
      *(undefined **)(puVar4 + (uVar18 - 0x3c)) = _DAT_03ffffc4;
      _DAT_03fffff8 = (byte *)(uVar27 + __n);
      pcVar23 = (char *)(iVar17 - *(int *)(iVar17 + 9));
      *pcVar23 = *pcVar23 + bVar28;
      pcVar23[__n] = pcVar23[__n] & (byte)pcVar23;
      pcVar23 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
      *pcVar23 = *pcVar23 + 'z';
      cVar25 = DAT_a408077c + '\a';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar25,0x7a)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = (char)puVar12 + 8;
      uVar18 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
      pcVar23 = (char *)(uVar18 + (int)_DAT_03fffff8 * 8);
      *pcVar23 = *pcVar23 + bVar7;
      cVar25 = *(char *)(uVar18 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + cVar25,bVar7)) +
                        2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_04000000 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
      *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
      _DAT_03fffff0 = 0x4000004;
      _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar10);
      _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
      _DAT_03ffffd0 = &DAT_03ffffe4;
      iVar17 = _DAT_03ffffd8 + __n;
      pcVar24 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
      _DAT_03ffffcc = unaff_EBP;
      _DAT_03ffffd4 = unaff_EBX;
      _DAT_03ffffdc = __n;
      _DAT_03ffffe4 = _DAT_03ffffc4;
      _DAT_03ffffe8 = _DAT_03ffffc8;
      _DAT_03ffffec = unaff_EBP;
      _DAT_03fffff4 = unaff_EBX;
      _DAT_03fffffc = __n;
      *pcVar24 = *pcVar24 + bVar28;
      pcVar24[__n] = pcVar24[__n] & (byte)pcVar24;
      bVar10 = (byte)pcVar24 | bVar10;
      uVar18 = (uint)pcVar24 & 0xffffff00 | (uint)bVar10;
      pcVar23 = (char *)(uVar18 + iVar17 * 8);
      *pcVar23 = *pcVar23 + bVar10;
      uVar16 = (uint)pcVar24 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar24 & 0xffffff00) >> 8) + *(char *)(uVar18 + 2),
                              bVar10);
      uVar18 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar18 = (uint)((uVar18 & 1) != 0);
      iVar17 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar16 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = (char)puVar12 + 8;
      puVar35 = (undefined4 *)(iVar17 + uVar18 + 0x3ffffc0);
      *(undefined4 **)(iVar17 + uVar18 + 0x3ffffc0) = unaff_EBP;
      cVar25 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar35 = puVar35 + -1;
        *puVar35 = *unaff_EBP;
        cVar25 = cVar25 + -1;
      } while (0 < cVar25);
      *(uint *)(iVar17 + uVar18 + 0x3ffffa0) = iVar17 + uVar18 + 0x3ffffc0;
      uVar16 = (uint)CONCAT11(bVar7 / 4,bVar7) & 0xffffff00;
      uVar18 = (uint)puVar12 & 0xffff0000 | uVar16;
      pcVar23 = (char *)(uVar18 | (uint)bVar7 & 0xffffff04);
      cVar25 = (char)((uint)bVar7 & 0xffffff04);
      *pcVar23 = *pcVar23 + cVar25;
      bVar7 = cVar25 - 0x30;
      cVar25 = *(char *)((uVar18 | (uint)bVar7) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar16 >> 8) + cVar25,bVar7)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      pcVar6 = (code *)swi(3);
      pcVar23 = (char *)(*pcVar6)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
      return pcVar23;
    }
    piVar19 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)(bVar8 | (byte)(uVar27 >> 8)));
    uVar16 = (int)piVar19 + *piVar19;
    pcVar23 = (char *)(uVar16 + uVar27 * 8);
    *pcVar23 = *pcVar23 + (char)uVar16;
    uVar13 = uVar16 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(char)uVar16);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar17 = *(int *)(uVar13 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar13 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    piVar19 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
    uVar13 = (int)piVar19 + *piVar19;
    pcVar23 = (char *)(uVar13 + uVar27 * 8);
    *pcVar23 = *pcVar23 + (char)uVar13;
    uVar14 = uVar13 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar13 + 2),(char)uVar13);
    uVar13 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar32 = puVar5 + (uint)((uVar13 & 1) != 0) +
                       *(int *)(uVar14 + 4) + (uint)((uVar16 & 1) != 0) + iVar17 + uVar18 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar14 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    pbVar20 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
  }
  *pbVar20 = *pbVar20 | bVar10;
  pbVar20[uVar27 * 8] = pbVar20[uVar27 * 8] + (char)pbVar20;
  uVar16 = (uint)pbVar20 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar20 >> 8) + pbVar20[2],(char)pbVar20);
  uVar18 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar33 = puVar32 + (uint)((uVar18 & 1) != 0) + *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar16 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
code_r0x080429ec:
  *(byte *)(uVar27 + 7) = bVar28;
  puVar33[(int)pcVar23] = puVar33[(int)pcVar23] | (byte)uVar27;
  *pcVar23 = *pcVar23 + (char)pcVar23;
  bVar7 = (char)pcVar23 - 0x30;
  cVar25 = *(char *)(((uint)pcVar23 & 0xffffff00 | (uint)bVar7) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(((uint)pcVar23 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar23 & 0xffffff00) >> 8) + cVar25,bVar7)) + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void atomic_add_value(uint uParm1,byte *pbParm2,int iParm3)

{
  byte *pbVar1;
  undefined uVar2;
  undefined *puVar3;
  undefined *puVar4;
  code *pcVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  ushort uVar11;
  uint *puVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  uint uVar17;
  int *piVar18;
  uint uVar19;
  byte *pbVar20;
  int iVar21;
  int iVar22;
  char *pcVar23;
  char cVar25;
  char *pcVar24;
  byte bVar26;
  uint *unaff_EBX;
  int iVar27;
  undefined *puVar28;
  undefined *puVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined *puVar32;
  undefined4 *puVar33;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar34;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack9 [4];
  undefined auStack5 [5];
  
  bVar6 = (char)uParm1 - 0x30;
  uVar15 = uParm1 & 0xffff0000 |
           (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                          *(char *)((uParm1 & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar16 = *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar15 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar15 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  uVar13 = uVar15 - 1;
  bVar6 = (byte)pbParm2;
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar13) = *(byte *)((int)unaff_EBX + uVar13) | bVar6;
    pcVar23 = (char *)(uVar13 + (int)pbParm2 * 8);
    *pcVar23 = *pcVar23 + (char)uVar13;
  }
  uVar13 = uVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar15 + 1),(char)uVar13);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar21 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar13 = (uint)puVar12 & 0xffffff00;
  pcVar23 = (char *)(uVar13 | (uint)bVar7);
  if (!in_PF) {
    pcVar23[3] = pcVar23[3] | (byte)(uVar13 >> 8);
    *pcVar23 = *pcVar23 + bVar7;
    pcVar23 = (char *)(uVar13 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar19 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar13 & 1) != 0);
  iVar22 = *(int *)(uVar19 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar19 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar19 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
  *(uint *)(&stack0x00000000 +
            iVar22 + (uint)((uVar15 & 1) != 0) + iVar21 + (uint)((uVar17 & 1) != 0) + iVar16 +
           (uVar13 - 5)) = uVar19;
  bVar10 = (byte)((uint)iParm3 >> 8);
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar19) = *(byte *)((int)unaff_EBX + uVar19) | bVar10;
    pcVar23 = (char *)(uVar19 + (int)pbParm2 * 8);
    *pcVar23 = *pcVar23 + bVar7;
  }
  uVar14 = (uint)puVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar19 + 2),bVar7);
  uVar19 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar19 = (uint)((uVar19 & 1) != 0);
  puVar3 = &stack0x00000000 +
           iVar22 + (uint)((uVar15 & 1) != 0) + iVar21 + (uint)((uVar17 & 1) != 0) + iVar16 +
           *(int *)(uVar14 + 4) + (uVar13 - 5);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar14 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar7);
  *(undefined **)(puVar3 + (uVar19 - 4)) = puVar3 + uVar19;
  bVar26 = (byte)((uint)unaff_EBX >> 8);
  if (!in_PF) {
    pcVar23[3] = pcVar23[3] | bVar26;
    *pcVar23 = *pcVar23 + bVar7;
    pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
  }
  uVar15 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  iVar16 = *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar15 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar15 = *(uint *)(puVar3 + iVar16 + (uVar19 - 4) + uVar17);
  if (!in_PF) {
    pbVar20 = (byte *)((int)unaff_EBX + uVar15 + 0xd0040000);
    *pbVar20 = *pbVar20 | (byte)uVar15;
  }
  uVar13 = uVar15 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar15 >> 8) + *(char *)(uVar15 + 2),(byte)uVar15);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar21 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar13 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
  iVar27 = *(int *)(puVar3 + iVar16 + (uVar19 - 4) + (uint)((uVar15 & 1) != 0) + iVar21 + uVar17 + 4
                   );
  puVar28 = (undefined *)(iVar27 + 4);
  if (in_PF) {
    uVar15 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar13 + 2),bVar7)
    ;
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar28 = (undefined *)(iVar27 + 4 + *(int *)(uVar15 + 4) + (uint)((uVar17 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar15 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar13 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar13 + 0x4000003) = *(byte *)(uVar13 + 0x4000003) | bVar6;
  *pbParm2 = *pbParm2 << 1 | (char)*pbParm2 < 0;
  *(uint *)(puVar28 + -4) = uVar13;
  *(int *)(puVar28 + -8) = iParm3;
  *(byte **)(puVar28 + -0xc) = pbParm2;
  *(uint **)(puVar28 + -0x10) = unaff_EBX;
  *(undefined **)(puVar28 + -0x14) = puVar28;
  *(undefined4 **)(puVar28 + -0x18) = unaff_EBP;
  *(undefined **)(puVar28 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar28 + -0x20) = unaff_EDI;
  bVar7 = (byte)iParm3;
  uVar17 = (uint)pbParm2 & 0xffffff00 | (uint)(byte)(bVar6 + bVar7);
  iVar16 = uVar13 - *(int *)(uVar13 + 0x13);
  *(int *)(puVar28 + -0x24) = iVar16;
  *(int *)(puVar28 + -0x28) = iParm3;
  *(uint *)(puVar28 + -0x2c) = uVar17;
  *(uint **)(puVar28 + -0x30) = unaff_EBX;
  *(undefined **)(puVar28 + -0x34) = puVar28 + -0x20;
  *(undefined4 **)(puVar28 + -0x38) = unaff_EBP;
  *(undefined **)(puVar28 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar28 + -0x40) = unaff_EDI;
  pbVar20 = (byte *)(uVar17 + iParm3);
  pcVar23 = (char *)(iVar16 - *(int *)(iVar16 + 9));
  *pcVar23 = *pcVar23 + bVar26;
  pcVar23[iParm3] = pcVar23[iParm3] & (byte)pcVar23;
  *(char **)(puVar28 + -0x44) = pcVar23;
  *(int *)(puVar28 + -0x48) = iParm3;
  *(byte **)(puVar28 + -0x4c) = pbVar20;
  *(uint **)(puVar28 + -0x50) = unaff_EBX;
  *(undefined **)(puVar28 + -0x54) = puVar28 + -0x40;
  *(undefined4 **)(puVar28 + -0x58) = unaff_EBP;
  *(undefined **)(puVar28 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar28 + -0x60) = unaff_EDI;
  bVar6 = (byte)unaff_EBX;
  if (!in_PF) {
    pbVar1 = (byte *)((int)((int)unaff_EBX + -0x2ffc0000) + (int)pcVar23);
    *pbVar1 = *pbVar1 | bVar6;
  }
  uVar15 = (uint)pcVar23 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(byte)pcVar23);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar17 = (uint)((uVar17 & 1) != 0);
  iVar16 = *(int *)(uVar15 + 4);
  puVar29 = puVar28 + iVar16 + -0x60 + uVar17;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar15 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar15 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
  if (in_PF) {
    uVar13 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar15 + 2),bVar8)
    ;
    uVar15 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar29 = puVar28 + iVar16 + -0x60 + (uint)((uVar15 & 1) != 0) + *(int *)(uVar13 + 4) + uVar17;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar13 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar15 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar15 + 0x4000003) = *(byte *)(uVar15 + 0x4000003) | bVar10;
  *pbVar20 = *pbVar20 << 1 | (char)*pbVar20 < 0;
  *(uint *)(puVar29 + -4) = uVar15;
  *(int *)(puVar29 + -8) = iParm3;
  *(byte **)(puVar29 + -0xc) = pbVar20;
  *(uint **)(puVar29 + -0x10) = unaff_EBX;
  *(undefined **)(puVar29 + -0x14) = puVar29;
  *(undefined4 **)(puVar29 + -0x18) = unaff_EBP;
  *(undefined **)(puVar29 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x20) = unaff_EDI;
  uVar13 = (uint)pbVar20 & 0xffffff00 | (uint)(byte)((char)pbVar20 + bVar7);
  iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
  *(int *)(puVar29 + -0x24) = iVar16;
  *(int *)(puVar29 + -0x28) = iParm3;
  *(uint *)(puVar29 + -0x2c) = uVar13;
  *(uint **)(puVar29 + -0x30) = unaff_EBX;
  *(undefined **)(puVar29 + -0x34) = puVar29 + -0x20;
  *(undefined4 **)(puVar29 + -0x38) = unaff_EBP;
  *(undefined **)(puVar29 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x40) = unaff_EDI;
  uVar13 = uVar13 + iParm3;
  piVar18 = (int *)(iVar16 - *(int *)(iVar16 + 9));
  *(byte *)piVar18 = *(char *)piVar18 + bVar26;
  *(byte *)((int)piVar18 + iParm3) = *(byte *)((int)piVar18 + iParm3) & (byte)piVar18;
  *(undefined4 *)(puVar29 + -0x44) = 0xb408077a;
  uVar17 = (int)piVar18 + *piVar18;
  pcVar23 = (char *)(uVar17 + uVar13 * 8);
  *pcVar23 = *pcVar23 + (char)uVar17;
  uVar15 = uVar17 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar17 >> 8) + *(char *)(uVar17 + 2),(char)uVar17);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar16 = *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar15 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  piVar18 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
  puVar3 = unaff_EDI + 1;
  uVar2 = in((short)uVar13);
  *unaff_EDI = uVar2;
  if (!in_PF) {
    piVar18 = (int *)((int)piVar18 + *piVar18);
    *(char *)(piVar18 + uVar13 * 2) = *(char *)(piVar18 + uVar13 * 2) + (char)piVar18;
  }
  uVar19 = (uint)piVar18 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)piVar18 >> 8) + *(char *)((int)piVar18 + 2),(char)piVar18);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  puVar4 = puVar29 + *(int *)(uVar19 + 4) + (uint)((uVar17 & 1) != 0) + iVar16 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar19 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar17 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
  cVar25 = (char)uVar13;
  if (SCARRY1((char)puVar12,'\b')) {
    uVar13 = uVar13 & 0xffffff00 | (uint)(byte)(cVar25 + bVar7);
    iVar16 = uVar17 - *(int *)(uVar17 + 0x13);
    *(int *)(puVar4 + (uVar15 - 4)) = iVar16;
    *(int *)(puVar4 + (uVar15 - 8)) = iParm3;
    *(uint *)(puVar4 + (uVar15 - 0xc)) = uVar13;
    *(uint **)(puVar4 + (uVar15 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar15)) = puVar4 + uVar15;
    *(undefined4 **)(puVar4 + (uVar15 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar15 - 0x1c)) = unaff_ESI;
    puVar30 = puVar4 + (uVar15 - 0x20);
    *(undefined **)(puVar4 + (uVar15 - 0x20)) = puVar3;
    uVar13 = uVar13 + iParm3;
    pbVar20 = (byte *)(iVar16 - *(int *)(iVar16 + 9));
    *pbVar20 = *pbVar20 + bVar26;
    pbVar20[iParm3] = pbVar20[iParm3] & (byte)pbVar20;
  }
  else {
    piVar18 = (int *)((uint)puVar12 & 0xffff0000 |
                     (uint)CONCAT11((byte)(((uint)puVar12 & 0xffffff00) >> 8) | bVar7,bVar8));
    uVar17 = (int)piVar18 + *piVar18;
    pcVar23 = (char *)(uVar17 + uVar13 * 8);
    *pcVar23 = *pcVar23 + (char)uVar17;
    uVar19 = uVar17 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar17 >> 8) + *(char *)(uVar17 + 2),(char)uVar17);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar17 = (uint)((uVar17 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar19 + 4) + uVar15 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar19 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar15 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if (bVar8 == 0) {
      uVar13 = uVar13 & 0xffffff00 | (uint)(byte)(cVar25 + bVar7);
      iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar4 + (uVar17 - 4)) = iVar16;
      *(int *)(puVar4 + (uVar17 - 8)) = iParm3;
      *(uint *)(puVar4 + (uVar17 - 0xc)) = uVar13;
      *(uint **)(puVar4 + (uVar17 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar17)) = puVar4 + uVar17;
      *(undefined4 **)(puVar4 + (uVar17 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x1c)) = unaff_ESI;
      puVar31 = puVar4 + (uVar17 - 0x20);
      *(undefined **)(puVar4 + (uVar17 - 0x20)) = puVar3;
      uVar13 = uVar13 + iParm3;
      pcVar23 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar23 = *pcVar23 + bVar26;
      pcVar23[iParm3] = pcVar23[iParm3] & (byte)pcVar23;
      goto code_r0x080429ec;
    }
    piVar18 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(bVar8 | bVar6));
    uVar15 = (int)piVar18 + *piVar18;
    pcVar23 = (char *)(uVar15 + uVar13 * 8);
    *pcVar23 = *pcVar23 + (char)uVar15;
    uVar19 = uVar15 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar15 >> 8) + *(char *)(uVar15 + 2),(char)uVar15);
    uVar15 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar15 = (uint)((uVar15 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar19 + 4) + uVar17 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar19 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar17 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if ((char)bVar8 < 0) {
      iVar16 = uVar17 - *(int *)(uVar17 + 0x13);
      *(int *)(puVar4 + (uVar15 - 4)) = iVar16;
      *(int *)(puVar4 + (uVar15 - 8)) = iParm3;
      *(uint *)(puVar4 + (uVar15 - 0xc)) = uVar13 & 0xffffff00 | (uint)(byte)(cVar25 + bVar7);
      *(uint **)(puVar4 + (uVar15 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar15 - 0x14)) = puVar4 + uVar15;
      *(undefined4 **)(puVar4 + (uVar15 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar15 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar15 - 0x20)) = puVar3;
      pcVar23 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar23 = *pcVar23 + bVar26;
      pcVar23[iParm3] = pcVar23[iParm3] & (byte)pcVar23;
      return;
    }
    piVar18 = (int *)((uint)puVar12 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8),bVar8));
    uVar17 = (int)piVar18 + *piVar18;
    pcVar23 = (char *)(uVar17 + uVar13 * 8);
    *pcVar23 = *pcVar23 + (char)uVar17;
    uVar19 = uVar17 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar17 >> 8) + *(char *)(uVar17 + 2),(char)uVar17);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar17 = (uint)((uVar17 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar19 + 4) + uVar15 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar19 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar15 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if (SCARRY1((char)puVar12,'\b') != (char)bVar8 < 0) {
      uVar13 = uVar13 & 0xffffff00 | (uint)(byte)(cVar25 + bVar7);
      iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar4 + (uVar17 - 4)) = iVar16;
      *(int *)(puVar4 + (uVar17 - 8)) = iParm3;
      *(uint *)(puVar4 + (uVar17 - 0xc)) = uVar13;
      *(uint **)(puVar4 + (uVar17 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar17 - 0x14)) = puVar4 + uVar17;
      *(undefined4 **)(puVar4 + (uVar17 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar17 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar17 - 0x20)) = puVar3;
      pbVar20 = (byte *)(uVar13 + iParm3);
      pcVar23 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar23 = *pcVar23 + bVar26;
      bVar8 = (byte)pcVar23;
      pcVar23[iParm3] = pcVar23[iParm3] & bVar8;
      if (!in_PF) {
        pcVar23[(int)(puVar4 + (uVar17 - 0x20))] = pcVar23[(int)(puVar4 + (uVar17 - 0x20))] | bVar10
        ;
        *pcVar23 = *pcVar23 + bVar8;
        pcVar23 = (char *)((uint)pcVar23 & 0xffffff00 | (uint)(byte)(bVar8 - 0x30));
      }
      uVar13 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
      bVar34 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar15 = (uint)bVar34;
      puVar4 = puVar4 + *(int *)(uVar13 + 4) + (uVar17 - 0x20);
      cVar25 = (char)puVar4 + bVar34;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      if (!in_PF) {
        puVar4[uVar15] = puVar4[uVar15] | bVar26;
        puVar4[(int)pbVar20 * 8 + uVar15] = puVar4[(int)pbVar20 * 8 + uVar15] + cVar25;
      }
      uVar15 = (uint)(puVar4 + uVar15) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar4 + uVar15) >> 8) + puVar4[uVar15 + 2],cVar25);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      iVar16 = ((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8)) + *(int *)(uVar15 + 4)
      ;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar15 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      uVar11 = (ushort)puVar12 & 0xff00 | (ushort)bVar8;
      iVar21 = (int)(short)uVar11;
      if (!in_PF) {
        pbVar1 = (byte *)(iVar16 + uVar17 + iVar21);
        *pbVar1 = *pbVar1 | bVar8;
        pcVar23 = (char *)(iVar21 + (int)pbVar20 * 8);
        *pcVar23 = *pcVar23 + bVar8;
      }
      iVar22 = CONCAT22((short)uVar11 >> 0xf,
                        CONCAT11((char)((uint)iVar21 >> 8) + *(char *)(iVar21 + 2),bVar8));
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar22 + 4);
      uVar13 = (uint)((uVar15 & 1) != 0);
      uVar15 = *puVar12;
      iVar21 = iVar16 + uVar17 + *puVar12;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar22 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar9 = (byte)puVar12;
      bVar8 = bVar9 + 8;
      pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
      *(uint *)(iVar21 + uVar13 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar9,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar8 < 0) * 0x80 |
           (uint)(bVar8 == 0) * 0x40 |
           (uint)(((iVar16 + uVar17 & 0xfffffff) + (uVar15 & 0xfffffff) + uVar13 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar9) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if (!in_PF) {
        pcVar23[4] = pcVar23[4] | (byte)pbVar20;
        *pcVar23 = *pcVar23 + bVar8;
        pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)(bVar9 - 0x28));
      }
      uVar15 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar16 = *(int *)(uVar15 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar15 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = DAT_5c08077a;
      uVar15 = (uint)puVar12 & 0xffffff00 | (uint)DAT_5c08077a;
      pcVar23 = (char *)(uVar15 + (int)pbVar20 * 8);
      *pcVar23 = *pcVar23 + DAT_5c08077a;
      uVar19 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)(uVar15 + 2),bVar8);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar22 = *(int *)(uVar19 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar19 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
      _DAT_03ffffc4 = unaff_EDI + 2;
      *puVar3 = *unaff_ESI;
      if (!in_PF) {
        pcVar23[4] = pcVar23[4] | bVar10;
        *pcVar23 = *pcVar23 + bVar8;
        pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
      }
      uVar14 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + pcVar23[2],(char)pcVar23);
      uVar19 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar19 = (uint)((uVar19 & 1) != 0);
      iVar16 = iVar21 + uVar13 + -4 + iVar16 + (uint)((uVar17 & 1) != 0) + iVar22 +
               (uint)((uVar15 & 1) != 0) + *(int *)(uVar14 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar14 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar10 = (char)puVar12 + 8;
      uVar17 = (uint)puVar12 & 0xffffff00 | (uint)bVar10;
      pbVar1 = (byte *)(iVar16 + uVar19 + 2 + uVar17);
      *pbVar1 = *pbVar1 | (byte)((uint)pbVar20 >> 8);
      pcVar23 = (char *)(uVar17 + (int)pbVar20 * 8);
      *pcVar23 = *pcVar23 + bVar10;
      uVar15 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar17 + 2),
                              bVar10);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      iVar16 = iVar16 + uVar19 + 2 + *(int *)(uVar15 + 4);
      puVar32 = (undefined *)(iVar16 + uVar17);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar15 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_03ffffc8 = unaff_ESI + 2;
      uVar15 = (uint)puVar12 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (in_PF) {
        uVar13 = (uint)puVar12 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)(uVar15 + 2),unaff_ESI[1]);
        uVar15 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar32 = (undefined *)(iVar16 + uVar17 + *(int *)(uVar13 + 4) + (uint)((uVar15 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar12 = (uint *)(uVar13 + 2);
        *puVar12 = *puVar12 | (uint)puVar12;
        uVar15 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      }
      *(byte *)(uVar15 + 0x4000004) = *(byte *)(uVar15 + 0x4000004) | (byte)uVar15;
      *pbVar20 = *pbVar20 << 1 | (char)*pbVar20 < 0;
      *(uint *)(puVar32 + -4) = uVar15;
      *(int *)(puVar32 + -8) = iParm3;
      *(byte **)(puVar32 + -0xc) = pbVar20;
      *(uint **)(puVar32 + -0x10) = unaff_EBX;
      *(undefined **)(puVar32 + -0x14) = puVar32;
      *(undefined4 **)(puVar32 + -0x18) = unaff_EBP;
      *(undefined **)(puVar32 + -0x1c) = _DAT_03ffffc8;
      *(undefined **)(puVar32 + -0x20) = _DAT_03ffffc4;
      uVar17 = (uint)pbVar20 & 0xffffff00 | (uint)(byte)((byte)pbVar20 + bVar7);
      iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar32 + -0x24) = iVar16;
      *(int *)(puVar32 + -0x28) = iParm3;
      *(uint *)(puVar32 + -0x2c) = uVar17;
      *(uint **)(puVar32 + -0x30) = unaff_EBX;
      *(undefined **)(puVar32 + -0x34) = puVar32 + -0x20;
      *(undefined4 **)(puVar32 + -0x38) = unaff_EBP;
      *(undefined **)(puVar32 + -0x3c) = _DAT_03ffffc8;
      *(undefined **)(puVar32 + -0x40) = _DAT_03ffffc4;
      pbVar20 = (byte *)(uVar17 + iParm3);
      pcVar23 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar23 = *pcVar23 + bVar26;
      pcVar23[iParm3] = pcVar23[iParm3] & (byte)pcVar23;
      iVar16 = CONCAT31((int3)((uint)pcVar23 >> 8),0x7a);
      puVar32[iVar16 + -0x2ffc003e] = puVar32[iVar16 + -0x2ffc003e] | bVar7;
      uVar15 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar23 >> 8) + *(char *)(iVar16 + 2),0x7a);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      puVar3 = puVar32 + *(int *)(uVar15 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar15 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      uVar15 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar12 + '\b');
      *(byte *)(uVar15 + 0x4000004) = *(byte *)(uVar15 + 0x4000004) | bVar6;
      *pbVar20 = *pbVar20 << 1 | (char)*pbVar20 < 0;
      *(uint *)(puVar3 + uVar17) = uVar15;
      *(int *)(puVar3 + (uVar17 - 4)) = iParm3;
      *(byte **)(puVar3 + (uVar17 - 8)) = pbVar20;
      *(uint **)(puVar3 + (uVar17 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar17 - 0x10)) = puVar3 + uVar17 + 4;
      *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar17)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar17 - 0x18)) = _DAT_03ffffc8;
      *(undefined **)(puVar3 + (uVar17 - 0x1c)) = _DAT_03ffffc4;
      uVar13 = (uint)pbVar20 & 0xffffff00 | (uint)(byte)((char)pbVar20 + bVar7);
      iVar16 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar3 + (uVar17 - 0x20)) = iVar16;
      *(int *)(puVar3 + (uVar17 - 0x24)) = iParm3;
      *(uint *)(puVar3 + (uVar17 - 0x28)) = uVar13;
      *(uint **)(puVar3 + (uVar17 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar17 - 0x30)) = puVar3 + (uVar17 - 0x1c);
      *(undefined4 **)(puVar3 + (uVar17 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar17 - 0x38)) = _DAT_03ffffc8;
      *(undefined **)(puVar3 + (uVar17 - 0x3c)) = _DAT_03ffffc4;
      _DAT_03fffff8 = (byte *)(uVar13 + iParm3);
      pcVar23 = (char *)(iVar16 - *(int *)(iVar16 + 9));
      *pcVar23 = *pcVar23 + bVar26;
      pcVar23[iParm3] = pcVar23[iParm3] & (byte)pcVar23;
      pcVar23 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
      *pcVar23 = *pcVar23 + 'z';
      cVar25 = DAT_a408077c + '\a';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar25,0x7a)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      uVar17 = (uint)puVar12 & 0xffffff00 | (uint)bVar6;
      pcVar23 = (char *)(uVar17 + (int)_DAT_03fffff8 * 8);
      *pcVar23 = *pcVar23 + bVar6;
      cVar25 = *(char *)(uVar17 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + cVar25,bVar6)) +
                        2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_04000000 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
      *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
      _DAT_03fffff0 = 0x4000004;
      _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar7);
      _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
      _DAT_03ffffd0 = &DAT_03ffffe4;
      iVar16 = _DAT_03ffffd8 + iParm3;
      pcVar24 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
      _DAT_03ffffcc = unaff_EBP;
      _DAT_03ffffd4 = unaff_EBX;
      _DAT_03ffffdc = iParm3;
      _DAT_03ffffe4 = _DAT_03ffffc4;
      _DAT_03ffffe8 = _DAT_03ffffc8;
      _DAT_03ffffec = unaff_EBP;
      _DAT_03fffff4 = unaff_EBX;
      _DAT_03fffffc = iParm3;
      *pcVar24 = *pcVar24 + bVar26;
      pcVar24[iParm3] = pcVar24[iParm3] & (byte)pcVar24;
      bVar7 = (byte)pcVar24 | bVar7;
      uVar17 = (uint)pcVar24 & 0xffffff00 | (uint)bVar7;
      pcVar23 = (char *)(uVar17 + iVar16 * 8);
      *pcVar23 = *pcVar23 + bVar7;
      uVar15 = (uint)pcVar24 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar24 & 0xffffff00) >> 8) + *(char *)(uVar17 + 2),
                              bVar7);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      iVar16 = *(int *)(uVar15 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar15 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      puVar33 = (undefined4 *)(iVar16 + uVar17 + 0x3ffffc0);
      *(undefined4 **)(iVar16 + uVar17 + 0x3ffffc0) = unaff_EBP;
      cVar25 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar33 = puVar33 + -1;
        *puVar33 = *unaff_EBP;
        cVar25 = cVar25 + -1;
      } while (0 < cVar25);
      *(uint *)(iVar16 + uVar17 + 0x3ffffa0) = iVar16 + uVar17 + 0x3ffffc0;
      uVar15 = (uint)CONCAT11(bVar6 / 4,bVar6) & 0xffffff00;
      uVar17 = (uint)puVar12 & 0xffff0000 | uVar15;
      pcVar23 = (char *)(uVar17 | (uint)bVar6 & 0xffffff04);
      cVar25 = (char)((uint)bVar6 & 0xffffff04);
      *pcVar23 = *pcVar23 + cVar25;
      bVar6 = cVar25 - 0x30;
      cVar25 = *(char *)((uVar17 | (uint)bVar6) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar15 >> 8) + cVar25,bVar6)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      pcVar5 = (code *)swi(3);
      (*pcVar5)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
      return;
    }
    piVar18 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)(bVar8 | (byte)(uVar13 >> 8)));
    uVar15 = (int)piVar18 + *piVar18;
    pcVar23 = (char *)(uVar15 + uVar13 * 8);
    *pcVar23 = *pcVar23 + (char)uVar15;
    uVar19 = uVar15 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar15 >> 8) + *(char *)(uVar15 + 2),(char)uVar15);
    uVar15 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar16 = *(int *)(uVar19 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar19 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    piVar18 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
    uVar19 = (int)piVar18 + *piVar18;
    pcVar23 = (char *)(uVar19 + uVar13 * 8);
    *pcVar23 = *pcVar23 + (char)uVar19;
    uVar14 = uVar19 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar19 >> 8) + *(char *)(uVar19 + 2),(char)uVar19);
    uVar19 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = puVar4 + (uint)((uVar19 & 1) != 0) +
                       *(int *)(uVar14 + 4) + (uint)((uVar15 & 1) != 0) + iVar16 + uVar17 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar14 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    pbVar20 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
  }
  *pbVar20 = *pbVar20 | bVar7;
  pbVar20[uVar13 * 8] = pbVar20[uVar13 * 8] + (char)pbVar20;
  uVar15 = (uint)pbVar20 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar20 >> 8) + pbVar20[2],(char)pbVar20);
  uVar17 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar31 = puVar30 + (uint)((uVar17 & 1) != 0) + *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar15 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  pcVar23 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
code_r0x080429ec:
  *(byte *)(uVar13 + 7) = bVar26;
  puVar31[(int)pcVar23] = puVar31[(int)pcVar23] | (byte)uVar13;
  *pcVar23 = *pcVar23 + (char)pcVar23;
  bVar6 = (char)pcVar23 - 0x30;
  cVar25 = *(char *)(((uint)pcVar23 & 0xffffff00 | (uint)bVar6) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(((uint)pcVar23 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar23 & 0xffffff00) >> 8) + cVar25,bVar6)) + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

char * strtok(char *__s,char *__delim)

{
  byte *pbVar1;
  undefined uVar2;
  undefined *puVar3;
  undefined *puVar4;
  code *pcVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  ushort uVar10;
  uint *puVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  int *piVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  byte *pbVar19;
  int iVar20;
  int iVar21;
  char *pcVar22;
  char cVar24;
  char *pcVar23;
  int in_ECX;
  byte bVar25;
  byte bVar26;
  uint *unaff_EBX;
  int iVar27;
  undefined *puVar28;
  undefined *puVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined *puVar32;
  undefined4 *puVar33;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar34;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar6 = (char)__s - 0x30;
  uVar16 = (uint)__s & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__s & 0xffffff00) >> 8) +
                          *(char *)(((uint)__s & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  iVar13 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar16 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  uVar16 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
  *(uint *)(&stack0x00000000 + iVar13 + (uVar14 - 4)) = uVar16;
  bVar9 = (byte)((uint)in_ECX >> 8);
  if (!in_PF) {
    *(byte *)((int)unaff_EBX + uVar16) = *(byte *)((int)unaff_EBX + uVar16) | bVar9;
    pcVar22 = (char *)(uVar16 + (int)__delim * 8);
    *pcVar22 = *pcVar22 + bVar6;
  }
  uVar12 = (uint)puVar11 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar16 + 2),bVar6);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar3 = &stack0x00000000 + iVar13 + *(int *)(uVar12 + 4) + (uVar14 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar12 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  pcVar22 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar6);
  *(undefined **)(puVar3 + (uVar16 - 4)) = puVar3 + uVar16;
  bVar26 = (byte)((uint)unaff_EBX >> 8);
  if (!in_PF) {
    pcVar22[3] = pcVar22[3] | bVar26;
    *pcVar22 = *pcVar22 + bVar6;
    pcVar22 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 - 0x28));
  }
  uVar12 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  iVar13 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar12 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  uVar12 = *(uint *)(puVar3 + iVar13 + (uVar16 - 4) + uVar14);
  if (!in_PF) {
    pbVar19 = (byte *)((int)unaff_EBX + uVar12 + 0xd0040000);
    *pbVar19 = *pbVar19 | (byte)uVar12;
  }
  uVar17 = uVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)(uVar12 + 2),(byte)uVar12);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar20 = *(int *)(uVar17 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar17 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar6 = (char)puVar11 + 8;
  uVar17 = (uint)puVar11 & 0xffffff00 | (uint)bVar6;
  iVar27 = *(int *)(puVar3 + iVar13 + (uVar16 - 4) + (uint)((uVar12 & 1) != 0) + iVar20 + uVar14 + 4
                   );
  puVar28 = (undefined *)(iVar27 + 4);
  if (in_PF) {
    uVar16 = (uint)puVar11 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar17 + 2),bVar6)
    ;
    uVar14 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar28 = (undefined *)(iVar27 + 4 + *(int *)(uVar16 + 4) + (uint)((uVar14 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar16 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    uVar17 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  }
  *(byte *)(uVar17 + 0x4000003) = *(byte *)(uVar17 + 0x4000003) | (byte)__delim;
  *__delim = *__delim << 1 | *__delim < 0;
  *(uint *)(puVar28 + -4) = uVar17;
  *(int *)(puVar28 + -8) = in_ECX;
  *(char **)(puVar28 + -0xc) = __delim;
  *(uint **)(puVar28 + -0x10) = unaff_EBX;
  *(undefined **)(puVar28 + -0x14) = puVar28;
  *(undefined4 **)(puVar28 + -0x18) = unaff_EBP;
  *(undefined **)(puVar28 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar28 + -0x20) = unaff_EDI;
  bVar6 = (byte)in_ECX;
  uVar14 = (uint)__delim & 0xffffff00 | (uint)(byte)((byte)__delim + bVar6);
  iVar13 = uVar17 - *(int *)(uVar17 + 0x13);
  *(int *)(puVar28 + -0x24) = iVar13;
  *(int *)(puVar28 + -0x28) = in_ECX;
  *(uint *)(puVar28 + -0x2c) = uVar14;
  *(uint **)(puVar28 + -0x30) = unaff_EBX;
  *(undefined **)(puVar28 + -0x34) = puVar28 + -0x20;
  *(undefined4 **)(puVar28 + -0x38) = unaff_EBP;
  *(undefined **)(puVar28 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar28 + -0x40) = unaff_EDI;
  pbVar19 = (byte *)(uVar14 + in_ECX);
  pcVar22 = (char *)(iVar13 - *(int *)(iVar13 + 9));
  *pcVar22 = *pcVar22 + bVar26;
  pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
  *(char **)(puVar28 + -0x44) = pcVar22;
  *(int *)(puVar28 + -0x48) = in_ECX;
  *(byte **)(puVar28 + -0x4c) = pbVar19;
  *(uint **)(puVar28 + -0x50) = unaff_EBX;
  *(undefined **)(puVar28 + -0x54) = puVar28 + -0x40;
  *(undefined4 **)(puVar28 + -0x58) = unaff_EBP;
  *(undefined **)(puVar28 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar28 + -0x60) = unaff_EDI;
  bVar25 = (byte)unaff_EBX;
  if (!in_PF) {
    pbVar1 = (byte *)((int)((int)unaff_EBX + -0x2ffc0000) + (int)pcVar22);
    *pbVar1 = *pbVar1 | bVar25;
  }
  uVar16 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(byte)pcVar22);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  iVar13 = *(int *)(uVar16 + 4);
  puVar29 = puVar28 + iVar13 + -0x60 + uVar14;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar16 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  uVar16 = (uint)puVar11 & 0xffffff00 | (uint)bVar7;
  if (in_PF) {
    uVar12 = (uint)puVar11 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar16 + 2),bVar7)
    ;
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar29 = puVar28 + iVar13 + -0x60 + (uint)((uVar16 & 1) != 0) + *(int *)(uVar12 + 4) + uVar14;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar12 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    uVar16 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
  }
  *(byte *)(uVar16 + 0x4000003) = *(byte *)(uVar16 + 0x4000003) | bVar9;
  *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
  *(uint *)(puVar29 + -4) = uVar16;
  *(int *)(puVar29 + -8) = in_ECX;
  *(byte **)(puVar29 + -0xc) = pbVar19;
  *(uint **)(puVar29 + -0x10) = unaff_EBX;
  *(undefined **)(puVar29 + -0x14) = puVar29;
  *(undefined4 **)(puVar29 + -0x18) = unaff_EBP;
  *(undefined **)(puVar29 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x20) = unaff_EDI;
  uVar12 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((char)pbVar19 + bVar6);
  iVar13 = uVar16 - *(int *)(uVar16 + 0x13);
  *(int *)(puVar29 + -0x24) = iVar13;
  *(int *)(puVar29 + -0x28) = in_ECX;
  *(uint *)(puVar29 + -0x2c) = uVar12;
  *(uint **)(puVar29 + -0x30) = unaff_EBX;
  *(undefined **)(puVar29 + -0x34) = puVar29 + -0x20;
  *(undefined4 **)(puVar29 + -0x38) = unaff_EBP;
  *(undefined **)(puVar29 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x40) = unaff_EDI;
  uVar12 = uVar12 + in_ECX;
  piVar15 = (int *)(iVar13 - *(int *)(iVar13 + 9));
  *(byte *)piVar15 = *(char *)piVar15 + bVar26;
  *(byte *)((int)piVar15 + in_ECX) = *(byte *)((int)piVar15 + in_ECX) & (byte)piVar15;
  *(undefined4 *)(puVar29 + -0x44) = 0xb408077a;
  uVar14 = (int)piVar15 + *piVar15;
  pcVar22 = (char *)(uVar14 + uVar12 * 8);
  *pcVar22 = *pcVar22 + (char)uVar14;
  uVar16 = uVar14 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar14 >> 8) + *(char *)(uVar14 + 2),(char)uVar14);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar13 = *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar16 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  piVar15 = (int *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
  puVar3 = unaff_EDI + 1;
  uVar2 = in((short)uVar12);
  *unaff_EDI = uVar2;
  if (!in_PF) {
    piVar15 = (int *)((int)piVar15 + *piVar15);
    *(char *)(piVar15 + uVar12 * 2) = *(char *)(piVar15 + uVar12 * 2) + (char)piVar15;
  }
  uVar17 = (uint)piVar15 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)piVar15 >> 8) + *(char *)((int)piVar15 + 2),(char)piVar15);
  uVar16 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar16 = (uint)((uVar16 & 1) != 0);
  puVar4 = puVar29 + *(int *)(uVar17 + 4) + (uint)((uVar14 & 1) != 0) + iVar13 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar17 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  bVar7 = (char)puVar11 + 8;
  uVar14 = (uint)puVar11 & 0xffffff00 | (uint)bVar7;
  cVar24 = (char)uVar12;
  if (SCARRY1((char)puVar11,'\b')) {
    uVar12 = uVar12 & 0xffffff00 | (uint)(byte)(cVar24 + bVar6);
    iVar13 = uVar14 - *(int *)(uVar14 + 0x13);
    *(int *)(puVar4 + (uVar16 - 4)) = iVar13;
    *(int *)(puVar4 + (uVar16 - 8)) = in_ECX;
    *(uint *)(puVar4 + (uVar16 - 0xc)) = uVar12;
    *(uint **)(puVar4 + (uVar16 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar16)) = puVar4 + uVar16;
    *(undefined4 **)(puVar4 + (uVar16 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar16 - 0x1c)) = unaff_ESI;
    puVar30 = puVar4 + (uVar16 - 0x20);
    *(undefined **)(puVar4 + (uVar16 - 0x20)) = puVar3;
    uVar12 = uVar12 + in_ECX;
    pbVar19 = (byte *)(iVar13 - *(int *)(iVar13 + 9));
    *pbVar19 = *pbVar19 + bVar26;
    pbVar19[in_ECX] = pbVar19[in_ECX] & (byte)pbVar19;
  }
  else {
    piVar15 = (int *)((uint)puVar11 & 0xffff0000 |
                     (uint)CONCAT11((byte)(((uint)puVar11 & 0xffffff00) >> 8) | bVar6,bVar7));
    uVar14 = (int)piVar15 + *piVar15;
    pcVar22 = (char *)(uVar14 + uVar12 * 8);
    *pcVar22 = *pcVar22 + (char)uVar14;
    uVar17 = uVar14 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar14 >> 8) + *(char *)(uVar14 + 2),(char)uVar14);
    uVar14 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar14 = (uint)((uVar14 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar17 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar17 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar7 = (char)puVar11 + 8;
    uVar16 = (uint)puVar11 & 0xffffff00 | (uint)bVar7;
    if (bVar7 == 0) {
      uVar12 = uVar12 & 0xffffff00 | (uint)(byte)(cVar24 + bVar6);
      iVar13 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar4 + (uVar14 - 4)) = iVar13;
      *(int *)(puVar4 + (uVar14 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar14 - 0xc)) = uVar12;
      *(uint **)(puVar4 + (uVar14 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar14)) = puVar4 + uVar14;
      *(undefined4 **)(puVar4 + (uVar14 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar14 - 0x1c)) = unaff_ESI;
      puVar31 = puVar4 + (uVar14 - 0x20);
      *(undefined **)(puVar4 + (uVar14 - 0x20)) = puVar3;
      uVar12 = uVar12 + in_ECX;
      pcVar22 = (char *)(iVar13 - *(int *)(iVar13 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
      goto code_r0x080429ec;
    }
    piVar15 = (int *)((uint)puVar11 & 0xffffff00 | (uint)(bVar7 | bVar25));
    uVar16 = (int)piVar15 + *piVar15;
    pcVar22 = (char *)(uVar16 + uVar12 * 8);
    *pcVar22 = *pcVar22 + (char)uVar16;
    uVar17 = uVar16 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(char)uVar16);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar16 = (uint)((uVar16 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar17 + 4) + uVar14 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar17 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar7 = (char)puVar11 + 8;
    uVar14 = (uint)puVar11 & 0xffffff00 | (uint)bVar7;
    if ((char)bVar7 < 0) {
      iVar13 = uVar14 - *(int *)(uVar14 + 0x13);
      *(int *)(puVar4 + (uVar16 - 4)) = iVar13;
      *(int *)(puVar4 + (uVar16 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar16 - 0xc)) = uVar12 & 0xffffff00 | (uint)(byte)(cVar24 + bVar6);
      *(uint **)(puVar4 + (uVar16 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar16 - 0x14)) = puVar4 + uVar16;
      *(undefined4 **)(puVar4 + (uVar16 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar16 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar16 - 0x20)) = puVar3;
      pcVar22 = (char *)(iVar13 - *(int *)(iVar13 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
      return;
    }
    piVar15 = (int *)((uint)puVar11 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8),bVar7));
    uVar14 = (int)piVar15 + *piVar15;
    pcVar22 = (char *)(uVar14 + uVar12 * 8);
    *pcVar22 = *pcVar22 + (char)uVar14;
    uVar17 = uVar14 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar14 >> 8) + *(char *)(uVar14 + 2),(char)uVar14);
    uVar14 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar14 = (uint)((uVar14 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar17 + 4) + uVar16 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar17 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    bVar7 = (char)puVar11 + 8;
    uVar16 = (uint)puVar11 & 0xffffff00 | (uint)bVar7;
    if (SCARRY1((char)puVar11,'\b') != (char)bVar7 < 0) {
      uVar12 = uVar12 & 0xffffff00 | (uint)(byte)(cVar24 + bVar6);
      iVar13 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar4 + (uVar14 - 4)) = iVar13;
      *(int *)(puVar4 + (uVar14 - 8)) = in_ECX;
      *(uint *)(puVar4 + (uVar14 - 0xc)) = uVar12;
      *(uint **)(puVar4 + (uVar14 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar14 - 0x14)) = puVar4 + uVar14;
      *(undefined4 **)(puVar4 + (uVar14 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar14 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar14 - 0x20)) = puVar3;
      pbVar19 = (byte *)(uVar12 + in_ECX);
      pcVar22 = (char *)(iVar13 - *(int *)(iVar13 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      bVar7 = (byte)pcVar22;
      pcVar22[in_ECX] = pcVar22[in_ECX] & bVar7;
      if (!in_PF) {
        pcVar22[(int)(puVar4 + (uVar14 - 0x20))] = pcVar22[(int)(puVar4 + (uVar14 - 0x20))] | bVar9;
        *pcVar22 = *pcVar22 + bVar7;
        pcVar22 = (char *)((uint)pcVar22 & 0xffffff00 | (uint)(byte)(bVar7 - 0x30));
      }
      uVar12 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      bVar34 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar16 = (uint)bVar34;
      puVar4 = puVar4 + *(int *)(uVar12 + 4) + (uVar14 - 0x20);
      cVar24 = (char)puVar4 + bVar34;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar12 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      if (!in_PF) {
        puVar4[uVar16] = puVar4[uVar16] | bVar26;
        puVar4[(int)pbVar19 * 8 + uVar16] = puVar4[(int)pbVar19 * 8 + uVar16] + cVar24;
      }
      uVar16 = (uint)(puVar4 + uVar16) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar4 + uVar16) >> 8) + puVar4[uVar16 + 2],cVar24);
      uVar14 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar14 = (uint)((uVar14 & 1) != 0);
      iVar13 = ((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8)) + *(int *)(uVar16 + 4)
      ;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar16 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar7 = (char)puVar11 + 8;
      uVar10 = (ushort)puVar11 & 0xff00 | (ushort)bVar7;
      iVar20 = (int)(short)uVar10;
      if (!in_PF) {
        pbVar1 = (byte *)(iVar13 + uVar14 + iVar20);
        *pbVar1 = *pbVar1 | bVar7;
        pcVar22 = (char *)(iVar20 + (int)pbVar19 * 8);
        *pcVar22 = *pcVar22 + bVar7;
      }
      iVar21 = CONCAT22((short)uVar10 >> 0xf,
                        CONCAT11((char)((uint)iVar20 >> 8) + *(char *)(iVar20 + 2),bVar7));
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(iVar21 + 4);
      uVar12 = (uint)((uVar16 & 1) != 0);
      uVar16 = *puVar11;
      iVar20 = iVar13 + uVar14 + *puVar11;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(iVar21 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar8 = (byte)puVar11;
      bVar7 = bVar8 + 8;
      pcVar22 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar7);
      *(uint *)(iVar20 + uVar12 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar8,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar7 < 0) * 0x80 |
           (uint)(bVar7 == 0) * 0x40 |
           (uint)(((iVar13 + uVar14 & 0xfffffff) + (uVar16 & 0xfffffff) + uVar12 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar8) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if (!in_PF) {
        pcVar22[4] = pcVar22[4] | (byte)pbVar19;
        *pcVar22 = *pcVar22 + bVar7;
        pcVar22 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)(bVar8 - 0x28));
      }
      uVar16 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      uVar14 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar13 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar16 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar7 = DAT_5c08077a;
      uVar16 = (uint)puVar11 & 0xffffff00 | (uint)DAT_5c08077a;
      pcVar22 = (char *)(uVar16 + (int)pbVar19 * 8);
      *pcVar22 = *pcVar22 + DAT_5c08077a;
      uVar17 = (uint)puVar11 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)(uVar16 + 2),bVar7);
      uVar16 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar21 = *(int *)(uVar17 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar17 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar7 = (char)puVar11 + 8;
      pcVar22 = (char *)((uint)puVar11 & 0xffffff00 | (uint)bVar7);
      _DAT_03ffffc4 = unaff_EDI + 2;
      *puVar3 = *unaff_ESI;
      if (!in_PF) {
        pcVar22[4] = pcVar22[4] | bVar9;
        *pcVar22 = *pcVar22 + bVar7;
        pcVar22 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 - 0x28));
      }
      uVar18 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      iVar13 = iVar20 + uVar12 + -4 + iVar13 + (uint)((uVar14 & 1) != 0) + iVar21 +
               (uint)((uVar16 & 1) != 0) + *(int *)(uVar18 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar18 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar9 = (char)puVar11 + 8;
      uVar14 = (uint)puVar11 & 0xffffff00 | (uint)bVar9;
      pbVar1 = (byte *)(iVar13 + uVar17 + 2 + uVar14);
      *pbVar1 = *pbVar1 | (byte)((uint)pbVar19 >> 8);
      pcVar22 = (char *)(uVar14 + (int)pbVar19 * 8);
      *pcVar22 = *pcVar22 + bVar9;
      uVar16 = (uint)puVar11 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),
                              bVar9);
      uVar14 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar14 = (uint)((uVar14 & 1) != 0);
      iVar13 = iVar13 + uVar17 + 2 + *(int *)(uVar16 + 4);
      puVar32 = (undefined *)(iVar13 + uVar14);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar16 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      _DAT_03ffffc8 = unaff_ESI + 2;
      uVar16 = (uint)puVar11 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (in_PF) {
        uVar12 = (uint)puVar11 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar11 >> 8) + *(char *)(uVar16 + 2),unaff_ESI[1]);
        uVar16 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar32 = (undefined *)(iVar13 + uVar14 + *(int *)(uVar12 + 4) + (uint)((uVar16 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar11 = (uint *)(uVar12 + 2);
        *puVar11 = *puVar11 | (uint)puVar11;
        uVar16 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
      }
      *(byte *)(uVar16 + 0x4000004) = *(byte *)(uVar16 + 0x4000004) | (byte)uVar16;
      *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
      *(uint *)(puVar32 + -4) = uVar16;
      *(int *)(puVar32 + -8) = in_ECX;
      *(byte **)(puVar32 + -0xc) = pbVar19;
      *(uint **)(puVar32 + -0x10) = unaff_EBX;
      *(undefined **)(puVar32 + -0x14) = puVar32;
      *(undefined4 **)(puVar32 + -0x18) = unaff_EBP;
      *(undefined **)(puVar32 + -0x1c) = _DAT_03ffffc8;
      *(undefined **)(puVar32 + -0x20) = _DAT_03ffffc4;
      uVar14 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((byte)pbVar19 + bVar6);
      iVar13 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar32 + -0x24) = iVar13;
      *(int *)(puVar32 + -0x28) = in_ECX;
      *(uint *)(puVar32 + -0x2c) = uVar14;
      *(uint **)(puVar32 + -0x30) = unaff_EBX;
      *(undefined **)(puVar32 + -0x34) = puVar32 + -0x20;
      *(undefined4 **)(puVar32 + -0x38) = unaff_EBP;
      *(undefined **)(puVar32 + -0x3c) = _DAT_03ffffc8;
      *(undefined **)(puVar32 + -0x40) = _DAT_03ffffc4;
      pbVar19 = (byte *)(uVar14 + in_ECX);
      pcVar22 = (char *)(iVar13 - *(int *)(iVar13 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
      iVar13 = CONCAT31((int3)((uint)pcVar22 >> 8),0x7a);
      puVar32[iVar13 + -0x2ffc003e] = puVar32[iVar13 + -0x2ffc003e] | bVar6;
      uVar16 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + *(char *)(iVar13 + 2),0x7a);
      uVar14 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar14 = (uint)((uVar14 & 1) != 0);
      puVar3 = puVar32 + *(int *)(uVar16 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar16 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      uVar16 = (uint)puVar11 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar11 + '\b');
      *(byte *)(uVar16 + 0x4000004) = *(byte *)(uVar16 + 0x4000004) | bVar25;
      *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
      *(uint *)(puVar3 + uVar14) = uVar16;
      *(int *)(puVar3 + (uVar14 - 4)) = in_ECX;
      *(byte **)(puVar3 + (uVar14 - 8)) = pbVar19;
      *(uint **)(puVar3 + (uVar14 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar14 - 0x10)) = puVar3 + uVar14 + 4;
      *(undefined4 **)(puVar3 + (int)(&DAT_ffffffec + uVar14)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar14 - 0x18)) = _DAT_03ffffc8;
      *(undefined **)(puVar3 + (uVar14 - 0x1c)) = _DAT_03ffffc4;
      uVar12 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((char)pbVar19 + bVar6);
      iVar13 = uVar16 - *(int *)(uVar16 + 0x13);
      *(int *)(puVar3 + (uVar14 - 0x20)) = iVar13;
      *(int *)(puVar3 + (uVar14 - 0x24)) = in_ECX;
      *(uint *)(puVar3 + (uVar14 - 0x28)) = uVar12;
      *(uint **)(puVar3 + (uVar14 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar3 + (uVar14 - 0x30)) = puVar3 + (uVar14 - 0x1c);
      *(undefined4 **)(puVar3 + (uVar14 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar3 + (uVar14 - 0x38)) = _DAT_03ffffc8;
      *(undefined **)(puVar3 + (uVar14 - 0x3c)) = _DAT_03ffffc4;
      _DAT_03fffff8 = (byte *)(uVar12 + in_ECX);
      pcVar22 = (char *)(iVar13 - *(int *)(iVar13 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      pcVar22[in_ECX] = pcVar22[in_ECX] & (byte)pcVar22;
      pcVar22 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
      *pcVar22 = *pcVar22 + 'z';
      cVar24 = DAT_a408077c + '\a';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar24,0x7a)) + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar9 = (char)puVar11 + 8;
      uVar14 = (uint)puVar11 & 0xffffff00 | (uint)bVar9;
      pcVar22 = (char *)(uVar14 + (int)_DAT_03fffff8 * 8);
      *pcVar22 = *pcVar22 + bVar9;
      cVar24 = *(char *)(uVar14 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar11 & 0xffffff00) >> 8) + cVar24,bVar9)) +
                        2);
      *puVar11 = *puVar11 | (uint)puVar11;
      _DAT_04000000 = (uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8);
      _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
      *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
      _DAT_03fffff0 = 0x4000004;
      _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar6);
      _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
      _DAT_03ffffd0 = &DAT_03ffffe4;
      iVar13 = _DAT_03ffffd8 + in_ECX;
      pcVar23 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
      _DAT_03ffffcc = unaff_EBP;
      _DAT_03ffffd4 = unaff_EBX;
      _DAT_03ffffdc = in_ECX;
      _DAT_03ffffe4 = _DAT_03ffffc4;
      _DAT_03ffffe8 = _DAT_03ffffc8;
      _DAT_03ffffec = unaff_EBP;
      _DAT_03fffff4 = unaff_EBX;
      _DAT_03fffffc = in_ECX;
      *pcVar23 = *pcVar23 + bVar26;
      pcVar23[in_ECX] = pcVar23[in_ECX] & (byte)pcVar23;
      bVar6 = (byte)pcVar23 | bVar6;
      uVar14 = (uint)pcVar23 & 0xffffff00 | (uint)bVar6;
      pcVar22 = (char *)(uVar14 + iVar13 * 8);
      *pcVar22 = *pcVar22 + bVar6;
      uVar16 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar23 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),
                              bVar6);
      uVar14 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar14 = (uint)((uVar14 & 1) != 0);
      iVar13 = *(int *)(uVar16 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(uVar16 + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      bVar6 = (char)puVar11 + 8;
      puVar33 = (undefined4 *)(iVar13 + uVar14 + 0x3ffffc0);
      *(undefined4 **)(iVar13 + uVar14 + 0x3ffffc0) = unaff_EBP;
      cVar24 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar33 = puVar33 + -1;
        *puVar33 = *unaff_EBP;
        cVar24 = cVar24 + -1;
      } while (0 < cVar24);
      *(uint *)(iVar13 + uVar14 + 0x3ffffa0) = iVar13 + uVar14 + 0x3ffffc0;
      uVar16 = (uint)CONCAT11(bVar6 / 4,bVar6) & 0xffffff00;
      uVar14 = (uint)puVar11 & 0xffff0000 | uVar16;
      pcVar22 = (char *)(uVar14 | (uint)bVar6 & 0xffffff04);
      cVar24 = (char)((uint)bVar6 & 0xffffff04);
      *pcVar22 = *pcVar22 + cVar24;
      bVar6 = cVar24 - 0x30;
      cVar24 = *(char *)((uVar14 | (uint)bVar6) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar11 = (uint *)(((uint)puVar11 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar16 >> 8) + cVar24,bVar6)) + 2);
      *puVar11 = *puVar11 | (uint)puVar11;
      pcVar5 = (code *)swi(3);
      pcVar22 = (char *)(*pcVar5)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
      return pcVar22;
    }
    piVar15 = (int *)((uint)puVar11 & 0xffffff00 | (uint)(byte)(bVar7 | (byte)(uVar12 >> 8)));
    uVar16 = (int)piVar15 + *piVar15;
    pcVar22 = (char *)(uVar16 + uVar12 * 8);
    *pcVar22 = *pcVar22 + (char)uVar16;
    uVar17 = uVar16 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar16 + 2),(char)uVar16);
    uVar16 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar13 = *(int *)(uVar17 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar17 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    piVar15 = (int *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
    uVar17 = (int)piVar15 + *piVar15;
    pcVar22 = (char *)(uVar17 + uVar12 * 8);
    *pcVar22 = *pcVar22 + (char)uVar17;
    uVar18 = uVar17 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar17 >> 8) + *(char *)(uVar17 + 2),(char)uVar17);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = puVar4 + (uint)((uVar17 & 1) != 0) +
                       *(int *)(uVar18 + 4) + (uint)((uVar16 & 1) != 0) + iVar13 + uVar14 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar11 = (uint *)(uVar18 + 2);
    *puVar11 = *puVar11 | (uint)puVar11;
    pbVar19 = (byte *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
  }
  *pbVar19 = *pbVar19 | bVar6;
  pbVar19[uVar12 * 8] = pbVar19[uVar12 * 8] + (char)pbVar19;
  uVar16 = (uint)pbVar19 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar19 >> 8) + pbVar19[2],(char)pbVar19);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar31 = puVar30 + (uint)((uVar14 & 1) != 0) + *(int *)(uVar16 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(uVar16 + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
  pcVar22 = (char *)((uint)puVar11 & 0xffffff00 | (uint)(byte)((char)puVar11 + 8));
code_r0x080429ec:
  *(byte *)(uVar12 + 7) = bVar26;
  puVar31[(int)pcVar22] = puVar31[(int)pcVar22] | (byte)uVar12;
  *pcVar22 = *pcVar22 + (char)pcVar22;
  bVar6 = (char)pcVar22 - 0x30;
  cVar24 = *(char *)(((uint)pcVar22 & 0xffffff00 | (uint)bVar6) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar11 = (uint *)(((uint)pcVar22 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar22 & 0xffffff00) >> 8) + cVar24,bVar6)) + 2);
  *puVar11 = *puVar11 | (uint)puVar11;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void ConnectAttach(uint uParm1,byte *pbParm2,int iParm3)

{
  byte *pbVar1;
  undefined *puVar2;
  undefined uVar3;
  undefined *puVar4;
  code *pcVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  ushort uVar11;
  uint *puVar12;
  uint uVar13;
  int iVar14;
  uint uVar15;
  int *piVar16;
  uint uVar17;
  uint uVar18;
  byte *pbVar19;
  int iVar20;
  int iVar21;
  char *pcVar22;
  char cVar24;
  char *pcVar23;
  uint uVar25;
  byte bVar26;
  uint *unaff_EBX;
  int iVar27;
  undefined *puVar28;
  undefined *puVar29;
  undefined *puVar30;
  undefined *puVar31;
  undefined *puVar32;
  undefined4 *puVar33;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar34;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  
  bVar6 = (char)uParm1 - 0x30;
  uVar13 = uParm1 & 0xffff0000 |
           (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                          *(char *)((uParm1 & 0xffffff00 | (uint)bVar6) + 2),bVar6);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  iVar14 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  uVar13 = *(uint *)(&stack0x00000000 + iVar14 + uVar15);
  if (!in_PF) {
    pbVar19 = (byte *)((int)unaff_EBX + uVar13 + 0xd0040000);
    *pbVar19 = *pbVar19 | (byte)uVar13;
  }
  uVar25 = uVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar13 + 2),(byte)uVar13);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar20 = *(int *)(uVar25 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar25 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar6 = (char)puVar12 + 8;
  uVar25 = (uint)puVar12 & 0xffffff00 | (uint)bVar6;
  iVar27 = *(int *)(&stack0x00000000 + iVar14 + (uint)((uVar13 & 1) != 0) + iVar20 + uVar15 + 4);
  puVar28 = (undefined *)(iVar27 + 4);
  if (in_PF) {
    uVar13 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar25 + 2),bVar6)
    ;
    uVar15 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar28 = (undefined *)(iVar27 + 4 + *(int *)(uVar13 + 4) + (uint)((uVar15 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar13 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar25 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  *(byte *)(uVar25 + 0x4000003) = *(byte *)(uVar25 + 0x4000003) | (byte)pbParm2;
  *pbParm2 = *pbParm2 << 1 | (char)*pbParm2 < 0;
  *(uint *)(puVar28 + -4) = uVar25;
  *(int *)(puVar28 + -8) = iParm3;
  *(byte **)(puVar28 + -0xc) = pbParm2;
  *(uint **)(puVar28 + -0x10) = unaff_EBX;
  *(undefined **)(puVar28 + -0x14) = puVar28;
  *(undefined4 **)(puVar28 + -0x18) = unaff_EBP;
  *(undefined **)(puVar28 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar28 + -0x20) = unaff_EDI;
  bVar6 = (byte)iParm3;
  uVar15 = (uint)pbParm2 & 0xffffff00 | (uint)(byte)((byte)pbParm2 + bVar6);
  iVar14 = uVar25 - *(int *)(uVar25 + 0x13);
  *(int *)(puVar28 + -0x24) = iVar14;
  *(int *)(puVar28 + -0x28) = iParm3;
  *(uint *)(puVar28 + -0x2c) = uVar15;
  *(uint **)(puVar28 + -0x30) = unaff_EBX;
  *(undefined **)(puVar28 + -0x34) = puVar28 + -0x20;
  *(undefined4 **)(puVar28 + -0x38) = unaff_EBP;
  *(undefined **)(puVar28 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar28 + -0x40) = unaff_EDI;
  pbVar19 = (byte *)(uVar15 + iParm3);
  pcVar22 = (char *)(iVar14 - *(int *)(iVar14 + 9));
  bVar26 = (byte)((uint)unaff_EBX >> 8);
  *pcVar22 = *pcVar22 + bVar26;
  pcVar22[iParm3] = pcVar22[iParm3] & (byte)pcVar22;
  *(char **)(puVar28 + -0x44) = pcVar22;
  *(int *)(puVar28 + -0x48) = iParm3;
  *(byte **)(puVar28 + -0x4c) = pbVar19;
  *(uint **)(puVar28 + -0x50) = unaff_EBX;
  *(undefined **)(puVar28 + -0x54) = puVar28 + -0x40;
  *(undefined4 **)(puVar28 + -0x58) = unaff_EBP;
  *(undefined **)(puVar28 + -0x5c) = unaff_ESI;
  *(undefined **)(puVar28 + -0x60) = unaff_EDI;
  bVar10 = (byte)unaff_EBX;
  if (!in_PF) {
    pbVar1 = (byte *)((int)((int)unaff_EBX + -0x2ffc0000) + (int)pcVar22);
    *pbVar1 = *pbVar1 | bVar10;
  }
  uVar13 = (uint)pcVar22 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(byte)pcVar22);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  iVar14 = *(int *)(uVar13 + 4);
  puVar29 = puVar28 + iVar14 + -0x60 + uVar15;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar7 = (char)puVar12 + 8;
  uVar13 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
  if (in_PF) {
    uVar25 = (uint)puVar12 & 0xffff0000 |
             (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar13 + 2),bVar7)
    ;
    uVar13 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar29 = puVar28 + iVar14 + -0x60 + (uint)((uVar13 & 1) != 0) + *(int *)(uVar25 + 4) + uVar15;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar25 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    uVar13 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
  }
  bVar7 = (byte)((uint)iParm3 >> 8);
  *(byte *)(uVar13 + 0x4000003) = *(byte *)(uVar13 + 0x4000003) | bVar7;
  *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
  *(uint *)(puVar29 + -4) = uVar13;
  *(int *)(puVar29 + -8) = iParm3;
  *(byte **)(puVar29 + -0xc) = pbVar19;
  *(uint **)(puVar29 + -0x10) = unaff_EBX;
  *(undefined **)(puVar29 + -0x14) = puVar29;
  *(undefined4 **)(puVar29 + -0x18) = unaff_EBP;
  *(undefined **)(puVar29 + -0x1c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x20) = unaff_EDI;
  uVar25 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((char)pbVar19 + bVar6);
  iVar14 = uVar13 - *(int *)(uVar13 + 0x13);
  *(int *)(puVar29 + -0x24) = iVar14;
  *(int *)(puVar29 + -0x28) = iParm3;
  *(uint *)(puVar29 + -0x2c) = uVar25;
  *(uint **)(puVar29 + -0x30) = unaff_EBX;
  *(undefined **)(puVar29 + -0x34) = puVar29 + -0x20;
  *(undefined4 **)(puVar29 + -0x38) = unaff_EBP;
  *(undefined **)(puVar29 + -0x3c) = unaff_ESI;
  *(undefined **)(puVar29 + -0x40) = unaff_EDI;
  uVar25 = uVar25 + iParm3;
  piVar16 = (int *)(iVar14 - *(int *)(iVar14 + 9));
  *(byte *)piVar16 = *(char *)piVar16 + bVar26;
  *(byte *)((int)piVar16 + iParm3) = *(byte *)((int)piVar16 + iParm3) & (byte)piVar16;
  *(undefined4 *)(puVar29 + -0x44) = 0xb408077a;
  uVar15 = (int)piVar16 + *piVar16;
  pcVar22 = (char *)(uVar15 + uVar25 * 8);
  *pcVar22 = *pcVar22 + (char)uVar15;
  uVar13 = uVar15 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar15 >> 8) + *(char *)(uVar15 + 2),(char)uVar15);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar14 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  piVar16 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
  puVar2 = unaff_EDI + 1;
  uVar3 = in((short)uVar25);
  *unaff_EDI = uVar3;
  if (!in_PF) {
    piVar16 = (int *)((int)piVar16 + *piVar16);
    *(char *)(piVar16 + uVar25 * 2) = *(char *)(piVar16 + uVar25 * 2) + (char)piVar16;
  }
  uVar17 = (uint)piVar16 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)piVar16 >> 8) + *(char *)((int)piVar16 + 2),(char)piVar16);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar13 & 1) != 0);
  puVar4 = puVar29 + *(int *)(uVar17 + 4) + (uint)((uVar15 & 1) != 0) + iVar14 + -0x44;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar17 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  bVar8 = (char)puVar12 + 8;
  uVar15 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
  cVar24 = (char)uVar25;
  if (SCARRY1((char)puVar12,'\b')) {
    uVar25 = uVar25 & 0xffffff00 | (uint)(byte)(cVar24 + bVar6);
    iVar14 = uVar15 - *(int *)(uVar15 + 0x13);
    *(int *)(puVar4 + (uVar13 - 4)) = iVar14;
    *(int *)(puVar4 + (uVar13 - 8)) = iParm3;
    *(uint *)(puVar4 + (uVar13 - 0xc)) = uVar25;
    *(uint **)(puVar4 + (uVar13 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar13)) = puVar4 + uVar13;
    *(undefined4 **)(puVar4 + (uVar13 - 0x18)) = unaff_EBP;
    *(undefined **)(puVar4 + (uVar13 - 0x1c)) = unaff_ESI;
    puVar30 = puVar4 + (uVar13 - 0x20);
    *(undefined **)(puVar4 + (uVar13 - 0x20)) = puVar2;
    uVar25 = uVar25 + iParm3;
    pbVar19 = (byte *)(iVar14 - *(int *)(iVar14 + 9));
    *pbVar19 = *pbVar19 + bVar26;
    pbVar19[iParm3] = pbVar19[iParm3] & (byte)pbVar19;
  }
  else {
    piVar16 = (int *)((uint)puVar12 & 0xffff0000 |
                     (uint)CONCAT11((byte)(((uint)puVar12 & 0xffffff00) >> 8) | bVar6,bVar8));
    uVar15 = (int)piVar16 + *piVar16;
    pcVar22 = (char *)(uVar15 + uVar25 * 8);
    *pcVar22 = *pcVar22 + (char)uVar15;
    uVar17 = uVar15 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar15 >> 8) + *(char *)(uVar15 + 2),(char)uVar15);
    uVar15 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar15 = (uint)((uVar15 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar17 + 4) + uVar13 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar17 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar13 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if (bVar8 == 0) {
      uVar25 = uVar25 & 0xffffff00 | (uint)(byte)(cVar24 + bVar6);
      iVar14 = uVar13 - *(int *)(uVar13 + 0x13);
      *(int *)(puVar4 + (uVar15 - 4)) = iVar14;
      *(int *)(puVar4 + (uVar15 - 8)) = iParm3;
      *(uint *)(puVar4 + (uVar15 - 0xc)) = uVar25;
      *(uint **)(puVar4 + (uVar15 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (int)(&DAT_ffffffec + uVar15)) = puVar4 + uVar15;
      *(undefined4 **)(puVar4 + (uVar15 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar15 - 0x1c)) = unaff_ESI;
      puVar31 = puVar4 + (uVar15 - 0x20);
      *(undefined **)(puVar4 + (uVar15 - 0x20)) = puVar2;
      uVar25 = uVar25 + iParm3;
      pcVar22 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      pcVar22[iParm3] = pcVar22[iParm3] & (byte)pcVar22;
      goto code_r0x080429ec;
    }
    piVar16 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(bVar8 | bVar10));
    uVar13 = (int)piVar16 + *piVar16;
    pcVar22 = (char *)(uVar13 + uVar25 * 8);
    *pcVar22 = *pcVar22 + (char)uVar13;
    uVar17 = uVar13 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar13 + 2),(char)uVar13);
    uVar13 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar13 = (uint)((uVar13 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar17 + 4) + uVar15 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar17 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar15 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if ((char)bVar8 < 0) {
      iVar14 = uVar15 - *(int *)(uVar15 + 0x13);
      *(int *)(puVar4 + (uVar13 - 4)) = iVar14;
      *(int *)(puVar4 + (uVar13 - 8)) = iParm3;
      *(uint *)(puVar4 + (uVar13 - 0xc)) = uVar25 & 0xffffff00 | (uint)(byte)(cVar24 + bVar6);
      *(uint **)(puVar4 + (uVar13 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar13 - 0x14)) = puVar4 + uVar13;
      *(undefined4 **)(puVar4 + (uVar13 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar13 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar13 - 0x20)) = puVar2;
      pcVar22 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      pcVar22[iParm3] = pcVar22[iParm3] & (byte)pcVar22;
      return;
    }
    piVar16 = (int *)((uint)puVar12 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8),bVar8));
    uVar15 = (int)piVar16 + *piVar16;
    pcVar22 = (char *)(uVar15 + uVar25 * 8);
    *pcVar22 = *pcVar22 + (char)uVar15;
    uVar17 = uVar15 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar15 >> 8) + *(char *)(uVar15 + 2),(char)uVar15);
    uVar15 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    uVar15 = (uint)((uVar15 & 1) != 0);
    puVar4 = puVar4 + *(int *)(uVar17 + 4) + uVar13 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar17 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    bVar8 = (char)puVar12 + 8;
    uVar13 = (uint)puVar12 & 0xffffff00 | (uint)bVar8;
    if (SCARRY1((char)puVar12,'\b') != (char)bVar8 < 0) {
      uVar25 = uVar25 & 0xffffff00 | (uint)(byte)(cVar24 + bVar6);
      iVar14 = uVar13 - *(int *)(uVar13 + 0x13);
      *(int *)(puVar4 + (uVar15 - 4)) = iVar14;
      *(int *)(puVar4 + (uVar15 - 8)) = iParm3;
      *(uint *)(puVar4 + (uVar15 - 0xc)) = uVar25;
      *(uint **)(puVar4 + (uVar15 - 0x10)) = unaff_EBX;
      *(undefined **)(puVar4 + (uVar15 - 0x14)) = puVar4 + uVar15;
      *(undefined4 **)(puVar4 + (uVar15 - 0x18)) = unaff_EBP;
      *(undefined **)(puVar4 + (uVar15 - 0x1c)) = unaff_ESI;
      *(undefined **)(puVar4 + (uVar15 - 0x20)) = puVar2;
      pbVar19 = (byte *)(uVar25 + iParm3);
      pcVar22 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      bVar8 = (byte)pcVar22;
      pcVar22[iParm3] = pcVar22[iParm3] & bVar8;
      if (!in_PF) {
        pcVar22[(int)(puVar4 + (uVar15 - 0x20))] = pcVar22[(int)(puVar4 + (uVar15 - 0x20))] | bVar7;
        *pcVar22 = *pcVar22 + bVar8;
        pcVar22 = (char *)((uint)pcVar22 & 0xffffff00 | (uint)(byte)(bVar8 - 0x30));
      }
      uVar25 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      bVar34 = (*unaff_EBX & 1) != 0;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar13 = (uint)bVar34;
      puVar4 = puVar4 + *(int *)(uVar25 + 4) + (uVar15 - 0x20);
      cVar24 = (char)puVar4 + bVar34;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar25 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      if (!in_PF) {
        puVar4[uVar13] = puVar4[uVar13] | bVar26;
        puVar4[(int)pbVar19 * 8 + uVar13] = puVar4[(int)pbVar19 * 8 + uVar13] + cVar24;
      }
      uVar13 = (uint)(puVar4 + uVar13) & 0xffff0000 |
               (uint)CONCAT11((char)((uint)(puVar4 + uVar13) >> 8) + puVar4[uVar13 + 2],cVar24);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar15 = (uint)((uVar15 & 1) != 0);
      iVar14 = ((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8)) + *(int *)(uVar13 + 4)
      ;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      uVar11 = (ushort)puVar12 & 0xff00 | (ushort)bVar8;
      iVar20 = (int)(short)uVar11;
      if (!in_PF) {
        pbVar1 = (byte *)(iVar14 + uVar15 + iVar20);
        *pbVar1 = *pbVar1 | bVar8;
        pcVar22 = (char *)(iVar20 + (int)pbVar19 * 8);
        *pcVar22 = *pcVar22 + bVar8;
      }
      iVar21 = CONCAT22((short)uVar11 >> 0xf,
                        CONCAT11((char)((uint)iVar20 >> 8) + *(char *)(iVar20 + 2),bVar8));
      uVar13 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar21 + 4);
      uVar25 = (uint)((uVar13 & 1) != 0);
      uVar13 = *puVar12;
      iVar20 = iVar14 + uVar15 + *puVar12;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(iVar21 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar9 = (byte)puVar12;
      bVar8 = bVar9 + 8;
      pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
      *(uint *)(iVar20 + uVar25 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar9,'\b') * 0x800 |
           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar8 < 0) * 0x80 |
           (uint)(bVar8 == 0) * 0x40 |
           (uint)(((iVar14 + uVar15 & 0xfffffff) + (uVar13 & 0xfffffff) + uVar25 & 0x10000000) != 0)
           * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar9) | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      if (!in_PF) {
        pcVar22[4] = pcVar22[4] | (byte)pbVar19;
        *pcVar22 = *pcVar22 + bVar8;
        pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)(bVar9 - 0x28));
      }
      uVar13 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar14 = *(int *)(uVar13 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = DAT_5c08077a;
      uVar13 = (uint)puVar12 & 0xffffff00 | (uint)DAT_5c08077a;
      pcVar22 = (char *)(uVar13 + (int)pbVar19 * 8);
      *pcVar22 = *pcVar22 + DAT_5c08077a;
      uVar17 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)(uVar13 + 2),bVar8);
      uVar13 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      iVar21 = *(int *)(uVar17 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar17 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar8 = (char)puVar12 + 8;
      pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)bVar8);
      _DAT_03ffffc4 = unaff_EDI + 2;
      *puVar2 = *unaff_ESI;
      if (!in_PF) {
        pcVar22[4] = pcVar22[4] | bVar7;
        *pcVar22 = *pcVar22 + bVar8;
        pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 - 0x28));
      }
      uVar18 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + pcVar22[2],(char)pcVar22);
      uVar17 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar17 = (uint)((uVar17 & 1) != 0);
      iVar14 = iVar20 + uVar25 + -4 + iVar14 + (uint)((uVar15 & 1) != 0) + iVar21 +
               (uint)((uVar13 & 1) != 0) + *(int *)(uVar18 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar18 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar7 = (char)puVar12 + 8;
      uVar15 = (uint)puVar12 & 0xffffff00 | (uint)bVar7;
      pbVar1 = (byte *)(iVar14 + uVar17 + 2 + uVar15);
      *pbVar1 = *pbVar1 | (byte)((uint)pbVar19 >> 8);
      pcVar22 = (char *)(uVar15 + (int)pbVar19 * 8);
      *pcVar22 = *pcVar22 + bVar7;
      uVar13 = (uint)puVar12 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + *(char *)(uVar15 + 2),
                              bVar7);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar15 = (uint)((uVar15 & 1) != 0);
      iVar14 = iVar14 + uVar17 + 2 + *(int *)(uVar13 + 4);
      puVar32 = (undefined *)(iVar14 + uVar15);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_03ffffc8 = unaff_ESI + 2;
      uVar13 = (uint)puVar12 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
      if (in_PF) {
        uVar25 = (uint)puVar12 & 0xffff0000 |
                 (uint)CONCAT11((char)((uint)puVar12 >> 8) + *(char *)(uVar13 + 2),unaff_ESI[1]);
        uVar13 = *unaff_EBX;
        *unaff_EBX = *unaff_EBX >> 1;
        puVar32 = (undefined *)(iVar14 + uVar15 + *(int *)(uVar25 + 4) + (uint)((uVar13 & 1) != 0));
        *unaff_EBX = *unaff_EBX >> 1;
        puVar12 = (uint *)(uVar25 + 2);
        *puVar12 = *puVar12 | (uint)puVar12;
        uVar13 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      }
      *(byte *)(uVar13 + 0x4000004) = *(byte *)(uVar13 + 0x4000004) | (byte)uVar13;
      *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
      *(uint *)(puVar32 + -4) = uVar13;
      *(int *)(puVar32 + -8) = iParm3;
      *(byte **)(puVar32 + -0xc) = pbVar19;
      *(uint **)(puVar32 + -0x10) = unaff_EBX;
      *(undefined **)(puVar32 + -0x14) = puVar32;
      *(undefined4 **)(puVar32 + -0x18) = unaff_EBP;
      *(undefined **)(puVar32 + -0x1c) = _DAT_03ffffc8;
      *(undefined **)(puVar32 + -0x20) = _DAT_03ffffc4;
      uVar15 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((byte)pbVar19 + bVar6);
      iVar14 = uVar13 - *(int *)(uVar13 + 0x13);
      *(int *)(puVar32 + -0x24) = iVar14;
      *(int *)(puVar32 + -0x28) = iParm3;
      *(uint *)(puVar32 + -0x2c) = uVar15;
      *(uint **)(puVar32 + -0x30) = unaff_EBX;
      *(undefined **)(puVar32 + -0x34) = puVar32 + -0x20;
      *(undefined4 **)(puVar32 + -0x38) = unaff_EBP;
      *(undefined **)(puVar32 + -0x3c) = _DAT_03ffffc8;
      *(undefined **)(puVar32 + -0x40) = _DAT_03ffffc4;
      pbVar19 = (byte *)(uVar15 + iParm3);
      pcVar22 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      pcVar22[iParm3] = pcVar22[iParm3] & (byte)pcVar22;
      iVar14 = CONCAT31((int3)((uint)pcVar22 >> 8),0x7a);
      puVar32[iVar14 + -0x2ffc003e] = puVar32[iVar14 + -0x2ffc003e] | bVar6;
      uVar13 = (uint)pcVar22 & 0xffff0000 |
               (uint)CONCAT11((char)((uint)pcVar22 >> 8) + *(char *)(iVar14 + 2),0x7a);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar15 = (uint)((uVar15 & 1) != 0);
      puVar2 = puVar32 + *(int *)(uVar13 + 4) + -0x40;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      uVar13 = (uint)puVar12 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar12 + '\b');
      *(byte *)(uVar13 + 0x4000004) = *(byte *)(uVar13 + 0x4000004) | bVar10;
      *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
      *(uint *)(puVar2 + uVar15) = uVar13;
      *(int *)(puVar2 + (uVar15 - 4)) = iParm3;
      *(byte **)(puVar2 + (uVar15 - 8)) = pbVar19;
      *(uint **)(puVar2 + (uVar15 - 0xc)) = unaff_EBX;
      *(undefined **)(puVar2 + (uVar15 - 0x10)) = puVar2 + uVar15 + 4;
      *(undefined4 **)(puVar2 + (int)(&DAT_ffffffec + uVar15)) = unaff_EBP;
      *(undefined **)(puVar2 + (uVar15 - 0x18)) = _DAT_03ffffc8;
      *(undefined **)(puVar2 + (uVar15 - 0x1c)) = _DAT_03ffffc4;
      uVar25 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((char)pbVar19 + bVar6);
      iVar14 = uVar13 - *(int *)(uVar13 + 0x13);
      *(int *)(puVar2 + (uVar15 - 0x20)) = iVar14;
      *(int *)(puVar2 + (uVar15 - 0x24)) = iParm3;
      *(uint *)(puVar2 + (uVar15 - 0x28)) = uVar25;
      *(uint **)(puVar2 + (uVar15 - 0x2c)) = unaff_EBX;
      *(undefined **)(puVar2 + (uVar15 - 0x30)) = puVar2 + (uVar15 - 0x1c);
      *(undefined4 **)(puVar2 + (uVar15 - 0x34)) = unaff_EBP;
      *(undefined **)(puVar2 + (uVar15 - 0x38)) = _DAT_03ffffc8;
      *(undefined **)(puVar2 + (uVar15 - 0x3c)) = _DAT_03ffffc4;
      _DAT_03fffff8 = (byte *)(uVar25 + iParm3);
      pcVar22 = (char *)(iVar14 - *(int *)(iVar14 + 9));
      *pcVar22 = *pcVar22 + bVar26;
      pcVar22[iParm3] = pcVar22[iParm3] & (byte)pcVar22;
      pcVar22 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
      *pcVar22 = *pcVar22 + 'z';
      cVar24 = DAT_a408077c + '\a';
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar24,0x7a)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar10 = (char)puVar12 + 8;
      uVar15 = (uint)puVar12 & 0xffffff00 | (uint)bVar10;
      pcVar22 = (char *)(uVar15 + (int)_DAT_03fffff8 * 8);
      *pcVar22 = *pcVar22 + bVar10;
      cVar24 = *(char *)(uVar15 + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(((uint)puVar12 & 0xffffff00) >> 8) + cVar24,bVar10))
                        + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      _DAT_04000000 = (uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8);
      _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
      *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
      _DAT_03fffff0 = 0x4000004;
      _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar6);
      _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
      _DAT_03ffffd0 = &DAT_03ffffe4;
      iVar14 = _DAT_03ffffd8 + iParm3;
      pcVar23 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
      _DAT_03ffffcc = unaff_EBP;
      _DAT_03ffffd4 = unaff_EBX;
      _DAT_03ffffdc = iParm3;
      _DAT_03ffffe4 = _DAT_03ffffc4;
      _DAT_03ffffe8 = _DAT_03ffffc8;
      _DAT_03ffffec = unaff_EBP;
      _DAT_03fffff4 = unaff_EBX;
      _DAT_03fffffc = iParm3;
      *pcVar23 = *pcVar23 + bVar26;
      pcVar23[iParm3] = pcVar23[iParm3] & (byte)pcVar23;
      bVar6 = (byte)pcVar23 | bVar6;
      uVar15 = (uint)pcVar23 & 0xffffff00 | (uint)bVar6;
      pcVar22 = (char *)(uVar15 + iVar14 * 8);
      *pcVar22 = *pcVar22 + bVar6;
      uVar13 = (uint)pcVar23 & 0xffff0000 |
               (uint)CONCAT11((char)(((uint)pcVar23 & 0xffffff00) >> 8) + *(char *)(uVar15 + 2),
                              bVar6);
      uVar15 = *unaff_EBX;
      *unaff_EBX = *unaff_EBX >> 1;
      uVar15 = (uint)((uVar15 & 1) != 0);
      iVar14 = *(int *)(uVar13 + 4);
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(uVar13 + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      bVar6 = (char)puVar12 + 8;
      puVar33 = (undefined4 *)(iVar14 + uVar15 + 0x3ffffc0);
      *(undefined4 **)(iVar14 + uVar15 + 0x3ffffc0) = unaff_EBP;
      cVar24 = '\a';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar33 = puVar33 + -1;
        *puVar33 = *unaff_EBP;
        cVar24 = cVar24 + -1;
      } while (0 < cVar24);
      *(uint *)(iVar14 + uVar15 + 0x3ffffa0) = iVar14 + uVar15 + 0x3ffffc0;
      uVar13 = (uint)CONCAT11(bVar6 / 4,bVar6) & 0xffffff00;
      uVar15 = (uint)puVar12 & 0xffff0000 | uVar13;
      pcVar22 = (char *)(uVar15 | (uint)bVar6 & 0xffffff04);
      cVar24 = (char)((uint)bVar6 & 0xffffff04);
      *pcVar22 = *pcVar22 + cVar24;
      bVar6 = cVar24 - 0x30;
      cVar24 = *(char *)((uVar15 | (uint)bVar6) + 2);
      *unaff_EBX = *unaff_EBX >> 1;
      *unaff_EBX = *unaff_EBX >> 1;
      puVar12 = (uint *)(((uint)puVar12 & 0xffff0000 |
                         (uint)CONCAT11((char)(uVar13 >> 8) + cVar24,bVar6)) + 2);
      *puVar12 = *puVar12 | (uint)puVar12;
      pcVar5 = (code *)swi(3);
      (*pcVar5)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
      return;
    }
    piVar16 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)(bVar8 | (byte)(uVar25 >> 8)));
    uVar13 = (int)piVar16 + *piVar16;
    pcVar22 = (char *)(uVar13 + uVar25 * 8);
    *pcVar22 = *pcVar22 + (char)uVar13;
    uVar17 = uVar13 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar13 + 2),(char)uVar13);
    uVar13 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar14 = *(int *)(uVar17 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar17 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    piVar16 = (int *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
    uVar17 = (int)piVar16 + *piVar16;
    pcVar22 = (char *)(uVar17 + uVar25 * 8);
    *pcVar22 = *pcVar22 + (char)uVar17;
    uVar18 = uVar17 & 0xffff0000 |
             (uint)CONCAT11((char)(uVar17 >> 8) + *(char *)(uVar17 + 2),(char)uVar17);
    uVar17 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar30 = puVar4 + (uint)((uVar17 & 1) != 0) +
                       *(int *)(uVar18 + 4) + (uint)((uVar13 & 1) != 0) + iVar14 + uVar15 + 2;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar12 = (uint *)(uVar18 + 2);
    *puVar12 = *puVar12 | (uint)puVar12;
    pbVar19 = (byte *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
  }
  *pbVar19 = *pbVar19 | bVar6;
  pbVar19[uVar25 * 8] = pbVar19[uVar25 * 8] + (char)pbVar19;
  uVar13 = (uint)pbVar19 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar19 >> 8) + pbVar19[2],(char)pbVar19);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar31 = puVar30 + (uint)((uVar15 & 1) != 0) + *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(uVar13 + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
  pcVar22 = (char *)((uint)puVar12 & 0xffffff00 | (uint)(byte)((char)puVar12 + 8));
code_r0x080429ec:
  *(byte *)(uVar25 + 7) = bVar26;
  puVar31[(int)pcVar22] = puVar31[(int)pcVar22] | (byte)uVar25;
  *pcVar22 = *pcVar22 + (char)pcVar22;
  bVar6 = (char)pcVar22 - 0x30;
  cVar24 = *(char *)(((uint)pcVar22 & 0xffffff00 | (uint)bVar6) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar12 = (uint *)(((uint)pcVar22 & 0xffff0000 |
                     (uint)CONCAT11((char)(((uint)pcVar22 & 0xffffff00) >> 8) + cVar24,bVar6)) + 2);
  *puVar12 = *puVar12 | (uint)puVar12;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void ChannelCreate(uint uParm1)

{
  char cVar1;
  byte bVar2;
  uint *puVar3;
  uint *unaff_EBX;
  
  bVar2 = (char)uParm1 - 0x30;
  cVar1 = *(char *)((uParm1 & 0xffffff00 | (uint)bVar2) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar3 = (uint *)((uParm1 & 0xffff0000 |
                    (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) + cVar1,bVar2)) + 2);
  *puVar3 = *puVar3 | (uint)puVar3;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

DIR * opendir(char *__name)

{
  undefined *puVar1;
  code *pcVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  char cVar17;
  uint *puVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  char *pcVar15;
  DIR *pDVar16;
  int in_ECX;
  byte *in_EDX;
  byte *pbVar18;
  uint *unaff_EBX;
  undefined *puVar19;
  undefined4 *puVar20;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar21;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  
  bVar3 = (char)__name - 0x30;
  uVar14 = (uint)__name & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__name & 0xffffff00) >> 8) +
                          *(char *)(((uint)__name & 0xffffff00 | (uint)bVar3) + 2),bVar3);
  _bVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  _bVar6 = (uint)((_bVar6 & 1) != 0);
  iVar13 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar14 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar3 = (char)puVar7 + 8;
  uVar12 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar3);
  bVar6 = (byte)((uint)in_ECX >> 8);
  if (!in_PF) {
    uVar12[(int)(&stack0x00000000 + iVar13 + _bVar6)] =
         uVar12[(int)(&stack0x00000000 + iVar13 + _bVar6)] | bVar6;
    *uVar12 = *uVar12 + bVar3;
    uVar12 = (char *)((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 - 0x28));
  }
  uVar8 = (uint)uVar12 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)uVar12 >> 8) + uVar12[2],(char)uVar12);
  bVar21 = (*unaff_EBX & 1) != 0;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)bVar21;
  puVar1 = &stack0x00000000 + iVar13 + *(int *)(uVar8 + 4) + _bVar6;
  cVar17 = (char)puVar1 + bVar21;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar8 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar3 = (byte)((uint)unaff_EBX >> 8);
  if (!in_PF) {
    puVar1[uVar14] = puVar1[uVar14] | bVar3;
    puVar1[(int)in_EDX * 8 + uVar14] = puVar1[(int)in_EDX * 8 + uVar14] + cVar17;
  }
  uVar14 = (uint)(puVar1 + uVar14) & 0xffff0000 |
           (uint)CONCAT11((char)((uint)(puVar1 + uVar14) >> 8) + puVar1[uVar14 + 2],cVar17);
  _bVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  _bVar6 = (uint)((_bVar6 & 1) != 0);
  iVar13 = ((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 8)) + *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar14 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar4 = (char)puVar7 + 8;
  _bVar4 = (ushort)puVar7 & 0xff00 | (ushort)bVar4;
  iVar9 = (int)(short)_bVar4;
  if (!in_PF) {
    pbVar18 = (byte *)(iVar13 + _bVar6 + iVar9);
    *pbVar18 = *pbVar18 | bVar4;
    uVar12 = (char *)(iVar9 + (int)in_EDX * 8);
    *uVar12 = *uVar12 + bVar4;
  }
  iVar10 = CONCAT22((short)_bVar4 >> 0xf,
                    CONCAT11((char)((uint)iVar9 >> 8) + *(char *)(iVar9 + 2),bVar4));
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(iVar10 + 4);
  uVar8 = (uint)((uVar14 & 1) != 0);
  uVar14 = *puVar7;
  iVar9 = iVar13 + _bVar6 + *puVar7;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(iVar10 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar5 = (byte)puVar7;
  bVar4 = bVar5 + 8;
  uVar12 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  *(uint *)(iVar9 + uVar8 + -4) =
       (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar5,'\b') * 0x800 | (uint)(in_IF & 1) * 0x200 |
       (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar4 < 0) * 0x80 | (uint)(bVar4 == 0) * 0x40 |
       (uint)(((iVar13 + _bVar6 & 0xfffffff) + (uVar14 & 0xfffffff) + uVar8 & 0x10000000) != 0) *
       0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar5) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  if (!in_PF) {
    uVar12[4] = uVar12[4] | (byte)in_EDX;
    *uVar12 = *uVar12 + bVar4;
    uVar12 = (char *)((uint)puVar7 & 0xffffff00 | (uint)(byte)(bVar5 - 0x28));
  }
  uVar14 = (uint)uVar12 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)uVar12 >> 8) + uVar12[2],(char)uVar12);
  _bVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar13 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar14 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar4 = DAT_5c08077a;
  uVar14 = (uint)puVar7 & 0xffffff00 | (uint)DAT_5c08077a;
  uVar12 = (char *)(uVar14 + (int)in_EDX * 8);
  *uVar12 = *uVar12 + DAT_5c08077a;
  uVar11 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)puVar7 >> 8) + *(char *)(uVar14 + 2),bVar4);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar10 = *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar11 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar4 = (char)puVar7 + 8;
  uVar12 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  _DAT_03ffffc4 = unaff_EDI + 1;
  *unaff_EDI = *unaff_ESI;
  if (!in_PF) {
    uVar12[4] = uVar12[4] | bVar6;
    *uVar12 = *uVar12 + bVar4;
    uVar12 = (char *)((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 - 0x28));
  }
  uVar12 = (uint)uVar12 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)uVar12 >> 8) + uVar12[2],(char)uVar12);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  iVar13 = iVar9 + uVar8 + -4 + iVar13 + (uint)((_bVar6 & 1) != 0) + iVar10 +
           (uint)((uVar14 & 1) != 0) + *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar12 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar6 = (char)puVar7 + 8;
  _bVar6 = (uint)puVar7 & 0xffffff00 | (uint)bVar6;
  pbVar18 = (byte *)(iVar13 + uVar11 + 2 + _bVar6);
  *pbVar18 = *pbVar18 | (byte)((uint)in_EDX >> 8);
  uVar12 = (char *)(_bVar6 + (int)in_EDX * 8);
  *uVar12 = *uVar12 + bVar6;
  uVar14 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + *(char *)(_bVar6 + 2),bVar6);
  _bVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  _bVar6 = (uint)((_bVar6 & 1) != 0);
  iVar13 = iVar13 + uVar11 + 2 + *(int *)(uVar14 + 4);
  puVar19 = (undefined *)(iVar13 + _bVar6);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar14 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  _DAT_03ffffc8 = unaff_ESI + 2;
  uVar14 = (uint)puVar7 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
  if (in_PF) {
    uVar8 = (uint)puVar7 & 0xffff0000 |
            (uint)CONCAT11((char)((uint)puVar7 >> 8) + *(char *)(uVar14 + 2),unaff_ESI[1]);
    uVar14 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar19 = (undefined *)(iVar13 + _bVar6 + *(int *)(uVar8 + 4) + (uint)((uVar14 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar7 = (uint *)(uVar8 + 2);
    *puVar7 = *puVar7 | (uint)puVar7;
    uVar14 = (uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 8);
  }
  *(byte *)(uVar14 + 0x4000004) = *(byte *)(uVar14 + 0x4000004) | (byte)uVar14;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar19 + -4) = uVar14;
  *(int *)(puVar19 + -8) = in_ECX;
  *(byte **)(puVar19 + -0xc) = in_EDX;
  *(uint **)(puVar19 + -0x10) = unaff_EBX;
  *(undefined **)(puVar19 + -0x14) = puVar19;
  *(undefined4 **)(puVar19 + -0x18) = unaff_EBP;
  *(undefined **)(puVar19 + -0x1c) = _DAT_03ffffc8;
  *(undefined **)(puVar19 + -0x20) = _DAT_03ffffc4;
  bVar4 = (byte)in_ECX;
  _bVar6 = (uint)in_EDX & 0xffffff00 | (uint)(byte)((byte)in_EDX + bVar4);
  iVar13 = uVar14 - *(int *)(uVar14 + 0x13);
  *(int *)(puVar19 + -0x24) = iVar13;
  *(int *)(puVar19 + -0x28) = in_ECX;
  *(uint *)(puVar19 + -0x2c) = _bVar6;
  *(uint **)(puVar19 + -0x30) = unaff_EBX;
  *(undefined **)(puVar19 + -0x34) = puVar19 + -0x20;
  *(undefined4 **)(puVar19 + -0x38) = unaff_EBP;
  *(undefined **)(puVar19 + -0x3c) = _DAT_03ffffc8;
  *(undefined **)(puVar19 + -0x40) = _DAT_03ffffc4;
  pbVar18 = (byte *)(_bVar6 + in_ECX);
  uVar12 = (char *)(iVar13 - *(int *)(iVar13 + 9));
  *uVar12 = *uVar12 + bVar3;
  uVar12[in_ECX] = uVar12[in_ECX] & (byte)uVar12;
  iVar13 = CONCAT31((int3)((uint)uVar12 >> 8),0x7a);
  puVar19[iVar13 + -0x2ffc003e] = puVar19[iVar13 + -0x2ffc003e] | bVar4;
  uVar14 = (uint)uVar12 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)uVar12 >> 8) + *(char *)(iVar13 + 2),0x7a);
  _bVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  _bVar6 = (uint)((_bVar6 & 1) != 0);
  puVar1 = puVar19 + *(int *)(uVar14 + 4) + -0x40;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar14 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  uVar14 = (uint)puVar7 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar7 + '\b');
  *(byte *)(uVar14 + 0x4000004) = *(byte *)(uVar14 + 0x4000004) | (byte)unaff_EBX;
  *pbVar18 = *pbVar18 << 1 | (char)*pbVar18 < 0;
  *(uint *)(puVar1 + _bVar6) = uVar14;
  *(int *)(puVar1 + (_bVar6 - 4)) = in_ECX;
  *(byte **)(puVar1 + (_bVar6 - 8)) = pbVar18;
  *(uint **)(puVar1 + (_bVar6 - 0xc)) = unaff_EBX;
  *(undefined **)(puVar1 + (_bVar6 - 0x10)) = puVar1 + _bVar6 + 4;
  *(undefined4 **)(puVar1 + (int)(&DAT_ffffffec + _bVar6)) = unaff_EBP;
  *(undefined **)(puVar1 + (_bVar6 - 0x18)) = _DAT_03ffffc8;
  *(undefined **)(puVar1 + (_bVar6 - 0x1c)) = _DAT_03ffffc4;
  uVar8 = (uint)pbVar18 & 0xffffff00 | (uint)(byte)((char)pbVar18 + bVar4);
  iVar13 = uVar14 - *(int *)(uVar14 + 0x13);
  *(int *)(puVar1 + (_bVar6 - 0x20)) = iVar13;
  *(int *)(puVar1 + (_bVar6 - 0x24)) = in_ECX;
  *(uint *)(puVar1 + (_bVar6 - 0x28)) = uVar8;
  *(uint **)(puVar1 + (_bVar6 - 0x2c)) = unaff_EBX;
  *(undefined **)(puVar1 + (_bVar6 - 0x30)) = puVar1 + (_bVar6 - 0x1c);
  *(undefined4 **)(puVar1 + (_bVar6 - 0x34)) = unaff_EBP;
  *(undefined **)(puVar1 + (_bVar6 - 0x38)) = _DAT_03ffffc8;
  *(undefined **)(puVar1 + (_bVar6 - 0x3c)) = _DAT_03ffffc4;
  _DAT_03fffff8 = (byte *)(uVar8 + in_ECX);
  uVar12 = (char *)(iVar13 - *(int *)(iVar13 + 9));
  *uVar12 = *uVar12 + bVar3;
  uVar12[in_ECX] = uVar12[in_ECX] & (byte)uVar12;
  uVar12 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
  *uVar12 = *uVar12 + 'z';
  cVar17 = DAT_a408077c + '\a';
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar17,0x7a)) + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar6 = (char)puVar7 + 8;
  _bVar6 = (uint)puVar7 & 0xffffff00 | (uint)bVar6;
  uVar12 = (char *)(_bVar6 + (int)_DAT_03fffff8 * 8);
  *uVar12 = *uVar12 + bVar6;
  cVar17 = *(char *)(_bVar6 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(((uint)puVar7 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + cVar17,bVar6)) + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  _DAT_04000000 = (uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 8);
  _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
  *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
  _DAT_03fffff0 = 0x4000004;
  _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar4);
  _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
  _DAT_03ffffd0 = &DAT_03ffffe4;
  iVar13 = _DAT_03ffffd8 + in_ECX;
  pcVar15 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
  _DAT_03ffffcc = unaff_EBP;
  _DAT_03ffffd4 = unaff_EBX;
  _DAT_03ffffdc = in_ECX;
  _DAT_03ffffe4 = _DAT_03ffffc4;
  _DAT_03ffffe8 = _DAT_03ffffc8;
  _DAT_03ffffec = unaff_EBP;
  _DAT_03fffff4 = unaff_EBX;
  _DAT_03fffffc = in_ECX;
  *pcVar15 = *pcVar15 + bVar3;
  pcVar15[in_ECX] = pcVar15[in_ECX] & (byte)pcVar15;
  bVar4 = (byte)pcVar15 | bVar4;
  _bVar6 = (uint)pcVar15 & 0xffffff00 | (uint)bVar4;
  uVar12 = (char *)(_bVar6 + iVar13 * 8);
  *uVar12 = *uVar12 + bVar4;
  uVar14 = (uint)pcVar15 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)pcVar15 & 0xffffff00) >> 8) + *(char *)(_bVar6 + 2),bVar4);
  _bVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  _bVar6 = (uint)((_bVar6 & 1) != 0);
  iVar13 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar14 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar3 = (char)puVar7 + 8;
  puVar20 = (undefined4 *)(iVar13 + _bVar6 + 0x3ffffc0);
  *(undefined4 **)(iVar13 + _bVar6 + 0x3ffffc0) = unaff_EBP;
  cVar17 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar20 = puVar20 + -1;
    *puVar20 = *unaff_EBP;
    cVar17 = cVar17 + -1;
  } while (0 < cVar17);
  *(uint *)(iVar13 + _bVar6 + 0x3ffffa0) = iVar13 + _bVar6 + 0x3ffffc0;
  uVar14 = (uint)CONCAT11(bVar3 / 4,bVar3) & 0xffffff00;
  _bVar6 = (uint)puVar7 & 0xffff0000 | uVar14;
  uVar12 = (char *)(_bVar6 | (uint)bVar3 & 0xffffff04);
  cVar17 = (char)((uint)bVar3 & 0xffffff04);
  *uVar12 = *uVar12 + cVar17;
  bVar3 = cVar17 - 0x30;
  cVar17 = *(char *)((_bVar6 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(((uint)puVar7 & 0xffff0000 | (uint)CONCAT11((char)(uVar14 >> 8) + cVar17,bVar3))
                   + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  pcVar2 = (code *)swi(3);
  pDVar16 = (DIR *)(*pcVar2)((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 8));
  return pDVar16;
}



// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void MsgSendv(uint uParm1,byte *pbParm2,int iParm3)

{
  undefined *puVar1;
  code *pcVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  char cVar16;
  uint *puVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  char *pcVar15;
  byte *pbVar17;
  uint *unaff_EBX;
  undefined *puVar18;
  undefined4 *puVar19;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool bVar20;
  bool in_PF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  
  bVar3 = (char)uParm1 - 0x30;
  uVar14 = uParm1 & 0xffff0000 |
           (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                          *(char *)((uParm1 & 0xffffff00 | (uint)bVar3) + 2),bVar3);
  bVar20 = (*unaff_EBX & 1) != 0;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)bVar20;
  puVar1 = &stack0x00000000 + *(int *)(uVar14 + 4);
  cVar16 = (char)puVar1 + bVar20;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar14 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar3 = (byte)((uint)unaff_EBX >> 8);
  if (!in_PF) {
    puVar1[uVar11] = puVar1[uVar11] | bVar3;
    puVar1[(int)pbParm2 * 8 + uVar11] = puVar1[(int)pbParm2 * 8 + uVar11] + cVar16;
  }
  uVar14 = (uint)(puVar1 + uVar11) & 0xffff0000 |
           (uint)CONCAT11((char)((uint)(puVar1 + uVar11) >> 8) + puVar1[uVar11 + 2],cVar16);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  iVar13 = ((uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 + 8)) + *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar14 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  _bVar4 = (ushort)puVar6 & 0xff00 | (ushort)bVar4;
  iVar7 = (int)(short)_bVar4;
  if (!in_PF) {
    pbVar17 = (byte *)(iVar13 + uVar11 + iVar7);
    *pbVar17 = *pbVar17 | bVar4;
    uVar10 = (char *)(iVar7 + (int)pbParm2 * 8);
    *uVar10 = *uVar10 + bVar4;
  }
  iVar8 = CONCAT22((short)_bVar4 >> 0xf,
                   CONCAT11((char)((uint)iVar7 >> 8) + *(char *)(iVar7 + 2),bVar4));
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(iVar8 + 4);
  uVar12 = (uint)((uVar14 & 1) != 0);
  uVar14 = *puVar6;
  iVar7 = iVar13 + uVar11 + *puVar6;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(iVar8 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar5 = (byte)puVar6;
  bVar4 = bVar5 + 8;
  uVar10 = (char *)((uint)puVar6 & 0xffffff00 | (uint)bVar4);
  *(uint *)(iVar7 + uVar12 + -4) =
       (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar5,'\b') * 0x800 | (uint)(in_IF & 1) * 0x200 |
       (uint)(in_TF & 1) * 0x100 | (uint)((char)bVar4 < 0) * 0x80 | (uint)(bVar4 == 0) * 0x40 |
       (uint)(((iVar13 + uVar11 & 0xfffffff) + (uVar14 & 0xfffffff) + uVar12 & 0x10000000) != 0) *
       0x10 | (uint)(in_PF & 1) * 4 | (uint)(0xf7 < bVar5) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  if (!in_PF) {
    uVar10[4] = uVar10[4] | (byte)pbParm2;
    *uVar10 = *uVar10 + bVar4;
    uVar10 = (char *)((uint)puVar6 & 0xffffff00 | (uint)(byte)(bVar5 - 0x28));
  }
  uVar14 = (uint)uVar10 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)uVar10 >> 8) + uVar10[2],(char)uVar10);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar13 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar14 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = DAT_5c08077a;
  uVar14 = (uint)puVar6 & 0xffffff00 | (uint)DAT_5c08077a;
  uVar10 = (char *)(uVar14 + (int)pbParm2 * 8);
  *uVar10 = *uVar10 + DAT_5c08077a;
  uVar9 = (uint)puVar6 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)puVar6 >> 8) + *(char *)(uVar14 + 2),bVar4);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar8 = *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar9 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  uVar10 = (char *)((uint)puVar6 & 0xffffff00 | (uint)bVar4);
  _DAT_03ffffc4 = unaff_EDI + 1;
  *unaff_EDI = *unaff_ESI;
  if (!in_PF) {
    uVar10[4] = uVar10[4] | (byte)((uint)iParm3 >> 8);
    *uVar10 = *uVar10 + bVar4;
    uVar10 = (char *)((uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 - 0x28));
  }
  uVar10 = (uint)uVar10 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)uVar10 >> 8) + uVar10[2],(char)uVar10);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar13 = iVar7 + uVar12 + -4 + iVar13 + (uint)((uVar11 & 1) != 0) + iVar8 +
           (uint)((uVar14 & 1) != 0) + *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar10 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  uVar11 = (uint)puVar6 & 0xffffff00 | (uint)bVar4;
  pbVar17 = (byte *)(iVar13 + uVar9 + 2 + uVar11);
  *pbVar17 = *pbVar17 | (byte)((uint)pbParm2 >> 8);
  uVar10 = (char *)(uVar11 + (int)pbParm2 * 8);
  *uVar10 = *uVar10 + bVar4;
  uVar14 = (uint)puVar6 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar6 & 0xffffff00) >> 8) + *(char *)(uVar11 + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  iVar13 = iVar13 + uVar9 + 2 + *(int *)(uVar14 + 4);
  puVar18 = (undefined *)(iVar13 + uVar11);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar14 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  _DAT_03ffffc8 = unaff_ESI + 2;
  uVar14 = (uint)puVar6 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
  if (in_PF) {
    uVar12 = (uint)puVar6 & 0xffff0000 |
             (uint)CONCAT11((char)((uint)puVar6 >> 8) + *(char *)(uVar14 + 2),unaff_ESI[1]);
    uVar14 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar18 = (undefined *)(iVar13 + uVar11 + *(int *)(uVar12 + 4) + (uint)((uVar14 & 1) != 0));
    *unaff_EBX = *unaff_EBX >> 1;
    puVar6 = (uint *)(uVar12 + 2);
    *puVar6 = *puVar6 | (uint)puVar6;
    uVar14 = (uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 + 8);
  }
  *(byte *)(uVar14 + 0x4000004) = *(byte *)(uVar14 + 0x4000004) | (byte)uVar14;
  *pbParm2 = *pbParm2 << 1 | (char)*pbParm2 < 0;
  *(uint *)(puVar18 + -4) = uVar14;
  *(int *)(puVar18 + -8) = iParm3;
  *(byte **)(puVar18 + -0xc) = pbParm2;
  *(uint **)(puVar18 + -0x10) = unaff_EBX;
  *(undefined **)(puVar18 + -0x14) = puVar18;
  *(undefined4 **)(puVar18 + -0x18) = unaff_EBP;
  *(undefined **)(puVar18 + -0x1c) = _DAT_03ffffc8;
  *(undefined **)(puVar18 + -0x20) = _DAT_03ffffc4;
  bVar5 = (byte)iParm3;
  uVar11 = (uint)pbParm2 & 0xffffff00 | (uint)(byte)((byte)pbParm2 + bVar5);
  iVar13 = uVar14 - *(int *)(uVar14 + 0x13);
  *(int *)(puVar18 + -0x24) = iVar13;
  *(int *)(puVar18 + -0x28) = iParm3;
  *(uint *)(puVar18 + -0x2c) = uVar11;
  *(uint **)(puVar18 + -0x30) = unaff_EBX;
  *(undefined **)(puVar18 + -0x34) = puVar18 + -0x20;
  *(undefined4 **)(puVar18 + -0x38) = unaff_EBP;
  *(undefined **)(puVar18 + -0x3c) = _DAT_03ffffc8;
  *(undefined **)(puVar18 + -0x40) = _DAT_03ffffc4;
  pbVar17 = (byte *)(uVar11 + iParm3);
  uVar10 = (char *)(iVar13 - *(int *)(iVar13 + 9));
  *uVar10 = *uVar10 + bVar3;
  uVar10[iParm3] = uVar10[iParm3] & (byte)uVar10;
  iVar13 = CONCAT31((int3)((uint)uVar10 >> 8),0x7a);
  puVar18[iVar13 + -0x2ffc003e] = puVar18[iVar13 + -0x2ffc003e] | bVar5;
  uVar14 = (uint)uVar10 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)uVar10 >> 8) + *(char *)(iVar13 + 2),0x7a);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  puVar1 = puVar18 + *(int *)(uVar14 + 4) + -0x40;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar14 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  uVar14 = (uint)puVar6 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar6 + '\b');
  *(byte *)(uVar14 + 0x4000004) = *(byte *)(uVar14 + 0x4000004) | (byte)unaff_EBX;
  *pbVar17 = *pbVar17 << 1 | (char)*pbVar17 < 0;
  *(uint *)(puVar1 + uVar11) = uVar14;
  *(int *)(puVar1 + (uVar11 - 4)) = iParm3;
  *(byte **)(puVar1 + (uVar11 - 8)) = pbVar17;
  *(uint **)(puVar1 + (uVar11 - 0xc)) = unaff_EBX;
  *(undefined **)(puVar1 + (uVar11 - 0x10)) = puVar1 + uVar11 + 4;
  *(undefined4 **)(puVar1 + (int)(&DAT_ffffffec + uVar11)) = unaff_EBP;
  *(undefined **)(puVar1 + (uVar11 - 0x18)) = _DAT_03ffffc8;
  *(undefined **)(puVar1 + (uVar11 - 0x1c)) = _DAT_03ffffc4;
  uVar12 = (uint)pbVar17 & 0xffffff00 | (uint)(byte)((char)pbVar17 + bVar5);
  iVar13 = uVar14 - *(int *)(uVar14 + 0x13);
  *(int *)(puVar1 + (uVar11 - 0x20)) = iVar13;
  *(int *)(puVar1 + (uVar11 - 0x24)) = iParm3;
  *(uint *)(puVar1 + (uVar11 - 0x28)) = uVar12;
  *(uint **)(puVar1 + (uVar11 - 0x2c)) = unaff_EBX;
  *(undefined **)(puVar1 + (uVar11 - 0x30)) = puVar1 + (uVar11 - 0x1c);
  *(undefined4 **)(puVar1 + (uVar11 - 0x34)) = unaff_EBP;
  *(undefined **)(puVar1 + (uVar11 - 0x38)) = _DAT_03ffffc8;
  *(undefined **)(puVar1 + (uVar11 - 0x3c)) = _DAT_03ffffc4;
  _DAT_03fffff8 = (byte *)(uVar12 + iParm3);
  uVar10 = (char *)(iVar13 - *(int *)(iVar13 + 9));
  *uVar10 = *uVar10 + bVar3;
  uVar10[iParm3] = uVar10[iParm3] & (byte)uVar10;
  uVar10 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
  *uVar10 = *uVar10 + 'z';
  cVar16 = DAT_a408077c + '\a';
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar16,0x7a)) + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  uVar11 = (uint)puVar6 & 0xffffff00 | (uint)bVar4;
  uVar10 = (char *)(uVar11 + (int)_DAT_03fffff8 * 8);
  *uVar10 = *uVar10 + bVar4;
  cVar16 = *(char *)(uVar11 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(((uint)puVar6 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)puVar6 & 0xffffff00) >> 8) + cVar16,bVar4)) + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  _DAT_04000000 = (uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 + 8);
  _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
  *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
  _DAT_03fffff0 = 0x4000004;
  _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar5);
  _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
  _DAT_03ffffd0 = &DAT_03ffffe4;
  iVar13 = _DAT_03ffffd8 + iParm3;
  pcVar15 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
  _DAT_03ffffcc = unaff_EBP;
  _DAT_03ffffd4 = unaff_EBX;
  _DAT_03ffffdc = iParm3;
  _DAT_03ffffe4 = _DAT_03ffffc4;
  _DAT_03ffffe8 = _DAT_03ffffc8;
  _DAT_03ffffec = unaff_EBP;
  _DAT_03fffff4 = unaff_EBX;
  _DAT_03fffffc = iParm3;
  *pcVar15 = *pcVar15 + bVar3;
  pcVar15[iParm3] = pcVar15[iParm3] & (byte)pcVar15;
  bVar5 = (byte)pcVar15 | bVar5;
  uVar11 = (uint)pcVar15 & 0xffffff00 | (uint)bVar5;
  uVar10 = (char *)(uVar11 + iVar13 * 8);
  *uVar10 = *uVar10 + bVar5;
  uVar14 = (uint)pcVar15 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)pcVar15 & 0xffffff00) >> 8) + *(char *)(uVar11 + 2),bVar5);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  iVar13 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar14 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar3 = (char)puVar6 + 8;
  puVar19 = (undefined4 *)(iVar13 + uVar11 + 0x3ffffc0);
  *(undefined4 **)(iVar13 + uVar11 + 0x3ffffc0) = unaff_EBP;
  cVar16 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar19 = puVar19 + -1;
    *puVar19 = *unaff_EBP;
    cVar16 = cVar16 + -1;
  } while (0 < cVar16);
  *(uint *)(iVar13 + uVar11 + 0x3ffffa0) = iVar13 + uVar11 + 0x3ffffc0;
  uVar14 = (uint)CONCAT11(bVar3 / 4,bVar3) & 0xffffff00;
  uVar11 = (uint)puVar6 & 0xffff0000 | uVar14;
  uVar10 = (char *)(uVar11 | (uint)bVar3 & 0xffffff04);
  cVar16 = (char)((uint)bVar3 & 0xffffff04);
  *uVar10 = *uVar10 + cVar16;
  bVar3 = cVar16 - 0x30;
  cVar16 = *(char *)((uVar11 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(((uint)puVar6 & 0xffff0000 | (uint)CONCAT11((char)(uVar14 >> 8) + cVar16,bVar3))
                   + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  pcVar2 = (code *)swi(3);
  (*pcVar2)((uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 + 8));
  return;
}



// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void TimerDestroy_r(uint uParm1,byte *pbParm2,int iParm3)

{
  int iVar1;
  undefined *puVar2;
  code *pcVar3;
  byte bVar4;
  byte bVar5;
  char cVar13;
  uint *puVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  char *pcVar12;
  byte *pbVar14;
  char cVar15;
  uint *unaff_EBX;
  undefined *puVar16;
  undefined4 *puVar17;
  undefined4 *unaff_EBP;
  undefined *unaff_ESI;
  undefined *unaff_EDI;
  bool in_PF;
  
  bVar4 = (char)uParm1 - 0x30;
  uVar11 = uParm1 & 0xffff0000 |
           (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                          *(char *)((uParm1 & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar10 = *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar11 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = DAT_5c08077a;
  uVar11 = (uint)puVar6 & 0xffffff00 | (uint)DAT_5c08077a;
  uVar8 = (char *)(uVar11 + (int)pbParm2 * 8);
  *uVar8 = *uVar8 + DAT_5c08077a;
  uVar7 = (uint)puVar6 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)puVar6 >> 8) + *(char *)(uVar11 + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar1 = *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar7 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  uVar8 = (char *)((uint)puVar6 & 0xffffff00 | (uint)bVar4);
  _DAT_03ffffc4 = unaff_EDI + 1;
  *unaff_EDI = *unaff_ESI;
  if (!in_PF) {
    uVar8[4] = uVar8[4] | (byte)((uint)iParm3 >> 8);
    *uVar8 = *uVar8 + bVar4;
    uVar8 = (char *)((uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 - 0x28));
  }
  uVar8 = (uint)uVar8 & 0xffff0000 | (uint)CONCAT11((char)((uint)uVar8 >> 8) + uVar8[2],(char)uVar8)
  ;
  uVar7 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar7 & 1) != 0);
  puVar2 = &stack0x00000000 +
           *(int *)(uVar8 + 4) +
           (uint)((uVar11 & 1) != 0) + iVar1 + (uint)((uVar9 & 1) != 0) + iVar10;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar8 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  uVar9 = (uint)puVar6 & 0xffffff00 | (uint)bVar4;
  puVar2[uVar9 + uVar7 + 2] = puVar2[uVar9 + uVar7 + 2] | (byte)((uint)pbParm2 >> 8);
  uVar8 = (char *)(uVar9 + (int)pbParm2 * 8);
  *uVar8 = *uVar8 + bVar4;
  uVar11 = (uint)puVar6 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar6 & 0xffffff00) >> 8) + *(char *)(uVar9 + 2),bVar4);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar10 = *(int *)(uVar11 + 4);
  puVar16 = puVar2 + iVar10 + uVar7 + 2 + uVar9;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar11 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  _DAT_03ffffc8 = unaff_ESI + 2;
  uVar11 = (uint)puVar6 & 0xffffff00 | (uint)(byte)unaff_ESI[1];
  if (in_PF) {
    uVar8 = (uint)puVar6 & 0xffff0000 |
            (uint)CONCAT11((char)((uint)puVar6 >> 8) + *(char *)(uVar11 + 2),unaff_ESI[1]);
    uVar11 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = puVar2 + iVar10 + uVar7 + 2 + (uint)((uVar11 & 1) != 0) + *(int *)(uVar8 + 4) + uVar9;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar6 = (uint *)(uVar8 + 2);
    *puVar6 = *puVar6 | (uint)puVar6;
    uVar11 = (uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 + 8);
  }
  *(byte *)(uVar11 + 0x4000004) = *(byte *)(uVar11 + 0x4000004) | (byte)uVar11;
  *pbParm2 = *pbParm2 << 1 | (char)*pbParm2 < 0;
  *(uint *)(puVar16 + -4) = uVar11;
  *(int *)(puVar16 + -8) = iParm3;
  *(byte **)(puVar16 + -0xc) = pbParm2;
  *(uint **)(puVar16 + -0x10) = unaff_EBX;
  *(undefined **)(puVar16 + -0x14) = puVar16;
  *(undefined4 **)(puVar16 + -0x18) = unaff_EBP;
  *(undefined **)(puVar16 + -0x1c) = _DAT_03ffffc8;
  *(undefined **)(puVar16 + -0x20) = _DAT_03ffffc4;
  bVar5 = (byte)iParm3;
  uVar9 = (uint)pbParm2 & 0xffffff00 | (uint)(byte)((char)pbParm2 + bVar5);
  iVar10 = uVar11 - *(int *)(uVar11 + 0x13);
  *(int *)(puVar16 + -0x24) = iVar10;
  *(int *)(puVar16 + -0x28) = iParm3;
  *(uint *)(puVar16 + -0x2c) = uVar9;
  *(uint **)(puVar16 + -0x30) = unaff_EBX;
  *(undefined **)(puVar16 + -0x34) = puVar16 + -0x20;
  *(undefined4 **)(puVar16 + -0x38) = unaff_EBP;
  *(undefined **)(puVar16 + -0x3c) = _DAT_03ffffc8;
  *(undefined **)(puVar16 + -0x40) = _DAT_03ffffc4;
  pbVar14 = (byte *)(uVar9 + iParm3);
  uVar8 = (char *)(iVar10 - *(int *)(iVar10 + 9));
  cVar15 = (char)((uint)unaff_EBX >> 8);
  *uVar8 = *uVar8 + cVar15;
  uVar8[iParm3] = uVar8[iParm3] & (byte)uVar8;
  iVar10 = CONCAT31((int3)((uint)uVar8 >> 8),0x7a);
  puVar16[iVar10 + -0x2ffc003e] = puVar16[iVar10 + -0x2ffc003e] | bVar5;
  uVar11 = (uint)uVar8 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)uVar8 >> 8) + *(char *)(iVar10 + 2),0x7a);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  puVar2 = puVar16 + *(int *)(uVar11 + 4) + -0x40;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar11 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  uVar11 = (uint)puVar6 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar6 + '\b');
  *(byte *)(uVar11 + 0x4000004) = *(byte *)(uVar11 + 0x4000004) | (byte)unaff_EBX;
  *pbVar14 = *pbVar14 << 1 | (char)*pbVar14 < 0;
  *(uint *)(puVar2 + uVar9) = uVar11;
  *(int *)(puVar2 + (uVar9 - 4)) = iParm3;
  *(byte **)(puVar2 + (uVar9 - 8)) = pbVar14;
  *(uint **)(puVar2 + (uVar9 - 0xc)) = unaff_EBX;
  *(undefined **)(puVar2 + (uVar9 - 0x10)) = puVar2 + uVar9 + 4;
  *(undefined4 **)(puVar2 + (int)(&DAT_ffffffec + uVar9)) = unaff_EBP;
  *(undefined **)(puVar2 + (uVar9 - 0x18)) = _DAT_03ffffc8;
  *(undefined **)(puVar2 + (uVar9 - 0x1c)) = _DAT_03ffffc4;
  uVar7 = (uint)pbVar14 & 0xffffff00 | (uint)(byte)((char)pbVar14 + bVar5);
  iVar10 = uVar11 - *(int *)(uVar11 + 0x13);
  *(int *)(puVar2 + (uVar9 - 0x20)) = iVar10;
  *(int *)(puVar2 + (uVar9 - 0x24)) = iParm3;
  *(uint *)(puVar2 + (uVar9 - 0x28)) = uVar7;
  *(uint **)(puVar2 + (uVar9 - 0x2c)) = unaff_EBX;
  *(undefined **)(puVar2 + (uVar9 - 0x30)) = puVar2 + (uVar9 - 0x1c);
  *(undefined4 **)(puVar2 + (uVar9 - 0x34)) = unaff_EBP;
  *(undefined **)(puVar2 + (uVar9 - 0x38)) = _DAT_03ffffc8;
  *(undefined **)(puVar2 + (uVar9 - 0x3c)) = _DAT_03ffffc4;
  _DAT_03fffff8 = (byte *)(uVar7 + iParm3);
  uVar8 = (char *)(iVar10 - *(int *)(iVar10 + 9));
  *uVar8 = *uVar8 + cVar15;
  uVar8[iParm3] = uVar8[iParm3] & (byte)uVar8;
  uVar8 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
  *uVar8 = *uVar8 + 'z';
  cVar13 = DAT_a408077c + '\a';
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar13,0x7a)) + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  uVar9 = (uint)puVar6 & 0xffffff00 | (uint)bVar4;
  uVar8 = (char *)(uVar9 + (int)_DAT_03fffff8 * 8);
  *uVar8 = *uVar8 + bVar4;
  cVar13 = *(char *)(uVar9 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(((uint)puVar6 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)puVar6 & 0xffffff00) >> 8) + cVar13,bVar4)) + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  _DAT_04000000 = (uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 + 8);
  _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
  *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
  _DAT_03fffff0 = 0x4000004;
  _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar5);
  _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
  _DAT_03ffffd0 = &DAT_03ffffe4;
  iVar10 = _DAT_03ffffd8 + iParm3;
  pcVar12 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
  _DAT_03ffffcc = unaff_EBP;
  _DAT_03ffffd4 = unaff_EBX;
  _DAT_03ffffdc = iParm3;
  _DAT_03ffffe4 = _DAT_03ffffc4;
  _DAT_03ffffe8 = _DAT_03ffffc8;
  _DAT_03ffffec = unaff_EBP;
  _DAT_03fffff4 = unaff_EBX;
  _DAT_03fffffc = iParm3;
  *pcVar12 = *pcVar12 + cVar15;
  pcVar12[iParm3] = pcVar12[iParm3] & (byte)pcVar12;
  bVar5 = (byte)pcVar12 | bVar5;
  uVar9 = (uint)pcVar12 & 0xffffff00 | (uint)bVar5;
  uVar8 = (char *)(uVar9 + iVar10 * 8);
  *uVar8 = *uVar8 + bVar5;
  uVar11 = (uint)pcVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)pcVar12 & 0xffffff00) >> 8) + *(char *)(uVar9 + 2),bVar5);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar10 = *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar11 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  puVar17 = (undefined4 *)(iVar10 + uVar9 + 0x3ffffc0);
  *(undefined4 **)(iVar10 + uVar9 + 0x3ffffc0) = unaff_EBP;
  cVar13 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar17 = puVar17 + -1;
    *puVar17 = *unaff_EBP;
    cVar13 = cVar13 + -1;
  } while (0 < cVar13);
  *(uint *)(iVar10 + uVar9 + 0x3ffffa0) = iVar10 + uVar9 + 0x3ffffc0;
  uVar11 = (uint)CONCAT11(bVar4 / 4,bVar4) & 0xffffff00;
  uVar9 = (uint)puVar6 & 0xffff0000 | uVar11;
  uVar8 = (char *)(uVar9 | (uint)bVar4 & 0xffffff04);
  cVar13 = (char)((uint)bVar4 & 0xffffff04);
  *uVar8 = *uVar8 + cVar13;
  bVar4 = cVar13 - 0x30;
  cVar13 = *(char *)((uVar9 | (uint)bVar4) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(((uint)puVar6 & 0xffff0000 | (uint)CONCAT11((char)(uVar11 >> 8) + cVar13,bVar4))
                   + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  pcVar3 = (code *)swi(3);
  (*pcVar3)((uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 + 8));
  return;
}



// WARNING: Instruction at (ram,0x08042af2) overlaps instruction at (ram,0x08042af1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_mutex_unlock(pthread_mutex_t *__mutex)

{
  undefined *puVar1;
  code *pcVar2;
  byte bVar3;
  byte bVar4;
  char cVar13;
  uint *puVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  char *pcVar9;
  uint uVar10;
  uint uVar11;
  char *pcVar12;
  int in_ECX;
  byte *in_EDX;
  byte *pbVar14;
  char cVar15;
  uint *unaff_EBX;
  undefined *puVar16;
  undefined4 *puVar17;
  undefined4 *unaff_EBP;
  byte *unaff_ESI;
  undefined4 unaff_EDI;
  bool in_PF;
  
  bVar3 = (char)__mutex - 0x30;
  uVar10 = (uint)__mutex & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__mutex & 0xffffff00) >> 8) +
                          *(char *)(((uint)__mutex & 0xffffff00 | (uint)bVar3) + 2),bVar3);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar6 & 1) != 0);
  puVar1 = &stack0x00000000 + *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar5 = (uint *)(uVar10 + 2);
  *puVar5 = *puVar5 | (uint)puVar5;
  bVar3 = (char)puVar5 + 8;
  uVar6 = (uint)puVar5 & 0xffffff00 | (uint)bVar3;
  puVar1[uVar6 + uVar11 + 2] = puVar1[uVar6 + uVar11 + 2] | (byte)((uint)in_EDX >> 8);
  pcVar9 = (char *)(uVar6 + (int)in_EDX * 8);
  *pcVar9 = *pcVar9 + bVar3;
  uVar10 = (uint)puVar5 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar5 & 0xffffff00) >> 8) + *(char *)(uVar6 + 2),bVar3);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar6 & 1) != 0);
  iVar8 = *(int *)(uVar10 + 4);
  puVar16 = puVar1 + iVar8 + uVar11 + 2 + uVar6;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar5 = (uint *)(uVar10 + 2);
  *puVar5 = *puVar5 | (uint)puVar5;
  _DAT_03ffffc8 = unaff_ESI + 1;
  uVar10 = (uint)puVar5 & 0xffffff00 | (uint)*unaff_ESI;
  if (in_PF) {
    uVar7 = (uint)puVar5 & 0xffff0000 |
            (uint)CONCAT11((char)((uint)puVar5 >> 8) + *(char *)(uVar10 + 2),*unaff_ESI);
    uVar10 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar16 = puVar1 + iVar8 + uVar11 + 2 + (uint)((uVar10 & 1) != 0) + *(int *)(uVar7 + 4) + uVar6;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar5 = (uint *)(uVar7 + 2);
    *puVar5 = *puVar5 | (uint)puVar5;
    uVar10 = (uint)puVar5 & 0xffffff00 | (uint)(byte)((char)puVar5 + 8);
  }
  *(byte *)(uVar10 + 0x4000004) = *(byte *)(uVar10 + 0x4000004) | (byte)uVar10;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar16 + -4) = uVar10;
  *(int *)(puVar16 + -8) = in_ECX;
  *(byte **)(puVar16 + -0xc) = in_EDX;
  *(uint **)(puVar16 + -0x10) = unaff_EBX;
  *(undefined **)(puVar16 + -0x14) = puVar16;
  *(undefined4 **)(puVar16 + -0x18) = unaff_EBP;
  *(byte **)(puVar16 + -0x1c) = _DAT_03ffffc8;
  *(undefined4 *)(puVar16 + -0x20) = unaff_EDI;
  bVar4 = (byte)in_ECX;
  uVar6 = (uint)in_EDX & 0xffffff00 | (uint)(byte)((char)in_EDX + bVar4);
  iVar8 = uVar10 - *(int *)(uVar10 + 0x13);
  *(int *)(puVar16 + -0x24) = iVar8;
  *(int *)(puVar16 + -0x28) = in_ECX;
  *(uint *)(puVar16 + -0x2c) = uVar6;
  *(uint **)(puVar16 + -0x30) = unaff_EBX;
  *(undefined **)(puVar16 + -0x34) = puVar16 + -0x20;
  *(undefined4 **)(puVar16 + -0x38) = unaff_EBP;
  *(byte **)(puVar16 + -0x3c) = _DAT_03ffffc8;
  *(undefined4 *)(puVar16 + -0x40) = unaff_EDI;
  pbVar14 = (byte *)(uVar6 + in_ECX);
  pcVar9 = (char *)(iVar8 - *(int *)(iVar8 + 9));
  cVar15 = (char)((uint)unaff_EBX >> 8);
  *pcVar9 = *pcVar9 + cVar15;
  pcVar9[in_ECX] = pcVar9[in_ECX] & (byte)pcVar9;
  iVar8 = CONCAT31((int3)((uint)pcVar9 >> 8),0x7a);
  puVar16[iVar8 + -0x2ffc003e] = puVar16[iVar8 + -0x2ffc003e] | bVar4;
  uVar11 = (uint)pcVar9 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar9 >> 8) + *(char *)(iVar8 + 2),0x7a);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar6 & 1) != 0);
  puVar1 = puVar16 + *(int *)(uVar11 + 4) + -0x40;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar5 = (uint *)(uVar11 + 2);
  *puVar5 = *puVar5 | (uint)puVar5;
  uVar11 = (uint)puVar5 & 0xffff0000 | (uint)CONCAT11(0x7a,(char)puVar5 + '\b');
  *(byte *)(uVar11 + 0x4000004) = *(byte *)(uVar11 + 0x4000004) | (byte)unaff_EBX;
  *pbVar14 = *pbVar14 << 1 | (char)*pbVar14 < 0;
  *(uint *)(puVar1 + uVar6) = uVar11;
  *(int *)(puVar1 + (uVar6 - 4)) = in_ECX;
  *(byte **)(puVar1 + (uVar6 - 8)) = pbVar14;
  *(uint **)(puVar1 + (uVar6 - 0xc)) = unaff_EBX;
  *(undefined **)(puVar1 + (uVar6 - 0x10)) = puVar1 + uVar6 + 4;
  *(undefined4 **)(puVar1 + (int)(&DAT_ffffffec + uVar6)) = unaff_EBP;
  *(byte **)(puVar1 + (uVar6 - 0x18)) = _DAT_03ffffc8;
  *(undefined4 *)(puVar1 + (uVar6 - 0x1c)) = unaff_EDI;
  uVar10 = (uint)pbVar14 & 0xffffff00 | (uint)(byte)((char)pbVar14 + bVar4);
  iVar8 = uVar11 - *(int *)(uVar11 + 0x13);
  *(int *)(puVar1 + (uVar6 - 0x20)) = iVar8;
  *(int *)(puVar1 + (uVar6 - 0x24)) = in_ECX;
  *(uint *)(puVar1 + (uVar6 - 0x28)) = uVar10;
  *(uint **)(puVar1 + (uVar6 - 0x2c)) = unaff_EBX;
  *(undefined **)(puVar1 + (uVar6 - 0x30)) = puVar1 + (uVar6 - 0x1c);
  *(undefined4 **)(puVar1 + (uVar6 - 0x34)) = unaff_EBP;
  *(byte **)(puVar1 + (uVar6 - 0x38)) = _DAT_03ffffc8;
  *(undefined4 *)(puVar1 + (uVar6 - 0x3c)) = unaff_EDI;
  _DAT_03fffff8 = (byte *)(uVar10 + in_ECX);
  pcVar9 = (char *)(iVar8 - *(int *)(iVar8 + 9));
  *pcVar9 = *pcVar9 + cVar15;
  pcVar9[in_ECX] = pcVar9[in_ECX] & (byte)pcVar9;
  pcVar9 = (char *)((int)_DAT_03fffff8 * 8 + -0x5bf7f886);
  *pcVar9 = *pcVar9 + 'z';
  cVar13 = DAT_a408077c + '\a';
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar5 = (uint *)(CONCAT22(0xa408,CONCAT11(cVar13,0x7a)) + 2);
  *puVar5 = *puVar5 | (uint)puVar5;
  bVar3 = (char)puVar5 + 8;
  uVar6 = (uint)puVar5 & 0xffffff00 | (uint)bVar3;
  pcVar9 = (char *)(uVar6 + (int)_DAT_03fffff8 * 8);
  *pcVar9 = *pcVar9 + bVar3;
  cVar13 = *(char *)(uVar6 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar5 = (uint *)(((uint)puVar5 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)puVar5 & 0xffffff00) >> 8) + cVar13,bVar3)) + 2);
  *puVar5 = *puVar5 | (uint)puVar5;
  _DAT_04000000 = (uint)puVar5 & 0xffffff00 | (uint)(byte)((char)puVar5 + 8);
  _DAT_03fffff8[7] = (char)_DAT_03fffff8[7] >> 8;
  *_DAT_03fffff8 = *_DAT_03fffff8 << 1 | (char)*_DAT_03fffff8 < 0;
  _DAT_03fffff0 = 0x4000004;
  _DAT_03ffffd8 = (uint)_DAT_03fffff8 & 0xffffff00 | (uint)(byte)((char)_DAT_03fffff8 + bVar4);
  _DAT_03ffffe0 = _DAT_04000000 - *(int *)(_DAT_04000000 + 0x13);
  _DAT_03ffffd0 = &DAT_03ffffe4;
  iVar8 = _DAT_03ffffd8 + in_ECX;
  pcVar12 = (char *)(_DAT_03ffffe0 - *(int *)(_DAT_03ffffe0 + 9));
  _DAT_03ffffc4 = unaff_EDI;
  _DAT_03ffffcc = unaff_EBP;
  _DAT_03ffffd4 = unaff_EBX;
  _DAT_03ffffdc = in_ECX;
  _DAT_03ffffe4 = unaff_EDI;
  _DAT_03ffffe8 = _DAT_03ffffc8;
  _DAT_03ffffec = unaff_EBP;
  _DAT_03fffff4 = unaff_EBX;
  _DAT_03fffffc = in_ECX;
  *pcVar12 = *pcVar12 + cVar15;
  pcVar12[in_ECX] = pcVar12[in_ECX] & (byte)pcVar12;
  bVar4 = (byte)pcVar12 | bVar4;
  uVar6 = (uint)pcVar12 & 0xffffff00 | (uint)bVar4;
  pcVar9 = (char *)(uVar6 + iVar8 * 8);
  *pcVar9 = *pcVar9 + bVar4;
  uVar11 = (uint)pcVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)pcVar12 & 0xffffff00) >> 8) + *(char *)(uVar6 + 2),bVar4);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar6 & 1) != 0);
  iVar8 = *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar5 = (uint *)(uVar11 + 2);
  *puVar5 = *puVar5 | (uint)puVar5;
  bVar3 = (char)puVar5 + 8;
  puVar17 = (undefined4 *)(iVar8 + uVar6 + 0x3ffffc0);
  *(undefined4 **)(iVar8 + uVar6 + 0x3ffffc0) = unaff_EBP;
  cVar13 = '\a';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar17 = puVar17 + -1;
    *puVar17 = *unaff_EBP;
    cVar13 = cVar13 + -1;
  } while (0 < cVar13);
  *(uint *)(iVar8 + uVar6 + 0x3ffffa0) = iVar8 + uVar6 + 0x3ffffc0;
  uVar11 = (uint)CONCAT11(bVar3 / 4,bVar3) & 0xffffff00;
  uVar6 = (uint)puVar5 & 0xffff0000 | uVar11;
  pcVar9 = (char *)(uVar6 | (uint)bVar3 & 0xffffff04);
  cVar13 = (char)((uint)bVar3 & 0xffffff04);
  *pcVar9 = *pcVar9 + cVar13;
  bVar3 = cVar13 - 0x30;
  cVar13 = *(char *)((uVar6 | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar5 = (uint *)(((uint)puVar5 & 0xffff0000 | (uint)CONCAT11((char)(uVar11 >> 8) + cVar13,bVar3))
                   + 2);
  *puVar5 = *puVar5 | (uint)puVar5;
  pcVar2 = (code *)swi(3);
  iVar8 = (*pcVar2)((uint)puVar5 & 0xffffff00 | (uint)(byte)((char)puVar5 + 8));
  return iVar8;
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
  pVar5 = (*pcVar2)((uint)puVar4 & 0xffffff00 | (uint)(byte)((char)puVar4 + 8));
  return pVar5;
}



// WARNING: Instruction at (ram,0x08042cd0) overlaps instruction at (ram,0x08042cce)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_mutexattr_init(pthread_mutexattr_t *__attr)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  byte bVar4;
  char cVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  byte *pbVar11;
  byte *pbVar12;
  uint uVar13;
  uint uVar14;
  char *pcVar15;
  int iVar16;
  byte extraout_CL;
  int in_ECX;
  int iVar17;
  uint in_EDX;
  int extraout_EDX;
  byte bVar18;
  uint *unaff_EBX;
  int unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  bool in_PF;
  undefined auStack30 [4];
  undefined auStack26 [4];
  undefined auStack22 [8];
  undefined auStack14 [4];
  undefined auStack10 [4];
  undefined auStack6 [4];
  undefined auStack2 [2];
  
  bVar4 = (char)__attr - 0x30;
  uVar6 = (uint)__attr & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__attr & 0xffffff00) >> 8) +
                         *(char *)(((uint)__attr & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar17 = *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  cVar5 = (char)puVar7 + '\b';
  *(char *)(in_EDX + 7) = *(char *)(in_EDX + 7) >> 1;
  uVar6 = (uint)CONCAT11((byte)((uint)puVar7 >> 8) | (byte)((uint)in_ECX >> 8),cVar5);
  uVar8 = (uint)puVar7 & 0xffff0000 | uVar6;
  pcVar15 = (char *)(uVar8 + in_EDX * 8);
  *pcVar15 = *pcVar15 + cVar5;
  uVar8 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar6 >> 8) + *(char *)(uVar8 + 2),cVar5);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar16 = *(int *)(uVar8 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar8 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar4 = (char)puVar7 + 8;
  uVar8 = (uint)CONCAT11(bVar4 / 0x7a,bVar4) & 0xffffff00;
  bVar18 = (byte)((uint)unaff_EBX >> 8);
  bVar4 = bVar4 & 0x7a | bVar18;
  uVar9 = (uint)puVar7 & 0xffff0000 | uVar8 | (uint)bVar4;
  pcVar15 = (char *)(uVar9 + in_EDX * 8);
  *pcVar15 = *pcVar15 + bVar4;
  uVar9 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar8 >> 8) + *(char *)(uVar9 + 2),bVar4);
  uVar8 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar1 = *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar9 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar4 = (char)puVar7 + 8;
  uVar9 = (uint)puVar7 & 0xffffff00 | (uint)bVar4;
  pbVar11 = (byte *)(uVar9 + 0xd0040000);
  *pbVar11 = *pbVar11 | bVar4;
  uVar10 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + *(char *)(uVar9 + 2),bVar4);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar10 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  pbVar11 = (byte *)((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 8));
  *pbVar11 = *pbVar11 | (byte)in_EDX;
  pbVar12 = pbVar11 + -0x2ffc0000;
  uVar13 = (uint)pbVar12 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pbVar12 >> 8) + pbVar11[-0x2ffbfffe],(char)pbVar12);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar10 = (uint)((uVar10 & 1) != 0);
  puVar3 = &stack0x00000002 +
           *(int *)(uVar13 + 4) +
           (uint)((uVar9 & 1) != 0) +
           iVar2 + (uint)((uVar8 & 1) != 0) +
                   iVar1 + (uint)((uVar6 & 1) != 0) + iVar16 + (uint)((uVar14 & 1) != 0) + iVar17;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar13 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar4 = (char)puVar7 + 8;
  uVar14 = (uint)puVar7 & 0xffffff00 | (uint)bVar4;
  iVar17 = in_ECX + -1;
  if (iVar17 == 0 || bVar4 == 0) {
    *(byte *)(uVar14 + 0xd0040000) = *(byte *)(uVar14 + 0xd0040000) | (byte)unaff_EBX;
    uVar6 = (uint)puVar7 & 0xffff0000 |
            (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),bVar4);
    uVar14 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar16 = *(int *)(uVar6 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar7 = (uint *)(uVar6 + 2);
    *puVar7 = *puVar7 | (uint)puVar7;
    bVar4 = in(0x7a);
    pbVar11 = (byte *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
    *pbVar11 = *pbVar11 | (byte)((uint)iVar17 >> 8);
    pbVar12 = pbVar11 + -0x2ffc0000;
    uVar8 = (uint)pbVar12 & 0xffff0000 |
            (uint)CONCAT11((char)((uint)pbVar12 >> 8) + pbVar11[-0x2ffbfffe],(char)pbVar12);
    uVar6 = *unaff_EBX;
    *unaff_EBX = *unaff_EBX >> 1;
    iVar17 = *(int *)(uVar8 + 4);
    *unaff_EBX = *unaff_EBX >> 1;
    puVar7 = (uint *)(uVar8 + 2);
    *puVar7 = *puVar7 | (uint)puVar7;
    *(undefined4 *)
     (puVar3 + (uint)((uVar6 & 1) != 0) + iVar17 + (uint)((uVar14 & 1) != 0) + iVar16 + uVar10) =
         0x8042c91;
    iVar17 = func_0x3c0c340b((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 8));
    uVar14 = iVar17 + 0xd0040000;
    cVar5 = *(char *)(iVar17 + -0x2ffbfffe);
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar7 = (uint *)((uVar14 & 0xffff0000 |
                      (uint)CONCAT11((char)(uVar14 >> 8) + cVar5,(char)uVar14)) + 2);
    *puVar7 = *puVar7 | (uint)puVar7;
    bVar4 = in((short)extraout_EDX);
    pcVar15 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
    if (!in_PF) {
      pcVar15[5] = pcVar15[5] | bVar4;
      *pcVar15 = *pcVar15 + bVar4;
      pcVar15 = (char *)((uint)puVar7 & 0xffffff00 | (uint)(byte)(bVar4 - 0x30));
    }
    cVar5 = pcVar15[2];
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar7 = (uint *)(((uint)pcVar15 & 0xffff0000 |
                      (uint)CONCAT11((char)((uint)pcVar15 >> 8) + cVar5,(char)pcVar15)) + 2);
    *puVar7 = *puVar7 | (uint)puVar7;
    bVar4 = (char)puVar7 + 8;
    uVar14 = (uint)puVar7 & 0xffffff00 | (uint)bVar4;
    LOCK();
    if (!in_PF) {
      *(byte *)(unaff_EBP + uVar14) = *(byte *)(unaff_EBP + uVar14) | extraout_CL;
      pcVar15 = (char *)(uVar14 + extraout_EDX * 8);
      *pcVar15 = *pcVar15 + bVar4;
    }
    cVar5 = *(char *)(uVar14 + 2);
    *unaff_EBX = *unaff_EBX >> 1;
    *unaff_EBX = *unaff_EBX >> 1;
    puVar7 = (uint *)(((uint)puVar7 & 0xffff0000 |
                      (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + cVar5,bVar4)) + 2);
    *puVar7 = *puVar7 | (uint)puVar7;
  }
  else {
    iVar16 = uVar14 - *(int *)(uVar14 + 0x13);
    *(int *)(puVar3 + (uVar10 - 4)) = iVar16;
    *(int *)(puVar3 + (uVar10 - 8)) = iVar17;
    *(uint *)(puVar3 + (uVar10 - 0xc)) =
         in_EDX & 0xffffff00 | (uint)(byte)((byte)in_EDX + (char)iVar17);
    *(uint **)(puVar3 + (uVar10 - 0x10)) = unaff_EBX;
    *(undefined **)(puVar3 + (int)(&DAT_ffffffec + uVar10)) = puVar3 + uVar10;
    *(int *)(puVar3 + (uVar10 - 0x18)) = unaff_EBP;
    *(undefined4 *)(puVar3 + (uVar10 - 0x1c)) = unaff_ESI;
    *(undefined4 *)(puVar3 + (uVar10 - 0x20)) = unaff_EDI;
    pcVar15 = (char *)(iVar16 - *(int *)(iVar16 + 9));
    *pcVar15 = *pcVar15 + bVar18;
    pcVar15[iVar17] = pcVar15[iVar17] & (byte)pcVar15;
  }
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention yet parameter storage is locked

void exit(int __status)

{
  char *pcVar1;
  char cVar2;
  byte bVar3;
  uint *puVar4;
  uint uVar5;
  byte in_CL;
  int in_EDX;
  uint *unaff_EBX;
  int unaff_EBP;
  bool in_PF;
  
  bVar3 = (char)__status - 0x30;
  cVar2 = *(char *)((__status & 0xffffff00U | (uint)bVar3) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)((__status & 0xffff0000U |
                    (uint)CONCAT11((char)((__status & 0xffffff00U) >> 8) + cVar2,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  bVar3 = (char)puVar4 + 8;
  uVar5 = (uint)puVar4 & 0xffffff00 | (uint)bVar3;
  LOCK();
  if (!in_PF) {
    *(byte *)(unaff_EBP + uVar5) = *(byte *)(unaff_EBP + uVar5) | in_CL;
    pcVar1 = (char *)(uVar5 + in_EDX * 8);
    *pcVar1 = *pcVar1 + bVar3;
  }
  cVar2 = *(char *)(uVar5 + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar4 = (uint *)(((uint)puVar4 & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)puVar4 & 0xffffff00) >> 8) + cVar2,bVar3)) + 2);
  *puVar4 = *puVar4 | (uint)puVar4;
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_mutex_trylock(pthread_mutex_t *__mutex)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined *puVar6;
  byte bVar7;
  byte bVar17;
  uint *puVar8;
  char *pcVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  byte bVar18;
  int in_ECX;
  byte *in_EDX;
  byte *pbVar19;
  int iVar20;
  byte bVar21;
  uint *unaff_EBX;
  int unaff_EBP;
  int unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 uVar22;
  bool in_PF;
  undefined auStack186 [4];
  undefined auStack182 [4];
  undefined auStack178 [4];
  undefined auStack174 [4];
  undefined auStack170 [4];
  undefined auStack166 [4];
  undefined auStack162 [4];
  undefined auStack158 [4];
  undefined auStack154 [4];
  undefined auStack150 [4];
  undefined auStack146 [4];
  undefined auStack142 [4];
  undefined auStack138 [4];
  undefined auStack134 [4];
  undefined auStack130 [4];
  undefined auStack126 [10];
  undefined auStack116 [4];
  undefined auStack112 [4];
  undefined auStack108 [4];
  undefined auStack104 [4];
  undefined auStack100 [4];
  undefined auStack96 [4];
  undefined auStack92 [4];
  undefined auStack88 [4];
  undefined auStack84 [4];
  undefined auStack80 [4];
  undefined auStack76 [4];
  undefined auStack72 [4];
  undefined auStack68 [4];
  undefined auStack64 [10];
  undefined auStack54 [4];
  undefined auStack50 [4];
  undefined auStack46 [4];
  undefined auStack42 [4];
  undefined auStack38 [4];
  undefined auStack34 [4];
  undefined auStack30 [4];
  undefined auStack26 [4];
  undefined auStack22 [4];
  undefined auStack18 [4];
  undefined auStack14 [8];
  undefined auStack6 [4];
  undefined auStack2 [2];
  
  bVar7 = (char)__mutex - 0x30;
  uVar12 = (uint)__mutex & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)__mutex & 0xffffff00) >> 8) +
                          *(char *)(((uint)__mutex & 0xffffff00 | (uint)bVar7) + 2),bVar7);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar11 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  uVar12 = (uint)puVar8 & 0xffffff00 | (uint)bVar7;
  bVar17 = (byte)(((uint)puVar8 & 0xffffff00) >> 8);
  if (!in_PF) {
    *(byte *)(unaff_EBP + uVar12) = *(byte *)(unaff_EBP + uVar12) | bVar17;
    pcVar9 = (char *)(uVar12 + (int)in_EDX * 8);
    *pcVar9 = *pcVar9 + bVar7;
  }
  uVar13 = (uint)puVar8 & 0xffff0000 | (uint)CONCAT11(bVar17 + *(char *)(uVar12 + 2),bVar7);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar13 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  pcVar9 = (char *)((uint)puVar8 & 0xffffff00 | (uint)bVar7);
  if (!in_PF) {
    pcVar9[5] = pcVar9[5] | (byte)((uint)in_EDX >> 8);
    *pcVar9 = *pcVar9 + bVar7;
    pcVar9 = (char *)((uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 - 0x28));
  }
  uVar14 = (uint)pcVar9 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar9 >> 8) + pcVar9[2],(char)pcVar9);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar14 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  uVar14 = (uint)puVar8 & 0xffffff00 | (uint)bVar7;
  bVar21 = (byte)((uint)unaff_EBX >> 8);
  *(char *)((int)unaff_EBX + 7) = *(char *)((int)unaff_EBX + 7) + bVar21;
  *(byte *)(unaff_EBP + uVar14) = *(byte *)(unaff_EBP + uVar14) | bVar21;
  pcVar9 = (char *)(uVar14 + (int)in_EDX * 8);
  *pcVar9 = *pcVar9 + bVar7;
  uVar15 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + *(char *)(uVar14 + 2),bVar7);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar14 = (uint)((uVar14 & 1) != 0);
  puVar6 = &stack0x00000000 +
           *(int *)(uVar15 + 4) +
           (uint)((uVar13 & 1) != 0) +
           iVar3 + (uint)((uVar12 & 1) != 0) + iVar2 + (uint)((uVar10 & 1) != 0) + iVar11;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar15 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar10 = (uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 0x83);
  bVar17 = (byte)in_ECX;
  *(byte *)(uVar10 + 0x4000005) = *(byte *)(uVar10 + 0x4000005) | bVar17;
  *in_EDX = *in_EDX << 1 | (char)*in_EDX < 0;
  *(uint *)(puVar6 + (uVar14 - 2)) = uVar10;
  *(int *)(puVar6 + (uVar14 - 6)) = in_ECX;
  *(byte **)(puVar6 + (int)(&DAT_fffffff6 + uVar14)) = in_EDX;
  *(uint **)(puVar6 + (uVar14 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar14 - 0x12)) = puVar6 + uVar14 + 2;
  *(int *)(puVar6 + (uVar14 - 0x16)) = unaff_EBP;
  *(int *)(puVar6 + (uVar14 - 0x1a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar14 - 0x1e)) = unaff_EDI;
  uVar12 = (uint)in_EDX & 0xffffff00 | (uint)(byte)((char)in_EDX + bVar17);
  iVar11 = uVar10 - *(int *)(uVar10 + 0x13);
  *(int *)(puVar6 + (uVar14 - 0x22)) = iVar11;
  *(int *)(puVar6 + (uVar14 - 0x26)) = in_ECX;
  *(uint *)(puVar6 + (uVar14 - 0x2a)) = uVar12;
  *(uint **)(puVar6 + (uVar14 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar14 - 0x32)) = puVar6 + (uVar14 - 0x1e);
  *(int *)(puVar6 + (uVar14 - 0x36)) = unaff_EBP;
  *(int *)(puVar6 + (uVar14 - 0x3a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar14 - 0x3e)) = unaff_EDI;
  pbVar19 = (byte *)(uVar12 + in_ECX);
  pcVar9 = (char *)(iVar11 - *(int *)(iVar11 + 9));
  *pcVar9 = *pcVar9 + bVar21;
  pcVar9[in_ECX] = pcVar9[in_ECX] & (byte)pcVar9;
  *(byte *)((int)unaff_EBX + 7) = *(byte *)((int)unaff_EBX + 7) | bVar21;
  pcVar9[unaff_EBP + -0x2ffc0000] = pcVar9[unaff_EBP + -0x2ffc0000] | (byte)pbVar19;
  uVar13 = (uint)pcVar9 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar9 >> 8) + pcVar9[2],(byte)pcVar9);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar12 = (uint)((uVar10 & 1) != 0);
  puVar6 = puVar6 + *(int *)(uVar13 + 4) + (uVar14 - 0x3e);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar13 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar10 = (uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 8) | 0x7b;
  *(byte *)(uVar10 + 0x4000005) =
       *(byte *)(uVar10 + 0x4000005) | (byte)(((uint)puVar8 & 0xffffff00) >> 8);
  *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
  *(uint *)(puVar6 + (uVar12 - 2)) = uVar10;
  *(int *)(puVar6 + (uVar12 - 6)) = in_ECX;
  *(byte **)(puVar6 + (uVar12 - 10)) = pbVar19;
  *(uint **)(puVar6 + (uVar12 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar12 - 0x12)) = puVar6 + uVar12 + 2;
  *(int *)(puVar6 + (uVar12 - 0x16)) = unaff_EBP;
  *(int *)(puVar6 + (uVar12 - 0x1a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar12 - 0x1e)) = unaff_EDI;
  uVar13 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((byte)pbVar19 + bVar17);
  iVar11 = uVar10 - *(int *)(uVar10 + 0x13);
  *(int *)(puVar6 + (uVar12 - 0x22)) = iVar11;
  *(int *)(puVar6 + (uVar12 - 0x26)) = in_ECX;
  *(uint *)(puVar6 + (uVar12 - 0x2a)) = uVar13;
  *(uint **)(puVar6 + (uVar12 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar12 - 0x32)) = puVar6 + (uVar12 - 0x1e);
  *(int *)(puVar6 + (uVar12 - 0x36)) = unaff_EBP;
  *(int *)(puVar6 + (uVar12 - 0x3a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar12 - 0x3e)) = unaff_EDI;
  pbVar19 = (byte *)(uVar13 + in_ECX);
  pcVar9 = (char *)(iVar11 - *(int *)(iVar11 + 9));
  *pcVar9 = *pcVar9 + bVar21;
  pcVar9[in_ECX] = pcVar9[in_ECX] & (byte)pcVar9;
  *(char *)((int)unaff_EBX + 7) = *(char *)((int)unaff_EBX + 7) + bVar21;
  bVar18 = (byte)((uint)in_ECX >> 8);
  pcVar9[unaff_EBP + -0x2ffc0000] = pcVar9[unaff_EBP + -0x2ffc0000] | bVar18;
  uVar13 = (uint)pcVar9 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar9 >> 8) + pcVar9[2],(byte)pcVar9);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar5 = (uint)((uVar10 & 1) != 0);
  puVar6 = puVar6 + *(int *)(uVar13 + 4) + (uVar12 - 0x3e);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar13 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar10 = (uint)puVar8 & 0xffffff00 | (uint)(byte)((byte)puVar8 + 0x83 + (0xf7 < (byte)puVar8));
  *(byte *)(uVar10 + 0x4000005) = *(byte *)(uVar10 + 0x4000005) | bVar21;
  *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
  *(uint *)(puVar6 + (uVar5 - 2)) = uVar10;
  *(int *)(puVar6 + (uVar5 - 6)) = in_ECX;
  *(byte **)(puVar6 + (uVar5 - 10)) = pbVar19;
  *(uint **)(puVar6 + (uVar5 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar5 - 0x12)) = puVar6 + uVar5 + 2;
  *(int *)(puVar6 + (uVar5 - 0x16)) = unaff_EBP;
  *(int *)(puVar6 + (uVar5 - 0x1a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar5 - 0x1e)) = unaff_EDI;
  uVar12 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((char)pbVar19 + bVar17);
  iVar11 = uVar10 - *(int *)(uVar10 + 0x13);
  *(int *)(puVar6 + (uVar5 - 0x22)) = iVar11;
  *(int *)(puVar6 + (uVar5 - 0x26)) = in_ECX;
  *(uint *)(puVar6 + (uVar5 - 0x2a)) = uVar12;
  *(uint **)(puVar6 + (uVar5 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar5 - 0x32)) = puVar6 + (uVar5 - 0x1e);
  *(int *)(puVar6 + (uVar5 - 0x36)) = unaff_EBP;
  *(int *)(puVar6 + (uVar5 - 0x3a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar5 - 0x3e)) = unaff_EDI;
  iVar20 = uVar12 + in_ECX;
  pcVar9 = (char *)(iVar11 - *(int *)(iVar11 + 9));
  *pcVar9 = *pcVar9 + bVar21;
  bVar7 = (byte)pcVar9;
  pcVar9[in_ECX] = pcVar9[in_ECX] & bVar7;
  *(char *)((int)unaff_EBX + 7) = *(char *)((int)unaff_EBX + 7) - bVar21;
  uVar10 = (uint)pcVar9 & 0xffff0000 | (uint)CONCAT11((byte)((uint)pcVar9 >> 8) | bVar7,bVar7);
  uVar12 = uVar10 + 0xd0040000;
  uVar12 = uVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)(uVar10 + 0xd0040002),(char)uVar12);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar11 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar12 = (uint)puVar8 & 0xffffff00 |
           (uint)(byte)(((byte)puVar8 + 0x8d) - (0xf7 < (byte)puVar8) | (byte)iVar20);
  uVar13 = uVar12 + 0xd0040000;
  uVar13 = uVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar12 + 0xd0040002),(char)uVar13);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar13 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(byte *)((int)unaff_EBX + 7) = *(byte *)((int)unaff_EBX + 7) & bVar21;
  uVar13 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((byte)((uint)puVar8 >> 8) | (byte)unaff_EBX,(char)puVar8 + '\b');
  uVar14 = uVar13 + 0xd0040000;
  uVar14 = uVar14 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar14 >> 8) + *(char *)(uVar13 + 0xd0040002),(char)uVar14);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar14 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar14 = (uint)puVar8 & 0xffffff00 | (uint)((char)puVar8 + 8U & 0x7b | bVar18);
  uVar15 = uVar14 + 0xd0040000;
  uVar15 = uVar15 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar15 >> 8) + *(char *)(uVar14 + 0xd0040002),(char)uVar15);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar4 = *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar15 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(char *)((int)unaff_EBX + 7) = *(char *)((int)unaff_EBX + 7) - bVar21;
  bVar18 = (byte)((uint)iVar20 >> 8);
  uVar15 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((byte)((uint)puVar8 >> 8) | bVar18,(char)puVar8 + '\b');
  uVar16 = uVar15 + 0xd0040000;
  uVar16 = uVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar15 + 0xd0040002),(char)uVar16);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  puVar6 = puVar6 + *(int *)(uVar16 + 4) +
                    (uint)((uVar14 & 1) != 0) +
                    iVar4 + (uint)((uVar13 & 1) != 0) +
                            iVar3 + (uint)((uVar12 & 1) != 0) +
                                    iVar2 + (uint)((uVar10 & 1) != 0) + iVar11 + uVar5 + -0x3a;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar16 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar10 = (uint)puVar8 & 0xffffff00;
  bVar7 = (char)puVar8 + 0x8d;
  pbVar19 = (byte *)(uVar10 | (uint)bVar7);
  uVar22 = *(undefined2 *)(puVar6 + uVar15);
  *pbVar19 = *pbVar19 | bVar7;
  *(undefined2 *)(puVar6 + uVar15) = uVar22;
  *pbVar19 = *pbVar19 + bVar7;
  bVar7 = (char)puVar8 + 0x5d;
  uVar12 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar10 >> 8) + *(char *)((uVar10 | (uint)bVar7) + 2),bVar7);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar11 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  uVar12 = (uint)puVar8 & 0xffffff00;
  pcVar9 = (char *)(uVar12 | (uint)bVar7);
  *(byte *)((int)unaff_EBX + 7) = *(byte *)((int)unaff_EBX + 7) ^ bVar21;
  pcVar9[unaff_ESI] = pcVar9[unaff_ESI] | bVar17;
  *pcVar9 = *pcVar9 + bVar7;
  bVar7 = (char)puVar8 - 0x28;
  uVar14 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)((uVar12 | (uint)bVar7) + 2),bVar7);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar12 & 1) != 0);
  puVar6 = puVar6 + *(int *)(uVar14 + 4) + (uint)((uVar10 & 1) != 0) + iVar11 + uVar15;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar14 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar10 = (uint)puVar8 & 0xffffff00;
  pbVar19 = (byte *)((uVar10 | (uint)(byte)((char)puVar8 + 8)) ^ 0x7b);
  uVar22 = *(undefined2 *)(puVar6 + uVar13);
  *pbVar19 = *pbVar19 | (byte)unaff_EBX;
  *(undefined2 *)(puVar6 + uVar13) = uVar22;
  *pbVar19 = *pbVar19 + (char)pbVar19;
  bVar7 = (char)pbVar19 - 0x30;
  uVar12 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar10 >> 8) + *(char *)((uVar10 | (uint)bVar7) + 2),bVar7);
  uVar10 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar11 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  uVar12 = (uint)puVar8 & 0xffffff00;
  pcVar9 = (char *)(uVar12 | (uint)bVar7);
  bVar17 = (byte)(uVar12 >> 8);
  pcVar9[unaff_ESI] = pcVar9[unaff_ESI] | bVar17;
  *pcVar9 = *pcVar9 + bVar7;
  bVar7 = (char)puVar8 - 0x28;
  uVar14 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11(bVar17 + *(char *)((uVar12 | (uint)bVar7) + 2),bVar7);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar12 = (uint)((uVar12 & 1) != 0);
  iVar2 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar14 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  uVar14 = (uint)puVar8 & 0xffffff00;
  pbVar19 = (byte *)(uVar14 | (uint)bVar7);
  uVar22 = *(undefined2 *)
            ((int)(puVar6 + iVar2 + (uint)((uVar10 & 1) != 0) + iVar11 + uVar13) + uVar12);
  *pbVar19 = *pbVar19 | bVar18;
  *(undefined2 *)((int)(puVar6 + iVar2 + (uint)((uVar10 & 1) != 0) + iVar11 + uVar13) + uVar12) =
       uVar22;
  *pbVar19 = *pbVar19 + bVar7;
  bVar7 = (char)puVar8 - 0x28;
  cVar1 = *(char *)((uVar14 | (uint)bVar7) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(((uint)puVar8 & 0xffff0000 | (uint)CONCAT11((char)(uVar14 >> 8) + cVar1,bVar7))
                   + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  pcVar9 = (char *)(((uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 8)) + 1);
  if (in_PF) {
    pcVar9[unaff_ESI] = pcVar9[unaff_ESI] | bVar21;
    *pcVar9 = *pcVar9 + (char)pcVar9;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling

void ClockId(uint uParm1,byte *pbParm2,int iParm3)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined *puVar6;
  byte bVar7;
  byte bVar17;
  uint *puVar8;
  uint uVar9;
  int iVar10;
  char *pcVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  byte bVar18;
  byte *pbVar19;
  int iVar20;
  byte bVar21;
  uint *unaff_EBX;
  int unaff_EBP;
  int unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 uVar22;
  bool in_PF;
  undefined auStack186 [4];
  undefined auStack182 [4];
  undefined auStack178 [4];
  undefined auStack174 [4];
  undefined auStack170 [4];
  undefined auStack166 [4];
  undefined auStack162 [4];
  undefined auStack158 [4];
  undefined auStack154 [4];
  undefined auStack150 [4];
  undefined auStack146 [4];
  undefined auStack142 [4];
  undefined auStack138 [4];
  undefined auStack134 [4];
  undefined auStack130 [4];
  undefined auStack126 [10];
  undefined auStack116 [4];
  undefined auStack112 [4];
  undefined auStack108 [4];
  undefined auStack104 [4];
  undefined auStack100 [4];
  undefined auStack96 [4];
  undefined auStack92 [4];
  undefined auStack88 [4];
  undefined auStack84 [4];
  undefined auStack80 [4];
  undefined auStack76 [4];
  undefined auStack72 [4];
  undefined auStack68 [4];
  undefined auStack64 [10];
  undefined auStack54 [4];
  undefined auStack50 [4];
  undefined auStack46 [4];
  undefined auStack42 [4];
  undefined auStack38 [4];
  undefined auStack34 [4];
  undefined auStack30 [4];
  undefined auStack26 [4];
  undefined auStack22 [4];
  undefined auStack18 [4];
  undefined auStack14 [8];
  undefined auStack6 [4];
  undefined auStack2 [2];
  
  bVar7 = (char)uParm1 - 0x30;
  uVar12 = uParm1 & 0xffff0000 |
           (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                          *(char *)((uParm1 & 0xffffff00 | (uint)bVar7) + 2),bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar10 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  uVar12 = (uint)puVar8 & 0xffffff00 | (uint)bVar7;
  bVar21 = (byte)((uint)unaff_EBX >> 8);
  *(char *)((int)unaff_EBX + 7) = *(char *)((int)unaff_EBX + 7) + bVar21;
  *(byte *)(unaff_EBP + uVar12) = *(byte *)(unaff_EBP + uVar12) | bVar21;
  pcVar11 = (char *)(uVar12 + (int)pbParm2 * 8);
  *pcVar11 = *pcVar11 + bVar7;
  uVar13 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + *(char *)(uVar12 + 2),bVar7);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar12 = (uint)((uVar12 & 1) != 0);
  puVar6 = &stack0x00000000 + *(int *)(uVar13 + 4) + (uint)((uVar9 & 1) != 0) + iVar10;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar13 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar9 = (uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 0x83);
  bVar17 = (byte)iParm3;
  *(byte *)(uVar9 + 0x4000005) = *(byte *)(uVar9 + 0x4000005) | bVar17;
  *pbParm2 = *pbParm2 << 1 | (char)*pbParm2 < 0;
  *(uint *)(puVar6 + (uVar12 - 2)) = uVar9;
  *(int *)(puVar6 + (uVar12 - 6)) = iParm3;
  *(byte **)(puVar6 + (int)(&DAT_fffffff6 + uVar12)) = pbParm2;
  *(uint **)(puVar6 + (uVar12 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar12 - 0x12)) = puVar6 + uVar12 + 2;
  *(int *)(puVar6 + (uVar12 - 0x16)) = unaff_EBP;
  *(int *)(puVar6 + (uVar12 - 0x1a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar12 - 0x1e)) = unaff_EDI;
  uVar13 = (uint)pbParm2 & 0xffffff00 | (uint)(byte)((char)pbParm2 + bVar17);
  iVar10 = uVar9 - *(int *)(uVar9 + 0x13);
  *(int *)(puVar6 + (uVar12 - 0x22)) = iVar10;
  *(int *)(puVar6 + (uVar12 - 0x26)) = iParm3;
  *(uint *)(puVar6 + (uVar12 - 0x2a)) = uVar13;
  *(uint **)(puVar6 + (uVar12 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar12 - 0x32)) = puVar6 + (uVar12 - 0x1e);
  *(int *)(puVar6 + (uVar12 - 0x36)) = unaff_EBP;
  *(int *)(puVar6 + (uVar12 - 0x3a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar12 - 0x3e)) = unaff_EDI;
  pbVar19 = (byte *)(uVar13 + iParm3);
  pcVar11 = (char *)(iVar10 - *(int *)(iVar10 + 9));
  *pcVar11 = *pcVar11 + bVar21;
  pcVar11[iParm3] = pcVar11[iParm3] & (byte)pcVar11;
  *(byte *)((int)unaff_EBX + 7) = *(byte *)((int)unaff_EBX + 7) | bVar21;
  pcVar11[unaff_EBP + -0x2ffc0000] = pcVar11[unaff_EBP + -0x2ffc0000] | (byte)pbVar19;
  uVar14 = (uint)pcVar11 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar11 >> 8) + pcVar11[2],(byte)pcVar11);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar9 & 1) != 0);
  puVar6 = puVar6 + *(int *)(uVar14 + 4) + (uVar12 - 0x3e);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar14 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar9 = (uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 8) | 0x7b;
  *(byte *)(uVar9 + 0x4000005) =
       *(byte *)(uVar9 + 0x4000005) | (byte)(((uint)puVar8 & 0xffffff00) >> 8);
  *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
  *(uint *)(puVar6 + (uVar13 - 2)) = uVar9;
  *(int *)(puVar6 + (uVar13 - 6)) = iParm3;
  *(byte **)(puVar6 + (uVar13 - 10)) = pbVar19;
  *(uint **)(puVar6 + (uVar13 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar13 - 0x12)) = puVar6 + uVar13 + 2;
  *(int *)(puVar6 + (uVar13 - 0x16)) = unaff_EBP;
  *(int *)(puVar6 + (uVar13 - 0x1a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar13 - 0x1e)) = unaff_EDI;
  uVar12 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((byte)pbVar19 + bVar17);
  iVar10 = uVar9 - *(int *)(uVar9 + 0x13);
  *(int *)(puVar6 + (uVar13 - 0x22)) = iVar10;
  *(int *)(puVar6 + (uVar13 - 0x26)) = iParm3;
  *(uint *)(puVar6 + (uVar13 - 0x2a)) = uVar12;
  *(uint **)(puVar6 + (uVar13 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar13 - 0x32)) = puVar6 + (uVar13 - 0x1e);
  *(int *)(puVar6 + (uVar13 - 0x36)) = unaff_EBP;
  *(int *)(puVar6 + (uVar13 - 0x3a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar13 - 0x3e)) = unaff_EDI;
  pbVar19 = (byte *)(uVar12 + iParm3);
  pcVar11 = (char *)(iVar10 - *(int *)(iVar10 + 9));
  *pcVar11 = *pcVar11 + bVar21;
  pcVar11[iParm3] = pcVar11[iParm3] & (byte)pcVar11;
  *(char *)((int)unaff_EBX + 7) = *(char *)((int)unaff_EBX + 7) + bVar21;
  bVar18 = (byte)((uint)iParm3 >> 8);
  pcVar11[unaff_EBP + -0x2ffc0000] = pcVar11[unaff_EBP + -0x2ffc0000] | bVar18;
  uVar12 = (uint)pcVar11 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar11 >> 8) + pcVar11[2],(byte)pcVar11);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar5 = (uint)((uVar9 & 1) != 0);
  puVar6 = puVar6 + *(int *)(uVar12 + 4) + (uVar13 - 0x3e);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar9 = (uint)puVar8 & 0xffffff00 | (uint)(byte)((byte)puVar8 + 0x83 + (0xf7 < (byte)puVar8));
  *(byte *)(uVar9 + 0x4000005) = *(byte *)(uVar9 + 0x4000005) | bVar21;
  *pbVar19 = *pbVar19 << 1 | (char)*pbVar19 < 0;
  *(uint *)(puVar6 + (uVar5 - 2)) = uVar9;
  *(int *)(puVar6 + (uVar5 - 6)) = iParm3;
  *(byte **)(puVar6 + (uVar5 - 10)) = pbVar19;
  *(uint **)(puVar6 + (uVar5 - 0xe)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar5 - 0x12)) = puVar6 + uVar5 + 2;
  *(int *)(puVar6 + (uVar5 - 0x16)) = unaff_EBP;
  *(int *)(puVar6 + (uVar5 - 0x1a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar5 - 0x1e)) = unaff_EDI;
  uVar12 = (uint)pbVar19 & 0xffffff00 | (uint)(byte)((char)pbVar19 + bVar17);
  iVar10 = uVar9 - *(int *)(uVar9 + 0x13);
  *(int *)(puVar6 + (uVar5 - 0x22)) = iVar10;
  *(int *)(puVar6 + (uVar5 - 0x26)) = iParm3;
  *(uint *)(puVar6 + (uVar5 - 0x2a)) = uVar12;
  *(uint **)(puVar6 + (uVar5 - 0x2e)) = unaff_EBX;
  *(undefined **)(puVar6 + (uVar5 - 0x32)) = puVar6 + (uVar5 - 0x1e);
  *(int *)(puVar6 + (uVar5 - 0x36)) = unaff_EBP;
  *(int *)(puVar6 + (uVar5 - 0x3a)) = unaff_ESI;
  *(undefined4 *)(puVar6 + (uVar5 - 0x3e)) = unaff_EDI;
  iVar20 = uVar12 + iParm3;
  pcVar11 = (char *)(iVar10 - *(int *)(iVar10 + 9));
  *pcVar11 = *pcVar11 + bVar21;
  bVar7 = (byte)pcVar11;
  pcVar11[iParm3] = pcVar11[iParm3] & bVar7;
  *(char *)((int)unaff_EBX + 7) = *(char *)((int)unaff_EBX + 7) - bVar21;
  uVar9 = (uint)pcVar11 & 0xffff0000 | (uint)CONCAT11((byte)((uint)pcVar11 >> 8) | bVar7,bVar7);
  uVar12 = uVar9 + 0xd0040000;
  uVar12 = uVar12 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)(uVar9 + 0xd0040002),(char)uVar12);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar10 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar12 = (uint)puVar8 & 0xffffff00 |
           (uint)(byte)(((byte)puVar8 + 0x8d) - (0xf7 < (byte)puVar8) | (byte)iVar20);
  uVar13 = uVar12 + 0xd0040000;
  uVar13 = uVar13 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar13 >> 8) + *(char *)(uVar12 + 0xd0040002),(char)uVar13);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar2 = *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar13 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(byte *)((int)unaff_EBX + 7) = *(byte *)((int)unaff_EBX + 7) & bVar21;
  uVar13 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((byte)((uint)puVar8 >> 8) | (byte)unaff_EBX,(char)puVar8 + '\b');
  uVar14 = uVar13 + 0xd0040000;
  uVar14 = uVar14 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar14 >> 8) + *(char *)(uVar13 + 0xd0040002),(char)uVar14);
  uVar13 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar14 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar14 = (uint)puVar8 & 0xffffff00 | (uint)((char)puVar8 + 8U & 0x7b | bVar18);
  uVar15 = uVar14 + 0xd0040000;
  uVar15 = uVar15 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar15 >> 8) + *(char *)(uVar14 + 0xd0040002),(char)uVar15);
  uVar14 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar4 = *(int *)(uVar15 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar15 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(char *)((int)unaff_EBX + 7) = *(char *)((int)unaff_EBX + 7) - bVar21;
  bVar18 = (byte)((uint)iVar20 >> 8);
  uVar15 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((byte)((uint)puVar8 >> 8) | bVar18,(char)puVar8 + '\b');
  uVar16 = uVar15 + 0xd0040000;
  uVar16 = uVar16 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar16 >> 8) + *(char *)(uVar15 + 0xd0040002),(char)uVar16);
  uVar15 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar15 = (uint)((uVar15 & 1) != 0);
  puVar6 = puVar6 + *(int *)(uVar16 + 4) +
                    (uint)((uVar14 & 1) != 0) +
                    iVar4 + (uint)((uVar13 & 1) != 0) +
                            iVar3 + (uint)((uVar12 & 1) != 0) +
                                    iVar2 + (uint)((uVar9 & 1) != 0) + iVar10 + uVar5 + -0x3a;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar16 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar9 = (uint)puVar8 & 0xffffff00;
  bVar7 = (char)puVar8 + 0x8d;
  pbVar19 = (byte *)(uVar9 | (uint)bVar7);
  uVar22 = *(undefined2 *)(puVar6 + uVar15);
  *pbVar19 = *pbVar19 | bVar7;
  *(undefined2 *)(puVar6 + uVar15) = uVar22;
  *pbVar19 = *pbVar19 + bVar7;
  bVar7 = (char)puVar8 + 0x5d;
  uVar12 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)bVar7) + 2),bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar10 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  uVar12 = (uint)puVar8 & 0xffffff00;
  pcVar11 = (char *)(uVar12 | (uint)bVar7);
  *(byte *)((int)unaff_EBX + 7) = *(byte *)((int)unaff_EBX + 7) ^ bVar21;
  pcVar11[unaff_ESI] = pcVar11[unaff_ESI] | bVar17;
  *pcVar11 = *pcVar11 + bVar7;
  bVar7 = (char)puVar8 - 0x28;
  uVar14 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)((uVar12 | (uint)bVar7) + 2),bVar7);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar12 & 1) != 0);
  puVar6 = puVar6 + *(int *)(uVar14 + 4) + (uint)((uVar9 & 1) != 0) + iVar10 + uVar15;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar14 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  uVar9 = (uint)puVar8 & 0xffffff00;
  pbVar19 = (byte *)((uVar9 | (uint)(byte)((char)puVar8 + 8)) ^ 0x7b);
  uVar22 = *(undefined2 *)(puVar6 + uVar13);
  *pbVar19 = *pbVar19 | (byte)unaff_EBX;
  *(undefined2 *)(puVar6 + uVar13) = uVar22;
  *pbVar19 = *pbVar19 + (char)pbVar19;
  bVar7 = (char)pbVar19 - 0x30;
  uVar12 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar9 >> 8) + *(char *)((uVar9 | (uint)bVar7) + 2),bVar7);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar10 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  uVar12 = (uint)puVar8 & 0xffffff00;
  pcVar11 = (char *)(uVar12 | (uint)bVar7);
  bVar17 = (byte)(uVar12 >> 8);
  pcVar11[unaff_ESI] = pcVar11[unaff_ESI] | bVar17;
  *pcVar11 = *pcVar11 + bVar7;
  bVar7 = (char)puVar8 - 0x28;
  uVar14 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11(bVar17 + *(char *)((uVar12 | (uint)bVar7) + 2),bVar7);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar12 = (uint)((uVar12 & 1) != 0);
  iVar2 = *(int *)(uVar14 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar14 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  bVar7 = (char)puVar8 + 8;
  uVar14 = (uint)puVar8 & 0xffffff00;
  pbVar19 = (byte *)(uVar14 | (uint)bVar7);
  uVar22 = *(undefined2 *)
            ((int)(puVar6 + iVar2 + (uint)((uVar9 & 1) != 0) + iVar10 + uVar13) + uVar12);
  *pbVar19 = *pbVar19 | bVar18;
  *(undefined2 *)((int)(puVar6 + iVar2 + (uint)((uVar9 & 1) != 0) + iVar10 + uVar13) + uVar12) =
       uVar22;
  *pbVar19 = *pbVar19 + bVar7;
  bVar7 = (char)puVar8 - 0x28;
  cVar1 = *(char *)((uVar14 | (uint)bVar7) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(((uint)puVar8 & 0xffff0000 | (uint)CONCAT11((char)(uVar14 >> 8) + cVar1,bVar7))
                   + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  pcVar11 = (char *)(((uint)puVar8 & 0xffffff00 | (uint)(byte)((char)puVar8 + 8)) + 1);
  if (in_PF) {
    pcVar11[unaff_ESI] = pcVar11[unaff_ESI] | bVar21;
    *pcVar11 = *pcVar11 + (char)pcVar11;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack

void TimerTimeout(uint uParm1,undefined4 uParm2,byte bParm3)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined *puVar6;
  byte bVar7;
  byte bVar13;
  uint uVar8;
  uint *puVar9;
  char *pcVar10;
  uint uVar11;
  byte *pbVar12;
  byte bVar14;
  uint *unaff_EBX;
  int unaff_ESI;
  undefined2 uVar15;
  bool in_PF;
  
  bVar7 = (char)uParm1 - 0x30;
  uVar8 = uParm1 & 0xffff0000 |
          (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                         *(char *)((uParm1 & 0xffffff00 | (uint)bVar7) + 2),bVar7);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar8 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar8 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  bVar7 = (char)puVar9 + 8;
  uVar8 = (uint)puVar9 & 0xffffff00;
  pcVar10 = (char *)(uVar8 | (uint)bVar7);
  bVar14 = (byte)((uint)unaff_EBX >> 8);
  *(byte *)((int)unaff_EBX + 7) = *(byte *)((int)unaff_EBX + 7) ^ bVar14;
  pcVar10[unaff_ESI] = pcVar10[unaff_ESI] | bParm3;
  *pcVar10 = *pcVar10 + bVar7;
  bVar7 = (char)puVar9 - 0x28;
  uVar11 = (uint)puVar9 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar8 >> 8) + *(char *)((uVar8 | (uint)bVar7) + 2),bVar7);
  uVar8 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar5 = (uint)((uVar8 & 1) != 0);
  puVar6 = &stack0x00000000 + *(int *)(uVar11 + 4) + (uint)((uVar2 & 1) != 0) + iVar3;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar11 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  uVar2 = (uint)puVar9 & 0xffffff00;
  pbVar12 = (byte *)((uVar2 | (uint)(byte)((char)puVar9 + 8)) ^ 0x7b);
  uVar15 = *(undefined2 *)(puVar6 + uVar5);
  *pbVar12 = *pbVar12 | (byte)unaff_EBX;
  *(undefined2 *)(puVar6 + uVar5) = uVar15;
  *pbVar12 = *pbVar12 + (char)pbVar12;
  bVar7 = (char)pbVar12 - 0x30;
  uVar8 = (uint)puVar9 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar2 >> 8) + *(char *)((uVar2 | (uint)bVar7) + 2),bVar7);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar8 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar8 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  bVar7 = (char)puVar9 + 8;
  uVar8 = (uint)puVar9 & 0xffffff00;
  pcVar10 = (char *)(uVar8 | (uint)bVar7);
  bVar13 = (byte)(uVar8 >> 8);
  pcVar10[unaff_ESI] = pcVar10[unaff_ESI] | bVar13;
  *pcVar10 = *pcVar10 + bVar7;
  bVar7 = (char)puVar9 - 0x28;
  uVar11 = (uint)puVar9 & 0xffff0000 |
           (uint)CONCAT11(bVar13 + *(char *)((uVar8 | (uint)bVar7) + 2),bVar7);
  uVar8 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar8 = (uint)((uVar8 & 1) != 0);
  iVar4 = *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar11 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  bVar7 = (char)puVar9 + 8;
  uVar11 = (uint)puVar9 & 0xffffff00;
  pbVar12 = (byte *)(uVar11 | (uint)bVar7);
  uVar15 = *(undefined2 *)(puVar6 + iVar4 + (uint)((uVar2 & 1) != 0) + iVar3 + uVar5 + uVar8);
  *pbVar12 = *pbVar12 | (byte)((uint)uParm2 >> 8);
  *(undefined2 *)(puVar6 + iVar4 + (uint)((uVar2 & 1) != 0) + iVar3 + uVar5 + uVar8) = uVar15;
  *pbVar12 = *pbVar12 + bVar7;
  bVar7 = (char)puVar9 - 0x28;
  cVar1 = *(char *)((uVar11 | (uint)bVar7) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(((uint)puVar9 & 0xffff0000 | (uint)CONCAT11((char)(uVar11 >> 8) + cVar1,bVar7))
                   + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  pcVar10 = (char *)(((uint)puVar9 & 0xffffff00 | (uint)(byte)((char)puVar9 + 8)) + 1);
  if (in_PF) {
    pcVar10[unaff_ESI] = pcVar10[unaff_ESI] | bVar14;
    *pcVar10 = *pcVar10 + (char)pcVar10;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int close(int __fd)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined *puVar6;
  byte bVar7;
  byte bVar13;
  uint uVar8;
  uint *puVar9;
  byte *pbVar10;
  char *pcVar11;
  uint uVar12;
  byte in_DH;
  uint *unaff_EBX;
  int unaff_ESI;
  undefined2 uVar14;
  bool in_PF;
  
  bVar7 = (char)__fd - 0x30;
  uVar8 = __fd & 0xffff0000U |
          (uint)CONCAT11((char)((__fd & 0xffffff00U) >> 8) +
                         *(char *)((__fd & 0xffffff00U | (uint)bVar7) + 2),bVar7);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar5 = (uint)((uVar2 & 1) != 0);
  puVar6 = &stack0x00000000 + *(int *)(uVar8 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar8 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  uVar2 = (uint)puVar9 & 0xffffff00;
  pbVar10 = (byte *)((uVar2 | (uint)(byte)((char)puVar9 + 8)) ^ 0x7b);
  uVar14 = *(undefined2 *)(puVar6 + uVar5);
  *pbVar10 = *pbVar10 | (byte)unaff_EBX;
  *(undefined2 *)(puVar6 + uVar5) = uVar14;
  *pbVar10 = *pbVar10 + (char)pbVar10;
  bVar7 = (char)pbVar10 - 0x30;
  uVar8 = (uint)puVar9 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar2 >> 8) + *(char *)((uVar2 | (uint)bVar7) + 2),bVar7);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar8 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar8 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  bVar7 = (char)puVar9 + 8;
  uVar8 = (uint)puVar9 & 0xffffff00;
  pcVar11 = (char *)(uVar8 | (uint)bVar7);
  bVar13 = (byte)(uVar8 >> 8);
  pcVar11[unaff_ESI] = pcVar11[unaff_ESI] | bVar13;
  *pcVar11 = *pcVar11 + bVar7;
  bVar7 = (char)puVar9 - 0x28;
  uVar12 = (uint)puVar9 & 0xffff0000 |
           (uint)CONCAT11(bVar13 + *(char *)((uVar8 | (uint)bVar7) + 2),bVar7);
  uVar8 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar8 = (uint)((uVar8 & 1) != 0);
  iVar4 = *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(uVar12 + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  bVar7 = (char)puVar9 + 8;
  uVar12 = (uint)puVar9 & 0xffffff00;
  pbVar10 = (byte *)(uVar12 | (uint)bVar7);
  uVar14 = *(undefined2 *)(puVar6 + iVar4 + (uint)((uVar2 & 1) != 0) + iVar3 + uVar5 + uVar8);
  *pbVar10 = *pbVar10 | in_DH;
  *(undefined2 *)(puVar6 + iVar4 + (uint)((uVar2 & 1) != 0) + iVar3 + uVar5 + uVar8) = uVar14;
  *pbVar10 = *pbVar10 + bVar7;
  bVar7 = (char)puVar9 - 0x28;
  cVar1 = *(char *)((uVar12 | (uint)bVar7) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar9 = (uint *)(((uint)puVar9 & 0xffff0000 | (uint)CONCAT11((char)(uVar12 >> 8) + cVar1,bVar7))
                   + 2);
  *puVar9 = *puVar9 | (uint)puVar9;
  pcVar11 = (char *)(((uint)puVar9 & 0xffffff00 | (uint)(byte)((char)puVar9 + 8)) + 1);
  if (in_PF) {
    pcVar11[unaff_ESI] = pcVar11[unaff_ESI] | (byte)((uint)unaff_EBX >> 8);
    *pcVar11 = *pcVar11 + (char)pcVar11;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_attr_getschedparam(pthread_attr_t *__attr,sched_param *__param)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  byte bVar5;
  byte bVar11;
  uint uVar6;
  uint *puVar7;
  char *pcVar8;
  uint uVar9;
  byte *pbVar10;
  uint *unaff_EBX;
  int unaff_ESI;
  undefined2 uVar12;
  bool in_PF;
  
  bVar5 = (char)__attr - 0x30;
  uVar6 = (uint)__attr & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__attr & 0xffffff00) >> 8) +
                         *(char *)(((uint)__attr & 0xffffff00 | (uint)bVar5) + 2),bVar5);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  iVar3 = *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar5 = (char)puVar7 + 8;
  uVar6 = (uint)puVar7 & 0xffffff00;
  pcVar8 = (char *)(uVar6 | (uint)bVar5);
  bVar11 = (byte)(uVar6 >> 8);
  pcVar8[unaff_ESI] = pcVar8[unaff_ESI] | bVar11;
  *pcVar8 = *pcVar8 + bVar5;
  bVar5 = (char)puVar7 - 0x28;
  uVar9 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11(bVar11 + *(char *)((uVar6 | (uint)bVar5) + 2),bVar5);
  uVar6 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar6 & 1) != 0);
  iVar4 = *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar9 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  bVar5 = (char)puVar7 + 8;
  uVar9 = (uint)puVar7 & 0xffffff00;
  pbVar10 = (byte *)(uVar9 | (uint)bVar5);
  uVar12 = *(undefined2 *)(&stack0x00000000 + iVar4 + (uint)((uVar2 & 1) != 0) + iVar3 + uVar6);
  *pbVar10 = *pbVar10 | (byte)((uint)__param >> 8);
  *(undefined2 *)(&stack0x00000000 + iVar4 + (uint)((uVar2 & 1) != 0) + iVar3 + uVar6) = uVar12;
  *pbVar10 = *pbVar10 + bVar5;
  bVar5 = (char)puVar7 - 0x28;
  cVar1 = *(char *)((uVar9 | (uint)bVar5) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(((uint)puVar7 & 0xffff0000 | (uint)CONCAT11((char)(uVar9 >> 8) + cVar1,bVar5)) +
                   2);
  *puVar7 = *puVar7 | (uint)puVar7;
  pcVar8 = (char *)(((uint)puVar7 & 0xffffff00 | (uint)(byte)((char)puVar7 + 8)) + 1);
  if (in_PF) {
    pcVar8[unaff_ESI] = pcVar8[unaff_ESI] | (byte)((uint)unaff_EBX >> 8);
    *pcVar8 = *pcVar8 + (char)pcVar8;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Unknown calling convention yet parameter storage is locked

int pthread_setspecific(pthread_key_t __key,void *__pointer)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  uint uVar5;
  uint *puVar6;
  byte *pbVar7;
  char *pcVar8;
  uint *unaff_EBX;
  int unaff_ESI;
  undefined2 uVar9;
  bool in_PF;
  
  bVar4 = (char)__key - 0x30;
  uVar5 = __key & 0xffff0000 |
          (uint)CONCAT11((char)((__key & 0xffffff00) >> 8) +
                         *(char *)((__key & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar2 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar2 & 1) != 0);
  iVar3 = *(int *)(uVar5 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(uVar5 + 2);
  *puVar6 = *puVar6 | (uint)puVar6;
  bVar4 = (char)puVar6 + 8;
  uVar5 = (uint)puVar6 & 0xffffff00;
  pbVar7 = (byte *)(uVar5 | (uint)bVar4);
  uVar9 = *(undefined2 *)(&stack0x00000000 + iVar3 + uVar2);
  *pbVar7 = *pbVar7 | (byte)((uint)__pointer >> 8);
  *(undefined2 *)(&stack0x00000000 + iVar3 + uVar2) = uVar9;
  *pbVar7 = *pbVar7 + bVar4;
  bVar4 = (char)puVar6 - 0x28;
  cVar1 = *(char *)((uVar5 | (uint)bVar4) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar6 = (uint *)(((uint)puVar6 & 0xffff0000 | (uint)CONCAT11((char)(uVar5 >> 8) + cVar1,bVar4)) +
                   2);
  *puVar6 = *puVar6 | (uint)puVar6;
  pcVar8 = (char *)(((uint)puVar6 & 0xffffff00 | (uint)(byte)((char)puVar6 + 8)) + 1);
  if (in_PF) {
    pcVar8[unaff_ESI] = pcVar8[unaff_ESI] | (byte)((uint)unaff_EBX >> 8);
    *pcVar8 = *pcVar8 + (char)pcVar8;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unknown calling convention yet parameter storage is locked

void free(void *__ptr)

{
  char cVar1;
  byte bVar2;
  uint *puVar3;
  char *pcVar4;
  uint *unaff_EBX;
  int unaff_ESI;
  bool in_PF;
  
  bVar2 = (char)__ptr - 0x30;
  cVar1 = *(char *)(((uint)__ptr & 0xffffff00 | (uint)bVar2) + 2);
  *unaff_EBX = *unaff_EBX >> 1;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar3 = (uint *)(((uint)__ptr & 0xffff0000 |
                    (uint)CONCAT11((char)(((uint)__ptr & 0xffffff00) >> 8) + cVar1,bVar2)) + 2);
  *puVar3 = *puVar3 | (uint)puVar3;
  pcVar4 = (char *)(((uint)puVar3 & 0xffffff00 | (uint)(byte)((char)puVar3 + 8)) + 1);
  if (in_PF) {
    pcVar4[unaff_ESI] = pcVar4[unaff_ESI] | (byte)((uint)unaff_EBX >> 8);
    *pcVar4 = *pcVar4 + (char)pcVar4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
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

void __stdcall main(void)

{
  undefined4 in_ECX;
  undefined *unaff_EDI;
  
  *unaff_EDI = (char)((uint)in_ECX >> 8);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0805629c) overlaps instruction at (ram,0x0805629b)
// 
// WARNING: Removing unreachable block (ram,0x080561aa)
// WARNING: Removing unreachable block (ram,0x0805622f)
// WARNING: Removing unreachable block (ram,0x0805629c)
// WARNING: Removing unreachable block (ram,0x080562a2)
// WARNING: Removing unreachable block (ram,0x08056238)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// operator delete(void*)

void operator_delete(void *param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  ushort uVar8;
  undefined *puVar9;
  uint *puVar10;
  uint uVar11;
  char cVar13;
  uint in_ECX;
  uint uVar12;
  int *in_EDX;
  uint uVar14;
  int unaff_EBX;
  uint uVar15;
  byte *pbVar16;
  int unaff_EBP;
  undefined *unaff_ESI;
  undefined4 *puVar17;
  int unaff_EDI;
  int in_FS_OFFSET;
  bool bVar18;
  byte in_AF;
  undefined2 uStack70;
  
  bVar5 = (byte)param_1;
  out(0x2f,bVar5);
  uVar15 = unaff_EBX * 2;
  out(*unaff_ESI,(short)in_EDX);
  if ((in_ECX & 0xffffff00 | (uint)((byte)in_ECX & *(byte *)(unaff_EDI + 2))) != 0) {
    out(unaff_ESI[1],(short)in_EDX);
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  bVar7 = 9 < (bVar5 & 0xf) | in_AF;
  bVar5 = bVar5 + bVar7 * -6;
  pbVar16 = (byte *)((uint)param_1 & 0xffffff00 |
                    (uint)(byte)(bVar5 + (0x9f < bVar5 | unaff_EBX < 0 | bVar7 * (bVar5 < 6)) *
                                         -0x60));
  *in_EDX = *in_EDX << 1;
  *pbVar16 = *pbVar16 | (byte)((uint)param_1 >> 8);
  *(undefined *)(unaff_EBP + 0x52016ef3) = *(undefined *)(unaff_EBP + 0x52016ef3);
  *(uint *)(pbVar16 + 0x22) = *(uint *)(pbVar16 + 0x22) & 0x28;
  uVar11 = (uint)(pbVar16 + 1) & 0xffff0000 |
           (uint)(ushort)((short)(char)(pbVar16 + 1) * (short)(char)unaff_ESI[0xc]);
  puVar9 = &DAT_962f8608 + uVar11;
  bVar7 = 9 < ((byte)puVar9 & 0xf) | bVar7;
  bVar6 = (byte)puVar9 + bVar7 * -6;
  bVar6 = bVar6 + (0x9f < bVar6 | 0x69d079f7 < uVar11 | bVar7 * (bVar6 < 6)) * -0x60;
  bVar7 = 9 < (bVar6 & 0xf) | bVar7;
  bVar6 = bVar6 + bVar7 * -6;
  bVar6 = bVar6 + (0x9f < bVar6 |
                  (byte)unaff_ESI[1] < *(byte *)(unaff_EDI + -1) | bVar7 * (bVar6 < 6)) * -0x60;
  puVar4 = (uint *)((uint)puVar9 & 0xffffff00 | (uint)bVar6);
  out(0x2f,bVar6);
  bVar5 = *(byte *)(unaff_EDI + 0x53);
  puVar10 = (uint *)(unaff_EDI * 3 + 0x2aa86a12);
  *puVar10 = *puVar10 >> 1 | (uint)((*puVar10 & 1) != 0) << 0x1f;
  cVar13 = *(char *)(unaff_EDI + -0x5f76910d);
  *puVar4 = *puVar4 | (uint)puVar4;
  puVar10 = (uint *)((int)puVar4 + -1);
  *puVar10 = *puVar10 | (uint)puVar10;
  *puVar4 = *puVar4 | (uint)puVar10;
  iVar1 = (uint)(byte)((bVar5 & 1) + cVar13) * 2;
  *(byte *)puVar4 = *(byte *)puVar4 | (byte)(((uint)puVar9 & 0xffffff00) >> 8);
  *(byte *)(uVar15 + 0x6fe37e74) = *(byte *)(uVar15 + 0x6fe37e74) | (byte)iVar1;
  puVar17 = (undefined4 *)((int)(unaff_ESI + 2) * 0x6a);
  uVar8 = (short)(char)(bVar6 * unaff_ESI[-8]) * (short)*(char *)(iVar1 + 0xb);
  uVar11 = (uint)uVar8;
  _DAT_40410b64 = (uint)puVar9 & 0xffff0000 | uVar11;
  uVar2 = (uint)CONCAT11(0x5e,(char)in_EDX);
  uVar14 = (uint)in_EDX & 0xffff0000 | uVar2;
  bVar5 = (byte)(uVar11 >> 8);
  uVar3 = uVar15 & 0xffff0000;
  bVar7 = (byte)((uint)iVar1 >> 8);
  cVar13 = bVar7 + bVar5;
  puVar10 = (uint *)(uint)CONCAT11(cVar13,(byte)iVar1);
  if (cVar13 == 0) {
    uVar12 = (uint)puVar10 | *puVar10;
    out(4,(uint)puVar9 & 0xffff0000 | uVar11 & 0xffffff00 |
          (uint)(byte)(((char)uVar8 -
                       *(char *)((uVar3 | (uint)CONCAT11((char)(uVar15 >> 8) + bVar5,(char)uVar15))
                                + 0xe364a36b)) - CARRY1(bVar7,bVar5)));
    uVar15 = (uint)CONCAT11((char)(uVar2 >> 8),(char)uVar15);
    pbVar16 = (byte *)(uVar3 | uVar15);
    bVar5 = (byte)(uVar15 >> 8);
    *pbVar16 = *pbVar16 | bVar5;
    _DAT_02744064 = (uint)pbVar16 ^ uVar14;
    uStack70 = (undefined2)((uint)(byte *)(unaff_EDI + -1) >> 0x10);
    uVar11 = (uint)(ushort)((ushort)(*(byte *)((uVar12 & 0xffffff00 |
                                                (uint)(byte)((char)uVar12 + bVar5) |
                                               *(uint *)((uVar3 | uVar15 & 0xffffff00) - 0x1d)) +
                                              0x3cf8aee0) & 0x2b) << 8 | 0xb8) & 0xffffff00 |
             0x8f3e0000 | (uint)(byte)(CARRY4(uVar14,*(uint *)((int)puVar17 + 0x72)) + 0x22);
    bVar7 = (byte)(uVar11 + 0x55149455);
    bVar5 = bVar7 + 6;
    bVar18 = 0xf9 < bVar7 || CARRY1(bVar5,0xaaeb6baa < uVar11);
    bVar5 = bVar5 + (0xaaeb6baa < uVar11);
    bVar7 = bVar5 + 0xa7;
    out(*puVar17,uStack70);
    uVar15 = (uint)(ushort)((short)(char)((bVar7 + bVar18 + -0x1d +
                                          (0x58 < bVar5 || CARRY1(bVar7,bVar18))) *
                                         *(char *)((int)puVar17 + -6)) *
                           (short)*(char *)(unaff_EDI + 10));
    pbVar16 = (byte *)(in_FS_OFFSET + (uVar11 + 0x55149455 & 0xffff0000 | uVar15));
    *pbVar16 = *pbVar16 | (byte)(uVar15 >> 8);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0805662a) overlaps instruction at (ram,0x08056626)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x08056586)
// WARNING: Removing unreachable block (ram,0x08056598)
// WARNING: Removing unreachable block (ram,0x080565b9)
// operator new(unsigned int)

void * operator_new(uint param_1)

{
  char *pcVar1;
  int iVar2;
  byte bVar3;
  uint uVar4;
  int iVar5;
  byte bVar6;
  ushort uVar7;
  int *piVar8;
  byte bVar11;
  uint uVar9;
  int iVar10;
  uint in_ECX;
  undefined2 uVar12;
  uint in_EDX;
  byte bVar14;
  int iVar13;
  int unaff_EBX;
  int *piVar15;
  char *unaff_ESI;
  int unaff_EDI;
  byte in_AF;
  
  bVar6 = (byte)param_1;
  out(0x2f,bVar6);
  uVar12 = (undefined2)in_EDX;
  out(*unaff_ESI,uVar12);
  if ((in_ECX & 0xffffff00 | (uint)((byte)in_ECX & *(byte *)(unaff_EDI + 2))) != 0) {
    out(unaff_ESI[1],uVar12);
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  bVar3 = 9 < (bVar6 & 0xf) | in_AF;
  bVar6 = bVar6 + bVar3 * -6;
  bVar6 = bVar6 + (0x9f < bVar6 | unaff_EBX < 0 | bVar3 * (bVar6 < 6)) * -0x60;
  piVar15 = (int *)(unaff_EBX * 4);
  out(unaff_ESI[1],uVar12);
  bVar14 = (byte)(in_EDX >> 8);
  piVar8 = (int *)((param_1 & 0xffffff00 | (uint)bVar6) + 0xe38b0529);
  *piVar8 = *piVar8 + unaff_EBX * -4;
  out(*(undefined4 *)(unaff_ESI + 2),uVar12);
  iVar10 = *piVar15;
  pcVar1 = unaff_ESI + 10;
  out(*(undefined4 *)(unaff_ESI + 6),uVar12);
  uVar7 = (short)(char)(bVar6 * unaff_ESI[-4] & 9) * (short)*unaff_ESI;
  piVar8 = (int *)(param_1 & 0xffff0000 | (uint)uVar7);
  iVar2 = *piVar15;
  uVar4 = (uint)CONCAT11((char)((uint)piVar15 >> 8) * 2,(char)piVar15);
  *piVar8 = *piVar8 + 1;
  ((byte *)((int)piVar8 + 7))[(int)pcVar1] = ((byte *)((int)piVar8 + 7))[(int)pcVar1] + (char)uVar7;
  *(byte *)piVar8 = *(byte *)piVar8 | (byte)(uVar4 >> 8);
  *(byte *)piVar8 = *(byte *)piVar8 | bVar14;
  *(byte *)((int)piVar8 + 0x787d467) =
       *(byte *)((int)piVar8 + 0x787d467) | (byte)((uint)(piVar8 + 0x1e1f502) >> 8);
  piVar8 = piVar8 + 0x33b5904;
  bVar11 = (byte)((uint)piVar8 >> 8);
  uVar7 = CONCAT11(bVar14 | bVar11,(char)in_EDX);
  bVar3 = 9 < ((byte)piVar8 & 0xf) | bVar3;
  bVar6 = (byte)piVar8 + bVar3 * -6;
  iVar5 = (int)register0x00000010 * 2;
  out(*pcVar1,uVar7);
  iVar13 = (in_EDX & 0xffff0000 | (uint)uVar7) + iVar10 * 0x868f600;
  uVar12 = (undefined2)iVar13;
  if (iVar10 * 0x868f600 == 0) {
    *(undefined4 *)(iVar5 + -4) = 0xe400d605;
    uVar9 = ((uint)piVar8 & 0xffff0000 |
            (uint)(byte)(bVar6 + (0x9f < bVar6 | bVar3 * (bVar6 < 6)) * -0x60 + bVar11 * -0xd)) +
            0xe3e504d1;
    out(*(undefined4 *)(unaff_ESI + 0xb),uVar12);
    piVar8 = (int *)(unaff_EDI + -3);
    uVar7 = (short)(char)uVar9 * (short)unaff_ESI[0x3a];
    uVar9 = uVar9 & 0xffff0000;
    iVar10 = (uVar9 | (uint)(ushort)((short)(char)uVar7 *
                                     (short)*(char *)((uVar9 | (uint)uVar7) + 0x6c) + 0xb408)) -
             *piVar8;
    bVar6 = *(byte *)(unaff_EDI + 0x3f);
    *(int *)(iVar5 + -8) = iVar10;
    *(uint *)(iVar5 + -0xc) = (uint)(bVar6 & 1);
    *(int *)(iVar5 + -0x10) = iVar13;
    *(uint *)(&DAT_ffffffec + iVar5) = (uint)piVar15 & 0xffff0000 | uVar4;
    *(int *)(iVar5 + -0x18) = iVar5 + -4;
    *(int *)(iVar5 + -0x1c) = iVar2 * 0x968f643;
    *(char **)(iVar5 + -0x20) = unaff_ESI + 0xf;
    *(int **)(iVar5 + -0x24) = piVar8;
    *(int *)(iVar10 + 0x6ef38d0e) = *(int *)(iVar10 + 0x6ef38d0e) + -1;
    *(byte *)piVar8 = (byte)iVar10 | (byte)*(undefined4 *)(iVar10 + 9);
    in(6);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  out(unaff_ESI[0xb],uVar12);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack

void FUN_0806f667(int iParm1,undefined4 uParm2,int iParm3)

{
  byte *pbVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  int unaff_ESI;
  undefined4 *unaff_EDI;
  byte local_8;
  
  if (iParm3 != 0) {
    pbVar1 = (byte *)((iParm1 + 0x83410bd1U & 0xffff0000 |
                      (uint)(ushort)((short)(char)(iParm1 + 0x83410bd1U) *
                                    (short)*(char *)(unaff_ESI + 0xb))) + 0x860806f9);
    *pbVar1 = *pbVar1 | (char)((uint)uParm2 >> 8) * 2;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = in((short)uParm2);
  iVar3 = *(int *)(unaff_ESI + -0x23);
  local_8 = (byte)uParm2;
  if ((uVar4 & 0xffffff00 | (uint)(byte)((byte)uVar4 | local_8)) != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar2 = in((short)uParm2);
  *unaff_EDI = uVar2;
  *(undefined4 *)(uVar4 + iVar3 + -4) = uParm2;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
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

void __divdi3_i4(uint uParm1,undefined4 uParm2,uint uParm3)

{
  uint uVar1;
  uint uVar2;
  bool bVar3;
  uint uVar4;
  byte bVar5;
  char **ppcVar6;
  uint uVar7;
  char *pcVar8;
  char cVar9;
  uint *puVar10;
  byte bVar11;
  int unaff_EBP;
  byte *unaff_ESI;
  byte *unaff_EDI;
  byte in_CF;
  bool bVar12;
  
  bVar5 = *unaff_EDI;
  *unaff_EDI = (byte)(uParm3 >> 8);
  uVar4 = (uint)CONCAT11(bVar5,(byte)uParm3);
  puVar10 = (uint *)(unaff_EBP + -0x6a);
  uVar2 = (uint)in_CF;
  uVar1 = *puVar10;
  uVar7 = *puVar10;
  uVar1 = *puVar10;
  *puVar10 = uVar1 + uParm1 + uVar2;
  bVar12 = 9 < ((byte)uParm1 & 0xf) ||
           ((uVar7 & 0xfffffff) + (uParm1 & 0xfffffff) + uVar2 & 0x10000000) != 0;
  bVar5 = (byte)uParm1 + bVar12 * -6;
  bVar5 = bVar5 + (0x9f < bVar5 |
                  (CARRY4(uVar1,uParm1) || CARRY4(uVar1 + uParm1,uVar2)) | bVar12 * (bVar5 < 6)) *
                  -0x60;
  bVar12 = 9 < (bVar5 & 0xf) || bVar12;
  bVar5 = bVar5 + bVar12 * -6;
  bVar5 = bVar5 + (0x9f < bVar5 | *unaff_ESI < *unaff_EDI | bVar12 * (bVar5 < 6)) * -0x60;
  out(0x2f,bVar5);
  puVar10 = (uint *)(uParm3 & 0xffff0000 | uVar4 & 0xffffff00 |
                    (uint)((byte)uParm3 & unaff_EDI[-0xc]));
  out(unaff_ESI[1],(ushort)uParm2 & 0xff00 | (ushort)(byte)((char)uParm2 + (char)(uVar4 >> 8)));
  uVar1 = *puVar10;
  bVar12 = bVar5 < 0x8b;
  bVar5 = bVar5 + 0x75;
  uVar7 = uParm1 & 0xffffff00 | (uint)bVar5;
  bVar11 = (byte)uVar1;
  bVar11 = bVar11 + bVar5 + bVar12;
  _bVar11 = (char *)(uVar1 & 0xffffff00 | (uint)bVar11);
  _cVar9 = (char *)((int)puVar10 + -1);
  cVar9 = (char)_cVar9;
  if (_cVar9 == (char *)0x0 || bVar11 != 0) {
    bVar3 = 9 < (bVar5 & 0xf) || ((bVar11 & 0xf) + (bVar5 & 0xf) + bVar12 & 0x10) != 0;
    bVar11 = bVar5 + bVar3 * -6;
    uVar1 = uParm1 & 0xffffff00 |
            (uint)(byte)(bVar11 + (0x9f < bVar11 |
                                  (CARRY1(bVar11,bVar5) || CARRY1(bVar11 + bVar5,bVar12)) |
                                  bVar3 * (bVar11 < 6)) * -0x60);
    ppcVar6 = (char **)(uVar1 | *(uint *)(uVar1 + 9));
    *(char *)((int)ppcVar6 + 0x27f042a) =
         *(char *)((int)ppcVar6 + 0x27f042a) + (char)((uint)_cVar9 >> 8);
    *ppcVar6 = _cVar9;
    *_bVar11 = *_bVar11 + cVar9;
    uVar7 = (uint)ppcVar6 & 0xffff00ff;
  }
  out(*(undefined4 *)(unaff_ESI + 2),(short)_bVar11);
  pcVar8 = (char *)(uVar7 & 0xffff0000 |
                   (uint)(ushort)((short)(char)uVar7 * (short)(char)unaff_ESI[-4]));
  *_cVar9 = *_cVar9 + cVar9;
  *pcVar8 = *pcVar8 + cVar9;
  _bVar11[0x61] = _bVar11[0x61] + cVar9;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x080700e7) overlaps instruction at (ram,0x080700e6)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x0807006a)
// WARNING: Removing unreachable block (ram,0x08070072)
// WARNING: Removing unreachable block (ram,0x08070097)
// WARNING: Removing unreachable block (ram,0x0807009a)
// WARNING: Removing unreachable block (ram,0x080700aa)
// WARNING: Removing unreachable block (ram,0x080700c4)
// WARNING: Removing unreachable block (ram,0x080700c8)
// WARNING: Removing unreachable block (ram,0x080700ca)
// WARNING: Removing unreachable block (ram,0x080700d6)
// WARNING: Removing unreachable block (ram,0x0807011d)
// WARNING: Removing unreachable block (ram,0x0807012a)
// WARNING: Removing unreachable block (ram,0x08070105)
// WARNING: Removing unreachable block (ram,0x08070134)
// WARNING: Removing unreachable block (ram,0x0807013f)
// WARNING: Removing unreachable block (ram,0x080700e7)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __udivdi3_i4(uint uParm1,uint uParm2,uint uParm3)

{
  int *piVar1;
  undefined2 *puVar2;
  byte bVar3;
  undefined uVar4;
  undefined4 uVar5;
  byte bVar6;
  int iVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  char cVar11;
  ushort uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint *puVar17;
  uint *puVar18;
  byte bVar19;
  char cVar20;
  int iVar21;
  uint *puVar22;
  uint *puVar23;
  byte bVar24;
  undefined2 uVar25;
  uint *puVar26;
  byte bVar27;
  uint unaff_EBX;
  int *piVar28;
  int *piVar29;
  int *piVar30;
  undefined *puVar31;
  undefined *puVar32;
  undefined *puVar33;
  undefined *puVar34;
  int iVar35;
  undefined *puVar36;
  int *piVar37;
  uint uVar38;
  uint uVar39;
  undefined *puVar40;
  undefined *unaff_ESI;
  undefined4 *puVar41;
  char *pcVar42;
  byte *unaff_EDI;
  byte *pbVar43;
  undefined4 *puVar44;
  int iVar45;
  undefined2 uVar46;
  undefined2 in_SS;
  undefined2 in_DS;
  int in_GS_OFFSET;
  bool in_PF;
  byte in_AF;
  bool bVar47;
  bool bVar48;
  int in_stack_00000000;
  
  bVar9 = (byte)uParm1;
  out(0x2f,bVar9);
  bVar19 = (char)uParm3 + (char)(uParm1 >> 8) & unaff_EDI[5];
  _bVar19 = (char *)(uParm3 & 0xffffff00 | (uint)bVar19);
  cVar11 = (char)unaff_EBX;
  bVar27 = cVar11 * 2;
  bVar48 = bVar27 == 0;
  out(*unaff_ESI,(short)uParm2);
  bVar47 = (cVar11 < 0 != (char)bVar27 < 0) != (char)bVar27 < 0;
  puVar41 = (undefined4 *)(unaff_ESI + 1);
  if (bVar48 || bVar47) {
    in_AF = 9 < (bVar9 & 0xf) | in_AF;
    bVar9 = bVar9 + in_AF * -6;
    uVar13 = uParm1 & 0xffffff00 |
             (uint)(byte)(bVar9 + (0x9f < bVar9 | cVar11 < 0 | in_AF * (bVar9 < 6)) * -0x60);
    uVar13 = uVar13 | *(uint *)(uVar13 + 9);
    bVar27 = bVar27 + (char)(uVar13 >> 8);
    puVar41 = (undefined4 *)(unaff_ESI + 5);
    out(*(undefined4 *)(unaff_ESI + 1),(short)uParm2);
    unaff_EDI = unaff_EDI + -1;
    uVar12 = (short)(char)uVar13 * (short)(char)unaff_ESI[0x10];
    *_bVar19 = *_bVar19 + bVar19;
    uParm1 = uVar13 & 0xffff0000 | (uint)uVar12 & 0xffffff00 |
             (uint)(byte)((char)uVar12 + (char)((uint)uVar12 >> 8));
  }
  puVar17 = (uint *)(unaff_EBX & 0xffffff00 | (uint)bVar27);
  bVar48 = bVar48 || bVar47;
  bVar10 = (byte)uParm1;
  *(byte *)((int)puVar41 + -0x69d887d1) = *(byte *)((int)puVar41 + -0x69d887d1) | bVar10;
  bVar6 = 9 < (bVar10 & 0xf) | in_AF;
  bVar10 = bVar10 + bVar6 * -6;
  bVar8 = (byte)(uParm1 >> 8);
  bVar10 = bVar10 + (0x9f < bVar10 | bVar6 * (bVar10 < 6)) * -0x60;
  bVar9 = *(byte *)puVar41;
  bVar24 = *unaff_EDI;
  bVar6 = 9 < (bVar10 & 0xf) | bVar6;
  bVar10 = bVar10 + bVar6 * -6;
  uVar12 = CONCAT11(0x2f,(byte)uParm2 + bVar8);
  uVar13 = uParm2 & 0xffff0000 | (uint)uVar12;
  if (CARRY1((byte)uParm2,bVar8)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  pbVar43 = unaff_EDI + (uint)bVar48 * -2 + 1 + (uint)bVar48 * -2 + 1;
  bVar3 = in(uVar12);
  unaff_EDI[(uint)bVar48 * -2 + 1] = bVar3;
  puVar26 = (uint *)(uParm1 & 0xffffff00 |
                     (uint)(byte)(bVar10 + (0x9f < bVar10 | bVar9 < bVar24 | bVar6 * (bVar10 < 6)) *
                                           -0x60) | *(uint *)((int)puVar17 + 9));
  _bVar19 = (char *)(uVar13 + 2);
  *_bVar19 = *_bVar19 + bVar27;
  puVar23 = (uint *)((int)puVar26 + in_GS_OFFSET + -0x7d);
  *puVar23 = *puVar23 & 100;
  *(int *)(pbVar43 + -0x69) = *(int *)(pbVar43 + -0x69) << (bVar19 + bVar8 & 0x1f);
  uVar13 = (uParm3 & 0xffff0000 |
           (uint)CONCAT11((char)((uParm3 & 0xffffff00) >> 8) + *(char *)(uVar13 + 0x18011ad2),
                          bVar19 + bVar8)) ^ *puVar26;
  *puVar17 = *puVar17 | (uint)puVar17;
  if ((DAT_89073752 <= bVar27 && (puVar17 < (uint *)0xc7637327) <= (byte)(bVar27 - DAT_89073752)) &&
      (bool)(bVar27 - DAT_89073752) != puVar17 < (uint *)0xc7637327) {
    in_stack_00000000 = *(int *)(in_stack_00000000 + 0x33);
  }
  piVar28 = (int *)(uVar13 + 0x9a2c7);
  *piVar28 = *piVar28 + uVar13;
  bVar19 = DAT_333358d7;
  puVar17 = (uint *)(unaff_EBX & 0xffffff00 | (uint)DAT_333358d7);
  uVar13 = *(uint *)(pbVar43 + in_GS_OFFSET + 9);
  *(char *)(in_stack_00000000 + 2) = *(char *)(in_stack_00000000 + 2) + DAT_333358d7;
  piVar30 = (int *)(*(uint *)(pbVar43 + in_GS_OFFSET + in_stack_00000000 * 4 + 2) ^ 0xff33b233 ^
                   *(uint *)(in_stack_00000000 + 0x1a));
  *puVar17 = *puVar17 + ((uint)puVar26 | uVar13);
  *puVar17 = *puVar17 | (uint)puVar17;
  pbVar43 = (byte *)(*piVar30 + -0x23);
  bVar9 = *pbVar43;
  *pbVar43 = *pbVar43 - bVar19;
  puVar44 = *(undefined4 **)((int)piVar30 + 6);
  pcVar42 = *(char **)((int)piVar30 + 10);
  uVar39 = *(uint *)((int)piVar30 + 0xe);
  piVar28 = *(int **)((int)piVar30 + 0x16);
  puVar26 = *(uint **)((int)piVar30 + 0x1a);
  iVar21 = *(int *)((int)piVar30 + 0x1e);
  uVar14 = *(uint *)((int)piVar30 + 0x22);
  uVar13 = (uint)(bVar9 < bVar19);
  bVar47 = ((((int)piVar30 + 0x26U & 0xfffffff) - (*puVar26 & 0xfffffff)) - uVar13 & 0x10000000) !=
           0;
  iVar45 = (int)piVar30 + (0x26 - *puVar26);
  iVar7 = -uVar13;
  puVar33 = (undefined *)(iVar45 + iVar7);
  *puVar44 = 0x3252051a;
  uVar46 = *(undefined2 *)(iVar45 + iVar7);
  *(undefined4 **)((byte *)((int)puVar26 + 0x77ff32b2) + (int)pcVar42) = puVar44;
  iVar21 = iVar21 + *(int *)((int)piVar28 + -0x76fecdae);
  puVar32 = (undefined *)(iVar45 + iVar7 + -2);
  *(undefined4 *)(iVar45 + iVar7 + -2) = puVar44[-0x11];
  cVar11 = (char)uVar14;
  puVar17 = (uint *)(uVar14 & 0xffff0000 |
                    (uint)CONCAT11((byte)(uVar14 >> 8) ^ *(byte *)((int)piVar28 + 0x61),cVar11));
  _bVar19 = (char *)(iVar21 + 0x13);
  *_bVar19 = *_bVar19 - cVar11;
  puVar41 = (undefined4 *)((int)puVar44 + (uint)bVar48 * -2 + 1);
  uVar25 = SUB42(puVar26,0);
  uVar4 = in(uVar25);
  *(undefined *)puVar44 = uVar4;
  puVar40 = (undefined *)(uVar39 & *(uint *)(uVar39 + 0x7b));
  puVar23 = (uint *)(iVar21 + -1);
  if (puVar23 == (uint *)0x0 || cVar11 != 0) {
code_r0x0806fee2:
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *(char **)(puVar33 + -6) = pcVar42;
    bVar9 = 9 < ((byte)puVar17 & 0xf) | bVar47;
    bVar19 = in(uVar25);
    return (((uint)puVar17 & 0xffff0000 |
            (uint)(CONCAT11((char)((uint)puVar17 >> 8) + bVar9,(byte)puVar17 + bVar9 * 6) & 0xff0f))
           - 0x51ee8b) - (uint)bVar9 & 0xffffff00 | (uint)bVar19;
  }
  do {
    uVar25 = SUB42(puVar26,0);
    bVar9 = (byte)puVar23;
    *(byte *)puVar23 = *(byte *)puVar23 + bVar9;
    *(byte *)puVar23 = *(byte *)puVar23 + bVar9;
    *(byte *)puVar23 = *(byte *)puVar23 + bVar9;
    *(byte *)puVar23 = *(byte *)puVar23 + bVar9;
    *(byte *)puVar23 = *(byte *)puVar23 + bVar9;
    *(byte *)((int)puVar23 + -0x2f) = *(byte *)((int)puVar23 + -0x2f) + (char)((uint)puVar26 >> 8);
    puVar31 = puVar32 + -2;
    *(undefined2 *)(puVar32 + -2) = in_SS;
    bVar47 = (bool)(9 < ((byte)puVar17 & 0xf) | bVar47);
    uVar12 = CONCAT11((char)((uint)puVar17 >> 8) + bVar47,(byte)puVar17 + bVar47 * 6) & 0xff0f;
    uVar39 = (uint)puVar17 & 0xffff0000;
    puVar17 = (uint *)(uVar39 | (uint)uVar12);
    puVar22 = (uint *)((int)puVar23 + 0x9a0eb);
    uVar13 = *puVar22;
    uVar14 = *puVar22;
    *puVar22 = *puVar22 + (int)puVar23;
    if (!SCARRY4(uVar14,(int)puVar23)) {
      bVar27 = (byte)puVar26;
      bVar19 = (byte)((uint)uVar12 >> 8);
      bVar24 = bVar27 + bVar19 + CARRY4(uVar13,(uint)puVar23);
      uVar14 = (uint)puVar26 & 0xffffff00;
      puVar26 = (uint *)(uVar14 | (uint)bVar24);
      *(undefined2 *)(puVar32 + -4) = in_SS;
      bVar47 = 9 < (byte)uVar12 ||
               ((bVar27 & 0xf) + (bVar19 & 0xf) + CARRY4(uVar13,(uint)puVar23) & 0x10) != 0;
      uVar13 = (uint)(CONCAT11(bVar19 + bVar47,(byte)uVar12 + bVar47 * 6) & 0xff0f);
      piVar29 = (int *)(uVar39 | uVar13);
      piVar1 = piVar28 + 0x184af886;
      bVar19 = *(byte *)piVar1;
      *(byte *)piVar1 = *(byte *)piVar1 + bVar9;
      *(int **)(puVar32 + -8) = piVar28;
      *(uint **)(puVar32 + -0xc) = puVar23;
      *(uint **)(puVar32 + -0x10) = puVar26;
      *(int **)(puVar32 + -0x14) = piVar29;
      *(undefined **)(puVar32 + -0x18) = puVar32 + -4;
      *(undefined **)(puVar32 + -0x1c) = puVar40;
      *(char **)(puVar32 + -0x20) = pcVar42;
      *(undefined4 **)(puVar32 + -0x24) = puVar41;
      uVar15 = (int)piVar28 + (-0x1cd16d40 - (uint)CARRY1(bVar19,bVar9));
      *puVar23 = *puVar23 + (int)piVar29;
      bVar9 = (byte)uVar15 - 0x31;
      uVar39 = uVar15 & 0xffffff00;
      uVar16 = uVar39 | (uint)bVar9;
      puVar40 = puVar40 + (-(uint)((byte)uVar15 < 0x31) - puVar26[8]);
      puVar22 = puVar23;
      if (in_PF) {
        *(uint **)(puVar32 + -0x28) = puVar23;
        puVar33 = puVar32 + -0x2a;
        puVar34 = puVar32 + -0x2a;
        puVar31 = puVar32 + -0x2a;
        *(undefined2 *)(puVar32 + -0x2a) = in_DS;
        puVar22 = (uint *)((int)puVar23 + -1);
        if (puVar22 == (uint *)0x0) {
          puVar22 = (uint *)((int)puVar23 + -2);
          uVar39 = uVar16;
          if (puVar22 != (uint *)0x0 && puVar40 == (undefined *)0x0) goto LAB_0806ff69;
          puVar17 = (uint *)(uVar15 & 0xffff0000 |
                            (uint)CONCAT11((byte)(uVar15 >> 8) & *(byte *)puVar22,bVar9));
          *puVar22 = *puVar22 ^ (uint)puVar26;
          puVar23 = (uint *)((int)puVar23 + -3);
          if (puVar23 == (uint *)0x0) {
            pbVar43 = (byte *)(pcVar42 + -0x3d);
            bVar9 = (byte)(uVar13 >> 8);
            bVar47 = ((*pbVar43 & 0xf) - (bVar9 & 0xf) & 0x10) != 0;
            *pbVar43 = *pbVar43 - bVar9;
            goto code_r0x0806ff1f;
          }
          pcVar42[0x29ec0038] = pcVar42[0x29ec0038] + bVar24;
          *(char **)((int)puVar26 + 0x2b02293d) =
               pcVar42 + (int)*(char **)((int)puVar26 + 0x2b02293d);
          *puVar17 = *puVar17 & (uint)piVar29;
          *puVar23 = *puVar23 & (uint)puVar23;
          *(undefined2 *)((int)puVar17 + -0x299d7ccd) = *(undefined2 *)((int)puVar17 + -0x299d7ccd);
          piVar29 = (int *)((uint)puVar26 ^ *(uint *)((int)puVar17 + 0x23012932));
          goto code_r0x0806ff8b;
        }
      }
      else {
LAB_0806ff69:
        uVar16 = uVar39 & 0xffff0000 |
                 (uint)CONCAT11((char)(uVar39 >> 8) + (char)((uint)puVar22 >> 8),DAT_38960009);
        *puVar22 = *puVar22 - uVar16;
        puVar26 = (uint *)CONCAT31((int3)(uVar14 >> 8),0x3d);
        puVar33 = puVar40;
      }
      *puVar26 = *puVar26 - uVar16;
      uVar13 = *puVar22;
      puVar34 = puVar33 + -uVar13;
      *(byte *)puVar22 =
           (*(byte *)puVar22 - (char)(uVar16 >> 8)) - (puVar33 < (undefined *)*puVar22);
      *(uint *)((int)puVar22 + 0x33b863d3) = *(uint *)((int)puVar22 + 0x33b863d3) | (uint)puVar22;
      *(uint *)((int)puVar26 + -0x2a) = *(uint *)((int)puVar26 + -0x2a) & 0x33;
      puVar17 = (uint *)(int)(short)uVar16;
      puVar23 = (uint *)((uint)puVar22 & 0xffff0000 |
                        (uint)CONCAT11((byte)((uint)puVar22 >> 8) ^ *(byte *)puVar22,(char)puVar22))
      ;
      *(undefined **)piVar29 = puVar33 + *piVar29 + -uVar13;
      goto code_r0x0806ff8b;
    }
    piVar29 = piVar28;
    puVar33 = puVar32;
    if (*puVar22 == 0 || SCARRY4(uVar14,(int)puVar23) != (int)*puVar22 < 0) goto code_r0x0806fee2;
code_r0x0806ff1f:
    *(uint **)(puVar31 + -4) = puVar17;
    *(uint **)(puVar31 + -8) = puVar23;
    *(uint **)(puVar31 + -0xc) = puVar26;
    *(int **)(puVar31 + -0x10) = piVar29;
    *(undefined **)(puVar31 + -0x14) = puVar31;
    *(undefined **)(puVar31 + -0x18) = puVar40;
    *(char **)(puVar31 + -0x1c) = pcVar42;
    puVar34 = puVar31 + -0x20;
    puVar32 = puVar31 + -0x20;
    *(undefined4 **)(puVar31 + -0x20) = puVar41;
    uVar25 = SUB42(puVar26,0);
    if (puVar23 == (uint *)0x0) break;
    puVar44 = (undefined4 *)((int)puVar41 + -1);
    cVar11 = pcVar42[-10];
    puVar41 = (undefined4 *)((int)puVar41 + (uint)bVar48 * -8 + 3);
    uVar5 = in(uVar25);
    *puVar44 = uVar5;
    puVar17 = (uint *)((uint)puVar17 & 0xffff0000 |
                      (uint)(ushort)((short)(char)((char)puVar17 * cVar11 *
                                                  *(char *)((int)pcVar42 * 9 + 0x6b)) *
                                    (short)(char)*(byte *)((int)puVar26 + -10)));
    pcVar42 = (char *)((int)pcVar42 * 0x9000b68);
    piVar28 = piVar29;
  } while( true );
  uVar5 = in(uVar25);
  *puVar41 = uVar5;
  out(uVar25,(char)puVar17);
  puVar41 = puVar41 + (uint)bVar48 * 0x3ffffffe + 1;
code_r0x0806ff8b:
  *(undefined4 *)(puVar34 + -4) = 0xec013818;
  uVar39 = (uint)puVar40 ^ *(uint *)(puVar40 + -0x12);
  *(uint **)(puVar34 + -8) = puVar26;
  bVar24 = (byte)((uint)puVar17 >> 8);
  uVar14 = (uint)puVar23 & 0xffffff00 | (uint)(byte)((byte)puVar23 + bVar24);
  uVar13 = (uint)piVar29 & 0xffffff00;
  puVar22 = (uint *)(uVar13 | (uint)(byte)((char)piVar29 + *pcVar42 + CARRY1((byte)puVar23,bVar24)))
  ;
  bVar9 = *(byte *)puVar26;
  bVar19 = *(byte *)puVar26;
  *(byte *)puVar26 = *(byte *)puVar26 - bVar24;
  bVar27 = *(byte *)puVar26;
  puVar23 = (uint *)&DAT_231e8189;
  *(undefined4 *)(puVar34 + -0xc) = 0x66e22ed2;
  piVar28 = (int *)(uVar14 - 1);
  if (piVar28 == (int *)0x0 || bVar27 != 0) {
    if (SBORROW1(bVar19,bVar24)) {
      piVar28 = (int *)(uVar14 - 2);
      if (piVar28 == (int *)0x0) {
        DAT_231e814c = (DAT_231e814c - (char)(uVar13 >> 8)) - (bVar9 < bVar24);
        *(uint **)(puVar34 + -0x10) = puVar17;
        *(undefined4 *)(puVar34 + -0x14) = 0;
        *(uint **)(puVar34 + -0x18) = puVar26;
        *(uint **)(puVar34 + -0x1c) = puVar22;
        *(undefined **)(puVar34 + -0x20) = puVar34 + -0xc;
        *(uint *)(puVar34 + -0x24) = uVar39;
        *(undefined4 *)(puVar34 + -0x28) = 0x231e8189;
        piVar37 = (int *)(puVar34 + -0x2c);
        *(undefined4 **)(puVar34 + -0x2c) = puVar41;
        puVar44 = puVar41;
        goto LAB_08070021;
      }
      goto LAB_0806fffb_2;
    }
    puVar17 = (uint *)((uint)puVar17 | *puVar17);
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *puVar17 = *puVar17 | (uint)puVar17;
    *(undefined4 *)(puVar34 + -0x10) = 0x7c8b0126;
    puVar17 = (uint *)((uint)puVar17 & 0xffffff00 | (uint)bRamd1470009);
    puVar36 = puVar34 + -0x12;
    *(undefined2 *)(puVar34 + -0x12) = in_SS;
  }
  else {
LAB_0806fffb_2:
    puVar26 = (uint *)((int)puVar26 + 1);
    puVar36 = puVar34 + (-0xc - *(int *)((int)piVar28 + -0x4d));
  }
  while( true ) {
    bVar9 = *(byte *)((int)puVar23 + -10);
    iVar45 = (int)puVar41 + (uint)bVar48 * -8 + 3;
    uVar5 = in((short)puVar26);
    *(undefined4 *)((int)puVar41 + -1) = uVar5;
    cVar11 = *(char *)((int)puVar23 * 9 + 0x6b);
    bVar19 = *(byte *)((int)puVar26 + -10);
    puVar23 = (uint *)((int)puVar23 * 0x9000b68);
    cVar20 = (char)piVar28;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    *(char *)piVar28 = *(char *)piVar28 + cVar20;
    _bVar19 = (char *)(((uint)puVar17 & 0xffff0000 |
                       (uint)(ushort)((short)(char)((char)puVar17 * bVar9 * cVar11) *
                                     (short)(char)bVar19)) + 0x26);
    *_bVar19 = *_bVar19 + (char)((uint)piVar28 >> 8);
    puVar17 = puVar22 + 0x2681f;
    uVar14 = *puVar17;
    *puVar17 = *puVar17 + (int)piVar28;
    puVar44 = (undefined4 *)(iVar45 + 1);
    *puVar23 = *puVar23 << 1 | (uint)CARRY4(uVar14,(uint)piVar28);
    piVar1 = (int *)puVar26[-0x1e3ffd98];
    iVar35 = (int)puVar36 + (int)puVar22;
    *(undefined2 *)((int)puVar36 + (int)puVar22 + -2) = in_SS;
    uVar14 = *puVar22;
    *puVar22 = *puVar22 + (int)puVar26;
    *(int **)((int)puVar36 + (int)puVar22 + -6) = piVar28;
    *(int **)((int)puVar36 + (int)puVar22 + -10) = piVar1;
    *(uint **)((int)puVar36 + (int)puVar22 + -0xe) = puVar26;
    *(uint **)((int)puVar36 + (int)puVar22 + -0x12) = puVar22;
    *(int *)((int)puVar36 + (int)puVar22 + -0x16) = (int)puVar36 + (int)puVar22 + -2;
    *(uint *)((int)puVar36 + (int)puVar22 + -0x1a) = uVar39;
    *(uint **)((int)puVar36 + (int)puVar22 + -0x1e) = puVar23;
    piVar37 = (int *)((int)puVar36 + (int)puVar22 + -0x22);
    *(undefined4 **)((int)puVar36 + (int)puVar22 + -0x22) = puVar44;
    uVar14 = (int)piVar28 + (-0x1cd14240 - (uint)CARRY4(uVar14,(uint)puVar26));
    *piVar1 = *piVar1 + (int)puVar22;
    cVar11 = (byte)uVar14 - 0x31;
    uVar39 = (uVar39 - puVar26[8]) - (uint)((byte)uVar14 < 0x31);
    if (!in_PF) break;
    puVar41 = (undefined4 *)(iVar45 + (uint)bVar48 * -2 + 2);
    uVar4 = in((short)puVar26);
    *(undefined *)puVar44 = uVar4;
    puVar17 = (uint *)(uVar14 & 0xffff0000 |
                      (uint)(ushort)((short)cVar11 * (short)*(char *)((int)puVar22 + -10)));
    puVar36 = (undefined *)((int)puVar36 + (int)puVar22 + -0x26);
    *(undefined4 *)(iVar35 + -0x26) = 0xfffffff6;
    piVar28 = piVar1;
  }
  *(uint *)((int)piVar1 + -0x19fefff7) =
       uVar14 & 0xffffff00 | (uint)(byte)(cVar11 - *(char *)piVar1);
  puVar22 = (uint *)CONCAT31((int3)(uVar13 >> 8),0x67);
  puVar17 = (uint *)0x291e6238;
LAB_08070021:
  pcVar42 = (char *)((int)puVar44 + 1);
  puVar18 = (uint *)((int)puVar22 + (int)puVar23 * 2 + 0x65);
  *puVar18 = *puVar18 & 0xffffffbd;
  uVar13 = *puVar22;
  bVar27 = (char)puVar17 + *(char *)((int)puVar22 + 0x73648363);
  puVar18 = (uint *)((uint)puVar17 & 0xffffff00 | (uint)bVar27);
  puVar17 = (uint *)((int)puVar18 + in_GS_OFFSET + 0x77);
  bVar9 = (byte)(uVar13 * 0x5a000943);
  *puVar17 = *puVar17 >> (bVar9 & 0x1f);
  bVar24 = (byte)((uint)puVar26 >> 8);
  pbVar43 = (byte *)((uint)puVar26 & 0xffff0000 |
                    (uint)CONCAT11(bVar24 + *(byte *)puVar23,(char)puVar26));
  bVar19 = (bVar9 & 0x1f) % 9;
  bVar9 = *pbVar43;
  *pbVar43 = (byte)(CONCAT11(CARRY1(bVar24,*(byte *)puVar23),bVar9) >> bVar19) | bVar9 << 9 - bVar19
  ;
  *puVar18 = *puVar18 + (int)puVar22;
  _bVar19 = (char *)(uVar13 * 0x5a000943 ^ *puVar22);
  *puVar18 = *puVar18 | (uint)puVar18;
  iVar45 = *piVar37;
  *(undefined2 *)((int)piVar37 + 2) = uVar46;
  bVar47 = puVar18 < (uint *)0x97638328;
  *(undefined2 *)piVar37 = uVar46;
  bVar9 = DAT_89073852 & 0xf;
  if ((DAT_89073852 <= bVar27 && bVar47 <= (byte)(bVar27 - DAT_89073852)) &&
      (bool)(bVar27 - DAT_89073852) != bVar47) {
    iVar45 = *(int *)(iVar45 + 0x33);
  }
  *(char **)(_bVar19 + 0x9a1ef) = _bVar19 + (int)*(char **)(_bVar19 + 0x9a1ef);
  uVar13 = _DAT_ff33b233;
  puVar23 = (uint *)((uint)puVar23 ^ *puVar22);
  cVar11 = (char)_bVar19;
  *_bVar19 = *_bVar19 + cVar11;
  *_bVar19 = *_bVar19 + cVar11;
  *_bVar19 = *_bVar19 + cVar11;
  *_bVar19 = *_bVar19 + cVar11;
  *_bVar19 = *_bVar19 + cVar11;
  *_bVar19 = *_bVar19 + cVar11;
  *_bVar19 = *_bVar19 + cVar11;
  *_bVar19 = *_bVar19 + cVar11;
  *(char *)(iVar45 * 9) = *(char *)(iVar45 * 9) + cVar11;
  uVar14 = (uint)_bVar19 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)_bVar19 >> 8) + (char)(uVar13 >> 8),cVar11);
  puVar17 = (uint *)(uVar13 | *(uint *)(iVar45 + 9));
  pbVar43 = (byte *)(iVar45 + 0xb);
  bVar19 = *pbVar43;
  *pbVar43 = *pbVar43 + (byte)puVar22;
  uRamfe67646c = uVar46;
  *puVar23 = *puVar23 << 1 | (uint)CARRY1(bVar19,(byte)puVar22);
  *(char **)((int)puVar23 + -0x51) = pcVar42;
  *puVar17 = *puVar17 | (uint)puVar17;
  puVar17 = (uint *)((int)puVar17 + 0x16e210d1);
  uVar13 = *puVar17;
  pbVar43 = (byte *)(uVar14 - 1);
  if (pbVar43 != (byte *)0x0) {
    puVar2 = (undefined2 *)(iVar45 + 2 + uVar13 * 2);
    *puVar2 = *puVar2;
    uVar38 = *(uint *)(uVar39 - 0x1c) ^ 0xfe67646c;
    *(uint **)(uVar38 - 4) = puVar23;
    uVar13 = uVar13 - 1;
    bVar19 = (byte)puVar23[(uint)bVar48 * 0x3ffffffe + 1];
    bVar9 = bVar19 + (9 < (bVar19 & 0xf) || (((bVar27 & 0xf) - bVar9) - bVar47 & 0x10) != 0) * 6 &
            0xf;
    bVar27 = (byte)uVar13;
    bVar19 = bVar27 + *(byte *)(iVar45 + -0x2e);
    *pcVar42 = (*pcVar42 - (char)((uint)iVar45 >> 8)) -
               (bVar9 < *pbVar43 ||
               (byte)(bVar9 - *pbVar43) < CARRY1(bVar27,*(byte *)(iVar45 + -0x2e)));
    *(char *)(iVar45 + 0xc) = *(char *)(iVar45 + 0xc) + bVar19;
    puVar17 = (uint *)(uVar14 + 0x7c);
    *puVar17 = *puVar17 & 0x21;
    *(undefined2 *)(uVar38 + puVar44[0x1a] + -6) = uVar46;
    *(uint *)(pcVar42 +
             (int)(puVar23 + (uint)bVar48 * 0x3ffffffe + 1) + (uint)bVar48 * -8 + 0x7cff3796) =
         uVar13 & 0xffffff00 | (uint)bVar19;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *puVar17 = *puVar17 | (uint)puVar17;
  *puVar17 = *puVar17 + 1;
  *puVar17 = *puVar17 | (uint)puVar17;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void _fini(undefined uParm1)

{
  out(0x2f,uParm1);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


