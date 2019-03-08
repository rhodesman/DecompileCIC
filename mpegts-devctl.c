typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned int    uint;
typedef unsigned int    undefined4;
typedef unsigned short    word;
typedef uint __useconds_t;

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

struct evp_pkey_ctx_st {
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



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

int printf(char *__format,...)

{
  int iVar1;
  undefined *puVar2;
  byte bVar3;
  byte bVar4;
  char cVar5;
  uint uVar6;
  uint *puVar7;
  byte *pbVar8;
  char *pcVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  byte bVar14;
  int in_ECX;
  int in_EDX;
  uint *unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined auStack20 [4];
  undefined auStack16 [4];
  undefined auStack12 [4];
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar3 = (char)__format - 0x30;
  uVar6 = (uint)__format & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__format & 0xffffff00) >> 8) +
                         *(char *)(((uint)__format & 0xffffff00 | (uint)bVar3) + 2),bVar3);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar12 & 1) != 0);
  puVar2 = &stack0x00000000 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar2 + (uVar13 - 4)) = puVar7;
  bVar3 = (char)puVar7 + 4;
  uVar12 = (uint)puVar7 & 0xffffff00;
  pbVar8 = (byte *)(uVar12 | (uint)bVar3);
  bVar4 = (byte)(uVar12 >> 8);
  *pbVar8 = *pbVar8 | bVar4;
  bVar3 = bVar3 - pbVar8[in_ECX];
  pcVar9 = (char *)(uVar12 | (uint)bVar3);
  *pcVar9 = *pcVar9 + bVar3;
  *pcVar9 = *pcVar9 + bVar3;
  uVar10 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11(bVar4 + *(char *)((uVar12 | (uint)(byte)(bVar3 - 0x30)) + 2),bVar3 - 0x30)
  ;
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar12 & 1) != 0);
  puVar2 = puVar2 + *(int *)(uVar10 + 4) + (uVar13 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar10 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar2 + (uVar6 - 4)) = puVar7;
  uVar12 = (uint)puVar7 & 0xffffff00;
  bVar4 = (byte)(uVar12 >> 8);
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar4;
  bVar3 = (char)puVar7 + 0xc;
  pcVar9 = (char *)(uVar12 | (uint)bVar3);
  *pcVar9 = *pcVar9 + bVar3;
  bVar3 = (char)puVar7 - 0x24;
  uVar10 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11(bVar4 + *(char *)((uVar12 | (uint)bVar3) + 2),bVar3);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar12 & 1) != 0);
  puVar2 = puVar2 + *(int *)(uVar10 + 4) + (uVar6 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar10 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar2 + (uVar13 - 4)) = puVar7;
  bVar4 = (char)puVar7 + 4;
  uVar12 = (uint)puVar7 & 0xffffff00;
  pbVar8 = (byte *)(uVar12 | (uint)bVar4);
  bVar14 = (byte)((uint)in_ECX >> 8);
  *pbVar8 = *pbVar8 | bVar14;
  bVar3 = bVar4 - pbVar8[in_ECX];
  pcVar9 = (char *)(uVar12 | (uint)bVar3);
  *pcVar9 = (*pcVar9 - bVar3) - (bVar4 < pbVar8[in_ECX]);
  *pcVar9 = *pcVar9 + bVar3;
  uVar10 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)((uVar12 | (uint)(byte)(bVar3 - 0x30)) + 2)
                          ,bVar3 - 0x30);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar12 & 1) != 0);
  puVar2 = puVar2 + *(int *)(uVar10 + 4) + (uVar13 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar10 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar2 + uVar6 + -4) = puVar7;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar14;
  *(undefined *)((uint)puVar7 & 0xffffff00) = *(undefined *)((uint)puVar7 & 0xffffff00);
  uVar10 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)puVar7 >> 8) +
                          *(char *)(CONCAT31((int3)((uint)puVar7 >> 8),0xd0) + 2),0xd0);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar12 & 1) != 0);
  puVar2 = puVar2 + *(int *)(uVar10 + 4) + uVar6 + -4;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar10 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar2 + uVar13 + -4) = puVar7;
  bVar3 = (char)puVar7 + 4;
  uVar12 = (uint)puVar7 & 0xffffff00;
  pbVar8 = (byte *)(uVar12 | (uint)bVar3);
  bVar4 = (byte)((uint)in_EDX >> 8);
  *pbVar8 = *pbVar8 | bVar4;
  bVar3 = bVar3 - pbVar8[in_ECX];
  pbVar8 = (byte *)(uVar12 | (uint)bVar3);
  *pbVar8 = *pbVar8 ^ bVar3;
  *pbVar8 = *pbVar8 + bVar3;
  uVar10 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)((uVar12 | (uint)(byte)(bVar3 - 0x30)) + 2)
                          ,bVar3 - 0x30);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar12 & 1) != 0);
  iVar1 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar10 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)((int)(puVar2 + iVar1 + uVar13 + -4) + uVar6 + -4) = puVar7;
  uVar12 = (uint)puVar7 & 0xffffff00;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar4;
  bVar3 = (char)puVar7 + 0xc;
  pcVar9 = (char *)(uVar12 | (uint)bVar3);
  *pcVar9 = *pcVar9 + bVar3;
  bVar3 = (char)puVar7 - 0x24;
  uVar11 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar12 >> 8) + *(char *)((uVar12 | (uint)bVar3) + 2),bVar3);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar10 = (uint)((uVar12 & 1) != 0);
  iVar1 = (int)(puVar2 + iVar1 + uVar13 + -4) + uVar6 + -4 + *(int *)(uVar11 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar11 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(iVar1 + uVar10 + -4) = puVar7;
  bVar3 = (char)puVar7 + 4;
  pbVar8 = (byte *)((uint)puVar7 & 0xffffff00 | (uint)bVar3);
  bVar4 = (byte)((uint)unaff_EBX >> 8);
  *pbVar8 = *pbVar8 | bVar4;
  uVar12 = (uint)puVar7 & 0xffffff00 | (uint)(byte)(bVar3 - pbVar8[in_ECX]);
  pcVar9 = (char *)(uVar12 - 1);
  cVar5 = (char)pcVar9;
  *pcVar9 = *pcVar9 + cVar5;
  pcVar9[in_EDX * 8] = pcVar9[in_EDX * 8] + cVar5;
  uVar6 = (uint)pcVar9 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)pcVar9 >> 8) + *(char *)(uVar12 + 1),cVar5);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar13 = (uint)((uVar12 & 1) != 0);
  iVar1 = iVar1 + uVar10 + -4 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(iVar1 + uVar13 + -4) = puVar7;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar4;
  bVar3 = (char)puVar7 + 0xc;
  pcVar9 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar3);
  *(uint *)(iVar1 + uVar13 + -8) = iVar1 + uVar13 + -4;
  *pcVar9 = *pcVar9 + bVar3;
  pcVar9[in_EDX * 8] = pcVar9[in_EDX * 8] + bVar3;
  uVar10 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + pcVar9[2],bVar3);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar12 & 1) != 0);
  iVar1 = iVar1 + uVar13 + -8 + *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar10 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(iVar1 + uVar6 + -4) = puVar7;
  bVar3 = (char)puVar7 + 4;
  uVar12 = (uint)puVar7 & 0xffffff00;
  pbVar8 = (byte *)((uVar12 | (uint)bVar3) + 0x1a);
  *pbVar8 = *pbVar8 | bVar3;
  bVar3 = (char)puVar7 + 0xc;
  pcVar9 = (char *)(uVar12 | (uint)bVar3);
  *(char **)(iVar1 + uVar6 + -8) = pcVar9;
  *(int *)(iVar1 + uVar6 + -0xc) = in_ECX;
  *(int *)(iVar1 + uVar6 + -0x10) = in_EDX;
  *(uint **)(iVar1 + uVar6 + -0x14) = unaff_EBX;
  *(uint *)(iVar1 + uVar6 + -0x18) = iVar1 + uVar6 + -4;
  *(undefined4 *)(iVar1 + uVar6 + -0x1c) = unaff_EBP;
  *(undefined4 *)(iVar1 + uVar6 + -0x20) = unaff_ESI;
  *(undefined4 *)(iVar1 + uVar6 + -0x24) = unaff_EDI;
  *pcVar9 = *pcVar9 + bVar3;
  pcVar9[in_EDX * 8] = pcVar9[in_EDX * 8] + bVar3;
  uVar13 = (uint)puVar7 & 0xffff0000 | (uint)CONCAT11((char)(uVar12 >> 8) + pcVar9[2],bVar3);
  uVar12 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar12 = (uint)((uVar12 & 1) != 0);
  iVar1 = iVar1 + uVar6 + -0x24 + *(int *)(uVar13 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar13 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(iVar1 + uVar12 + -4) = puVar7;
  bVar3 = (char)puVar7 + 4;
  pbVar8 = (byte *)(in_EDX + 4 + (int)unaff_EBX);
  *pbVar8 = *pbVar8 | bVar3;
  pbVar8 = (byte *)(((uint)puVar7 & 0xffffff00 | (uint)bVar3) * 2);
  *pbVar8 = *pbVar8 | bVar14;
  DAT_0bd416d1 = DAT_0bd416d1 + (char)in_EDX;
  *(undefined2 *)(iVar1 + uVar12 + -6) = in_ES;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

int usleep(__useconds_t __useconds)

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  byte bVar4;
  byte bVar5;
  char cVar6;
  uint uVar7;
  uint *puVar8;
  char *pcVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  byte bVar13;
  int in_ECX;
  int in_EDX;
  uint *unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined auStack20 [4];
  undefined auStack16 [4];
  undefined auStack12 [4];
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar4 = (char)__useconds - 0x30;
  uVar7 = __useconds & 0xffff0000 |
          (uint)CONCAT11((char)((__useconds & 0xffffff00) >> 8) +
                         *(char *)((__useconds & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + (uVar2 - 4)) = puVar8;
  uVar11 = (uint)puVar8 & 0xffffff00;
  bVar5 = (byte)(uVar11 >> 8);
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar5;
  bVar4 = (char)puVar8 + 0xc;
  pcVar9 = (char *)(uVar11 | (uint)bVar4);
  *pcVar9 = *pcVar9 + bVar4;
  bVar4 = (char)puVar8 - 0x24;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11(bVar5 + *(char *)((uVar11 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar10 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + (uVar7 - 4)) = puVar8;
  bVar5 = (char)puVar8 + 4;
  uVar11 = (uint)puVar8 & 0xffffff00;
  _bVar5 = (byte *)(uVar11 | (uint)bVar5);
  bVar13 = (byte)((uint)in_ECX >> 8);
  *_bVar5 = *_bVar5 | bVar13;
  bVar4 = bVar5 - _bVar5[in_ECX];
  pcVar9 = (char *)(uVar11 | (uint)bVar4);
  *pcVar9 = (*pcVar9 - bVar4) - (bVar5 < _bVar5[in_ECX]);
  *pcVar9 = *pcVar9 + bVar4;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)(byte)(bVar4 - 0x30)) + 2)
                          ,bVar4 - 0x30);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar10 + 4) + (uVar7 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + (uVar2 - 4)) = puVar8;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar13;
  *(undefined *)((uint)puVar8 & 0xffffff00) = *(undefined *)((uint)puVar8 & 0xffffff00);
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)puVar8 >> 8) +
                          *(char *)(CONCAT31((int3)((uint)puVar8 >> 8),0xd0) + 2),0xd0);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar10 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + uVar7 + -4) = puVar8;
  bVar4 = (char)puVar8 + 4;
  uVar11 = (uint)puVar8 & 0xffffff00;
  _bVar5 = (byte *)(uVar11 | (uint)bVar4);
  bVar5 = (byte)((uint)in_EDX >> 8);
  *_bVar5 = *_bVar5 | bVar5;
  bVar4 = bVar4 - _bVar5[in_ECX];
  _bVar5 = (byte *)(uVar11 | (uint)bVar4);
  *_bVar5 = *_bVar5 ^ bVar4;
  *_bVar5 = *_bVar5 + bVar4;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)(byte)(bVar4 - 0x30)) + 2)
                          ,bVar4 - 0x30);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar10 + 4) + uVar7 + -4;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + uVar2 + -4) = puVar8;
  uVar11 = (uint)puVar8 & 0xffffff00;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar5;
  bVar4 = (char)puVar8 + 0xc;
  pcVar9 = (char *)(uVar11 | (uint)bVar4);
  *pcVar9 = *pcVar9 + bVar4;
  bVar4 = (char)puVar8 - 0x24;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar11 & 1) != 0);
  iVar1 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)((int)(puVar3 + iVar1 + uVar2 + -4) + uVar7 + -4) = puVar8;
  bVar4 = (char)puVar8 + 4;
  _bVar5 = (byte *)((uint)puVar8 & 0xffffff00 | (uint)bVar4);
  bVar5 = (byte)((uint)unaff_EBX >> 8);
  *_bVar5 = *_bVar5 | bVar5;
  uVar11 = (uint)puVar8 & 0xffffff00 | (uint)(byte)(bVar4 - _bVar5[in_ECX]);
  pcVar9 = (char *)(uVar11 - 1);
  cVar6 = (char)pcVar9;
  *pcVar9 = *pcVar9 + cVar6;
  pcVar9[in_EDX * 8] = pcVar9[in_EDX * 8] + cVar6;
  uVar12 = (uint)pcVar9 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar9 >> 8) + *(char *)(uVar11 + 1),cVar6);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar10 = (uint)((uVar11 & 1) != 0);
  iVar1 = (int)(puVar3 + iVar1 + uVar2 + -4) + uVar7 + -4 + *(int *)(uVar12 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(iVar1 + uVar10 + -4) = puVar8;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar5;
  bVar4 = (char)puVar8 + 0xc;
  pcVar9 = (char *)((uint)puVar8 & 0xffffff00 | (uint)bVar4);
  *(uint *)(iVar1 + uVar10 + -8) = iVar1 + uVar10 + -4;
  *pcVar9 = *pcVar9 + bVar4;
  pcVar9[in_EDX * 8] = pcVar9[in_EDX * 8] + bVar4;
  uVar7 = (uint)puVar8 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + pcVar9[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  iVar1 = iVar1 + uVar10 + -8 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(iVar1 + uVar2 + -4) = puVar8;
  bVar4 = (char)puVar8 + 4;
  uVar11 = (uint)puVar8 & 0xffffff00;
  _bVar5 = (byte *)((uVar11 | (uint)bVar4) + 0x1a);
  *_bVar5 = *_bVar5 | bVar4;
  bVar4 = (char)puVar8 + 0xc;
  pcVar9 = (char *)(uVar11 | (uint)bVar4);
  *(char **)(iVar1 + uVar2 + -8) = pcVar9;
  *(int *)(iVar1 + uVar2 + -0xc) = in_ECX;
  *(int *)(iVar1 + uVar2 + -0x10) = in_EDX;
  *(uint **)(iVar1 + uVar2 + -0x14) = unaff_EBX;
  *(uint *)(iVar1 + uVar2 + -0x18) = iVar1 + uVar2 + -4;
  *(undefined4 *)(iVar1 + uVar2 + -0x1c) = unaff_EBP;
  *(undefined4 *)(iVar1 + uVar2 + -0x20) = unaff_ESI;
  *(undefined4 *)(iVar1 + uVar2 + -0x24) = unaff_EDI;
  *pcVar9 = *pcVar9 + bVar4;
  pcVar9[in_EDX * 8] = pcVar9[in_EDX * 8] + bVar4;
  uVar7 = (uint)puVar8 & 0xffff0000 | (uint)CONCAT11((char)(uVar11 >> 8) + pcVar9[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  iVar1 = iVar1 + uVar2 + -0x24 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(iVar1 + uVar11 + -4) = puVar8;
  bVar4 = (char)puVar8 + 4;
  _bVar5 = (byte *)(in_EDX + 4 + (int)unaff_EBX);
  *_bVar5 = *_bVar5 | bVar4;
  _bVar5 = (byte *)(((uint)puVar8 & 0xffffff00 | (uint)bVar4) * 2);
  *_bVar5 = *_bVar5 | bVar13;
  DAT_0bd416d1 = DAT_0bd416d1 + (char)in_EDX;
  *(undefined2 *)(iVar1 + uVar11 + -6) = in_ES;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling

void devctl(uint uParm1,int iParm2,int iParm3)

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  byte bVar4;
  byte bVar5;
  char cVar6;
  uint uVar7;
  uint *puVar8;
  char *pcVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  byte bVar13;
  uint *unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined auStack20 [4];
  undefined auStack16 [4];
  undefined auStack12 [4];
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar4 = (char)uParm1 - 0x30;
  uVar7 = uParm1 & 0xffff0000 |
          (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                         *(char *)((uParm1 & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + (uVar2 - 4)) = puVar8;
  bVar5 = (char)puVar8 + 4;
  uVar11 = (uint)puVar8 & 0xffffff00;
  _bVar5 = (byte *)(uVar11 | (uint)bVar5);
  bVar13 = (byte)((uint)iParm3 >> 8);
  *_bVar5 = *_bVar5 | bVar13;
  bVar4 = bVar5 - _bVar5[iParm3];
  pcVar9 = (char *)(uVar11 | (uint)bVar4);
  *pcVar9 = (*pcVar9 - bVar4) - (bVar5 < _bVar5[iParm3]);
  *pcVar9 = *pcVar9 + bVar4;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)(byte)(bVar4 - 0x30)) + 2)
                          ,bVar4 - 0x30);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar10 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + (uVar7 - 4)) = puVar8;
  *(byte *)(iParm2 + (int)unaff_EBX) = *(byte *)(iParm2 + (int)unaff_EBX) | bVar13;
  *(undefined *)((uint)puVar8 & 0xffffff00) = *(undefined *)((uint)puVar8 & 0xffffff00);
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)puVar8 >> 8) +
                          *(char *)(CONCAT31((int3)((uint)puVar8 >> 8),0xd0) + 2),0xd0);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar10 + 4) + (uVar7 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + (uVar2 - 4)) = puVar8;
  bVar4 = (char)puVar8 + 4;
  uVar11 = (uint)puVar8 & 0xffffff00;
  _bVar5 = (byte *)(uVar11 | (uint)bVar4);
  bVar5 = (byte)((uint)iParm2 >> 8);
  *_bVar5 = *_bVar5 | bVar5;
  bVar4 = bVar4 - _bVar5[iParm3];
  _bVar5 = (byte *)(uVar11 | (uint)bVar4);
  *_bVar5 = *_bVar5 ^ bVar4;
  *_bVar5 = *_bVar5 + bVar4;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)(byte)(bVar4 - 0x30)) + 2)
                          ,bVar4 - 0x30);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar7 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar10 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + uVar7 + -4) = puVar8;
  uVar11 = (uint)puVar8 & 0xffffff00;
  *(byte *)(iParm2 + (int)unaff_EBX) = *(byte *)(iParm2 + (int)unaff_EBX) | bVar5;
  bVar4 = (char)puVar8 + 0xc;
  pcVar9 = (char *)(uVar11 | (uint)bVar4);
  *pcVar9 = *pcVar9 + bVar4;
  bVar4 = (char)puVar8 - 0x24;
  uVar10 = (uint)puVar8 & 0xffff0000 |
           (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  iVar1 = *(int *)(uVar10 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar10 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(puVar3 + iVar1 + uVar7 + -4 + uVar2 + -4) = puVar8;
  bVar4 = (char)puVar8 + 4;
  _bVar5 = (byte *)((uint)puVar8 & 0xffffff00 | (uint)bVar4);
  bVar5 = (byte)((uint)unaff_EBX >> 8);
  *_bVar5 = *_bVar5 | bVar5;
  uVar11 = (uint)puVar8 & 0xffffff00 | (uint)(byte)(bVar4 - _bVar5[iParm3]);
  pcVar9 = (char *)(uVar11 - 1);
  cVar6 = (char)pcVar9;
  *pcVar9 = *pcVar9 + cVar6;
  pcVar9[iParm2 * 8] = pcVar9[iParm2 * 8] + cVar6;
  uVar12 = (uint)pcVar9 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar9 >> 8) + *(char *)(uVar11 + 1),cVar6);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar10 = (uint)((uVar11 & 1) != 0);
  iVar1 = (int)(puVar3 + iVar1 + uVar7 + -4 + *(int *)(uVar12 + 4) + uVar2 + -4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar12 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(iVar1 + uVar10 + -4) = puVar8;
  *(byte *)(iParm2 + (int)unaff_EBX) = *(byte *)(iParm2 + (int)unaff_EBX) | bVar5;
  bVar4 = (char)puVar8 + 0xc;
  pcVar9 = (char *)((uint)puVar8 & 0xffffff00 | (uint)bVar4);
  *(uint *)(iVar1 + uVar10 + -8) = iVar1 + uVar10 + -4;
  *pcVar9 = *pcVar9 + bVar4;
  pcVar9[iParm2 * 8] = pcVar9[iParm2 * 8] + bVar4;
  uVar7 = (uint)puVar8 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)puVar8 & 0xffffff00) >> 8) + pcVar9[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  iVar1 = iVar1 + uVar10 + -8 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(iVar1 + uVar2 + -4) = puVar8;
  bVar4 = (char)puVar8 + 4;
  uVar11 = (uint)puVar8 & 0xffffff00;
  _bVar5 = (byte *)((uVar11 | (uint)bVar4) + 0x1a);
  *_bVar5 = *_bVar5 | bVar4;
  bVar4 = (char)puVar8 + 0xc;
  pcVar9 = (char *)(uVar11 | (uint)bVar4);
  *(char **)(iVar1 + uVar2 + -8) = pcVar9;
  *(int *)(iVar1 + uVar2 + -0xc) = iParm3;
  *(int *)(iVar1 + uVar2 + -0x10) = iParm2;
  *(uint **)(iVar1 + uVar2 + -0x14) = unaff_EBX;
  *(uint *)(iVar1 + uVar2 + -0x18) = iVar1 + uVar2 + -4;
  *(undefined4 *)(iVar1 + uVar2 + -0x1c) = unaff_EBP;
  *(undefined4 *)(iVar1 + uVar2 + -0x20) = unaff_ESI;
  *(undefined4 *)(iVar1 + uVar2 + -0x24) = unaff_EDI;
  *pcVar9 = *pcVar9 + bVar4;
  pcVar9[iParm2 * 8] = pcVar9[iParm2 * 8] + bVar4;
  uVar7 = (uint)puVar8 & 0xffff0000 | (uint)CONCAT11((char)(uVar11 >> 8) + pcVar9[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  iVar1 = iVar1 + uVar2 + -0x24 + *(int *)(uVar7 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar8 = (uint *)(uVar7 + 2);
  *puVar8 = *puVar8 | (uint)puVar8;
  *(uint **)(iVar1 + uVar11 + -4) = puVar8;
  bVar4 = (char)puVar8 + 4;
  _bVar5 = (byte *)(iParm2 + 4 + (int)unaff_EBX);
  *_bVar5 = *_bVar5 | bVar4;
  _bVar5 = (byte *)(((uint)puVar8 & 0xffffff00 | (uint)bVar4) * 2);
  *_bVar5 = *_bVar5 | bVar13;
  DAT_0bd416d1 = DAT_0bd416d1 + (char)iParm2;
  *(undefined2 *)(iVar1 + uVar11 + -6) = in_ES;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling

void _init_libc(uint uParm1,int iParm2,int iParm3)

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  byte bVar4;
  char cVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  byte *pbVar9;
  char *pcVar10;
  uint uVar11;
  uint uVar12;
  byte bVar13;
  byte bVar14;
  uint *unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined auStack24 [4];
  undefined auStack20 [4];
  undefined auStack16 [4];
  undefined auStack12 [4];
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar4 = (char)uParm1 - 0x30;
  uVar6 = uParm1 & 0xffff0000 |
          (uint)CONCAT11((char)((uParm1 & 0xffffff00) >> 8) +
                         *(char *)((uParm1 & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + (uVar2 - 4)) = puVar7;
  bVar13 = (byte)((uint)iParm3 >> 8);
  *(byte *)(iParm2 + (int)unaff_EBX) = *(byte *)(iParm2 + (int)unaff_EBX) | bVar13;
  *(undefined *)((uint)puVar7 & 0xffffff00) = *(undefined *)((uint)puVar7 & 0xffffff00);
  uVar8 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)((uint)puVar7 >> 8) +
                         *(char *)(CONCAT31((int3)((uint)puVar7 >> 8),0xd0) + 2),0xd0);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar8 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar8 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + (uVar6 - 4)) = puVar7;
  bVar4 = (char)puVar7 + 4;
  uVar11 = (uint)puVar7 & 0xffffff00;
  pbVar9 = (byte *)(uVar11 | (uint)bVar4);
  bVar14 = (byte)((uint)iParm2 >> 8);
  *pbVar9 = *pbVar9 | bVar14;
  bVar4 = bVar4 - pbVar9[iParm3];
  pbVar9 = (byte *)(uVar11 | (uint)bVar4);
  *pbVar9 = *pbVar9 ^ bVar4;
  *pbVar9 = *pbVar9 + bVar4;
  uVar8 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)(byte)(bVar4 - 0x30)) + 2),
                         bVar4 - 0x30);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar8 + 4) + (uVar6 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar8 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + (uVar2 - 4)) = puVar7;
  uVar11 = (uint)puVar7 & 0xffffff00;
  *(byte *)(iParm2 + (int)unaff_EBX) = *(byte *)(iParm2 + (int)unaff_EBX) | bVar14;
  bVar4 = (char)puVar7 + 0xc;
  pcVar10 = (char *)(uVar11 | (uint)bVar4);
  *pcVar10 = *pcVar10 + bVar4;
  bVar4 = (char)puVar7 - 0x24;
  uVar8 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar11 & 1) != 0);
  iVar1 = *(int *)(uVar8 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar8 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + iVar1 + (uVar2 - 4) + uVar6 + -4) = puVar7;
  bVar4 = (char)puVar7 + 4;
  pbVar9 = (byte *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  bVar14 = (byte)((uint)unaff_EBX >> 8);
  *pbVar9 = *pbVar9 | bVar14;
  uVar11 = (uint)puVar7 & 0xffffff00 | (uint)(byte)(bVar4 - pbVar9[iParm3]);
  pcVar10 = (char *)(uVar11 - 1);
  cVar5 = (char)pcVar10;
  *pcVar10 = *pcVar10 + cVar5;
  pcVar10[iParm2 * 8] = pcVar10[iParm2 * 8] + cVar5;
  uVar12 = (uint)pcVar10 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar10 >> 8) + *(char *)(uVar11 + 1),cVar5);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar8 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + iVar1 + (uVar2 - 4) + *(int *)(uVar12 + 4) + uVar6 + -4;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar12 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + uVar8 + -4) = puVar7;
  *(byte *)(iParm2 + (int)unaff_EBX) = *(byte *)(iParm2 + (int)unaff_EBX) | bVar14;
  bVar4 = (char)puVar7 + 0xc;
  pcVar10 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  *(undefined **)(puVar3 + uVar8 + -8) = puVar3 + uVar8 + -4;
  *pcVar10 = *pcVar10 + bVar4;
  pcVar10[iParm2 * 8] = pcVar10[iParm2 * 8] + bVar4;
  uVar6 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + pcVar10[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  iVar1 = (int)(puVar3 + *(int *)(uVar6 + 4) + uVar8 + -8);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(iVar1 + uVar2 + -4) = puVar7;
  bVar4 = (char)puVar7 + 4;
  uVar11 = (uint)puVar7 & 0xffffff00;
  pbVar9 = (byte *)((uVar11 | (uint)bVar4) + 0x1a);
  *pbVar9 = *pbVar9 | bVar4;
  bVar4 = (char)puVar7 + 0xc;
  pcVar10 = (char *)(uVar11 | (uint)bVar4);
  *(char **)(iVar1 + uVar2 + -8) = pcVar10;
  *(int *)(iVar1 + uVar2 + -0xc) = iParm3;
  *(int *)(iVar1 + uVar2 + -0x10) = iParm2;
  *(uint **)(iVar1 + uVar2 + -0x14) = unaff_EBX;
  *(uint *)(iVar1 + uVar2 + -0x18) = iVar1 + uVar2 + -4;
  *(undefined4 *)(iVar1 + uVar2 + -0x1c) = unaff_EBP;
  *(undefined4 *)(iVar1 + uVar2 + -0x20) = unaff_ESI;
  *(undefined4 *)(iVar1 + uVar2 + -0x24) = unaff_EDI;
  *pcVar10 = *pcVar10 + bVar4;
  pcVar10[iParm2 * 8] = pcVar10[iParm2 * 8] + bVar4;
  uVar6 = (uint)puVar7 & 0xffff0000 | (uint)CONCAT11((char)(uVar11 >> 8) + pcVar10[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  iVar1 = iVar1 + uVar2 + -0x24 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(iVar1 + uVar11 + -4) = puVar7;
  bVar4 = (char)puVar7 + 4;
  pbVar9 = (byte *)(iParm2 + 4 + (int)unaff_EBX);
  *pbVar9 = *pbVar9 | bVar4;
  pbVar9 = (byte *)(((uint)puVar7 & 0xffffff00 | (uint)bVar4) * 2);
  *pbVar9 = *pbVar9 | bVar13;
  DAT_0bd416d1 = DAT_0bd416d1 + (char)iParm2;
  *(undefined2 *)(iVar1 + uVar11 + -6) = in_ES;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

int atexit(void (*__func)(int,void *))

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  byte bVar4;
  char cVar5;
  uint uVar6;
  uint *puVar7;
  byte *pbVar8;
  uint uVar9;
  char *pcVar10;
  uint uVar11;
  uint uVar12;
  int in_ECX;
  byte bVar13;
  int in_EDX;
  uint *unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined auStack56 [4];
  undefined auStack52 [4];
  undefined auStack48 [4];
  undefined auStack44 [4];
  undefined auStack40 [4];
  undefined auStack36 [4];
  undefined auStack32 [4];
  undefined auStack28 [4];
  undefined auStack24 [4];
  undefined auStack20 [4];
  undefined auStack16 [4];
  undefined auStack12 [4];
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar4 = (char)__func - 0x30;
  uVar6 = (uint)__func & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__func & 0xffffff00) >> 8) +
                         *(char *)(((uint)__func & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + (uVar2 - 4)) = puVar7;
  bVar4 = (char)puVar7 + 4;
  uVar11 = (uint)puVar7 & 0xffffff00;
  pbVar8 = (byte *)(uVar11 | (uint)bVar4);
  bVar13 = (byte)((uint)in_EDX >> 8);
  *pbVar8 = *pbVar8 | bVar13;
  bVar4 = bVar4 - pbVar8[in_ECX];
  pbVar8 = (byte *)(uVar11 | (uint)bVar4);
  *pbVar8 = *pbVar8 ^ bVar4;
  *pbVar8 = *pbVar8 + bVar4;
  uVar9 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)(byte)(bVar4 - 0x30)) + 2),
                         bVar4 - 0x30);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar9 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar9 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + (uVar6 - 4)) = puVar7;
  uVar11 = (uint)puVar7 & 0xffffff00;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar13;
  bVar4 = (char)puVar7 + 0xc;
  pcVar10 = (char *)(uVar11 | (uint)bVar4);
  *pcVar10 = *pcVar10 + bVar4;
  bVar4 = (char)puVar7 - 0x24;
  uVar9 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  iVar1 = *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar9 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + iVar1 + (uVar6 - 4) + (uVar2 - 4)) = puVar7;
  bVar4 = (char)puVar7 + 4;
  pbVar8 = (byte *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  bVar13 = (byte)((uint)unaff_EBX >> 8);
  *pbVar8 = *pbVar8 | bVar13;
  uVar11 = (uint)puVar7 & 0xffffff00 | (uint)(byte)(bVar4 - pbVar8[in_ECX]);
  pcVar10 = (char *)(uVar11 - 1);
  cVar5 = (char)pcVar10;
  *pcVar10 = *pcVar10 + cVar5;
  pcVar10[in_EDX * 8] = pcVar10[in_EDX * 8] + cVar5;
  uVar12 = (uint)pcVar10 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar10 >> 8) + *(char *)(uVar11 + 1),cVar5);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + iVar1 + (uVar6 - 4) + *(int *)(uVar12 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar12 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + uVar9 + -4) = puVar7;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar13;
  bVar4 = (char)puVar7 + 0xc;
  pcVar10 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  *(undefined **)(puVar3 + uVar9 + -8) = puVar3 + uVar9 + -4;
  *pcVar10 = *pcVar10 + bVar4;
  pcVar10[in_EDX * 8] = pcVar10[in_EDX * 8] + bVar4;
  uVar6 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + pcVar10[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar6 + 4) + uVar9 + -8;
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + uVar2 + -4) = puVar7;
  bVar4 = (char)puVar7 + 4;
  uVar11 = (uint)puVar7 & 0xffffff00;
  pbVar8 = (byte *)((uVar11 | (uint)bVar4) + 0x1a);
  *pbVar8 = *pbVar8 | bVar4;
  bVar4 = (char)puVar7 + 0xc;
  pcVar10 = (char *)(uVar11 | (uint)bVar4);
  *(char **)(puVar3 + uVar2 + -8) = pcVar10;
  *(int *)(puVar3 + uVar2 + -0xc) = in_ECX;
  *(int *)(puVar3 + uVar2 + -0x10) = in_EDX;
  *(uint **)(puVar3 + uVar2 + -0x14) = unaff_EBX;
  *(undefined **)(puVar3 + uVar2 + -0x18) = puVar3 + uVar2 + -4;
  *(undefined4 *)(puVar3 + uVar2 + -0x1c) = unaff_EBP;
  *(undefined4 *)(puVar3 + uVar2 + -0x20) = unaff_ESI;
  *(undefined4 *)(puVar3 + uVar2 + -0x24) = unaff_EDI;
  *pcVar10 = *pcVar10 + bVar4;
  pcVar10[in_EDX * 8] = pcVar10[in_EDX * 8] + bVar4;
  uVar6 = (uint)puVar7 & 0xffff0000 | (uint)CONCAT11((char)(uVar11 >> 8) + pcVar10[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  iVar1 = *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)((int)(puVar3 + iVar1 + uVar2 + -0x24) + uVar11 + -4) = puVar7;
  bVar4 = (char)puVar7 + 4;
  pbVar8 = (byte *)(in_EDX + 4 + (int)unaff_EBX);
  *pbVar8 = *pbVar8 | bVar4;
  pbVar8 = (byte *)(((uint)puVar7 & 0xffffff00 | (uint)bVar4) * 2);
  *pbVar8 = *pbVar8 | (byte)((uint)in_ECX >> 8);
  DAT_0bd416d1 = DAT_0bd416d1 + (char)in_EDX;
  *(undefined2 *)((int)(puVar3 + iVar1 + uVar2 + -0x24) + uVar11 + -6) = in_ES;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

void exit(int __status)

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  byte bVar4;
  char cVar5;
  uint uVar6;
  uint *puVar7;
  char *pcVar8;
  uint uVar9;
  byte *pbVar10;
  uint uVar11;
  uint uVar12;
  int in_ECX;
  int in_EDX;
  byte bVar13;
  uint *unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined auStack58 [6];
  undefined auStack52 [4];
  undefined auStack48 [4];
  undefined auStack44 [4];
  undefined auStack40 [4];
  undefined auStack36 [4];
  undefined auStack32 [4];
  undefined auStack28 [4];
  undefined auStack24 [4];
  undefined auStack20 [4];
  undefined auStack16 [4];
  undefined auStack12 [4];
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar4 = (char)__status - 0x30;
  uVar6 = __status & 0xffff0000U |
          (uint)CONCAT11((char)((__status & 0xffffff00U) >> 8) +
                         *(char *)((__status & 0xffffff00U | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = &stack0x00000000 + *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + (uVar2 - 4)) = puVar7;
  uVar11 = (uint)puVar7 & 0xffffff00;
  *(byte *)(in_EDX + (int)unaff_EBX) =
       *(byte *)(in_EDX + (int)unaff_EBX) | (byte)((uint)in_EDX >> 8);
  bVar4 = (char)puVar7 + 0xc;
  pcVar8 = (char *)(uVar11 | (uint)bVar4);
  *pcVar8 = *pcVar8 + bVar4;
  bVar4 = (char)puVar7 - 0x24;
  uVar9 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(uVar11 >> 8) + *(char *)((uVar11 | (uint)bVar4) + 2),bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar11 & 1) != 0);
  iVar1 = *(int *)(uVar9 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar9 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + iVar1 + (uVar2 - 4) + (uVar6 - 4)) = puVar7;
  bVar4 = (char)puVar7 + 4;
  pbVar10 = (byte *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  bVar13 = (byte)((uint)unaff_EBX >> 8);
  *pbVar10 = *pbVar10 | bVar13;
  uVar11 = (uint)puVar7 & 0xffffff00 | (uint)(byte)(bVar4 - pbVar10[in_ECX]);
  pcVar8 = (char *)(uVar11 - 1);
  cVar5 = (char)pcVar8;
  *pcVar8 = *pcVar8 + cVar5;
  pcVar8[in_EDX * 8] = pcVar8[in_EDX * 8] + cVar5;
  uVar12 = (uint)pcVar8 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar8 >> 8) + *(char *)(uVar11 + 1),cVar5);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + iVar1 + (uVar2 - 4) + *(int *)(uVar12 + 4) + (uVar6 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar12 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + (uVar9 - 4)) = puVar7;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar13;
  bVar4 = (char)puVar7 + 0xc;
  pcVar8 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  *(undefined **)(puVar3 + (uVar9 - 8)) = puVar3 + (uVar9 - 4);
  *pcVar8 = *pcVar8 + bVar4;
  pcVar8[in_EDX * 8] = pcVar8[in_EDX * 8] + bVar4;
  uVar6 = (uint)puVar7 & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + pcVar8[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar11 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar6 + 4) + (uVar9 - 8);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + uVar2 + -4) = puVar7;
  bVar4 = (char)puVar7 + 4;
  uVar11 = (uint)puVar7 & 0xffffff00;
  pbVar10 = (byte *)((uVar11 | (uint)bVar4) + 0x1a);
  *pbVar10 = *pbVar10 | bVar4;
  bVar4 = (char)puVar7 + 0xc;
  pcVar8 = (char *)(uVar11 | (uint)bVar4);
  *(char **)(puVar3 + uVar2 + -8) = pcVar8;
  *(int *)(puVar3 + uVar2 + -0xc) = in_ECX;
  *(int *)(puVar3 + uVar2 + -0x10) = in_EDX;
  *(uint **)(puVar3 + uVar2 + -0x14) = unaff_EBX;
  *(undefined **)(puVar3 + uVar2 + -0x18) = puVar3 + uVar2 + -4;
  *(undefined4 *)(puVar3 + uVar2 + -0x1c) = unaff_EBP;
  *(undefined4 *)(puVar3 + uVar2 + -0x20) = unaff_ESI;
  *(undefined4 *)(puVar3 + uVar2 + -0x24) = unaff_EDI;
  *pcVar8 = *pcVar8 + bVar4;
  pcVar8[in_EDX * 8] = pcVar8[in_EDX * 8] + bVar4;
  uVar6 = (uint)puVar7 & 0xffff0000 | (uint)CONCAT11((char)(uVar11 >> 8) + pcVar8[2],bVar4);
  uVar11 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar11 = (uint)((uVar11 & 1) != 0);
  iVar1 = *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + iVar1 + uVar2 + -0x24 + uVar11 + -4) = puVar7;
  bVar4 = (char)puVar7 + 4;
  pbVar10 = (byte *)(in_EDX + 4 + (int)unaff_EBX);
  *pbVar10 = *pbVar10 | bVar4;
  pbVar10 = (byte *)(((uint)puVar7 & 0xffffff00 | (uint)bVar4) * 2);
  *pbVar10 = *pbVar10 | (byte)((uint)in_ECX >> 8);
  DAT_0bd416d1 = DAT_0bd416d1 + (char)in_EDX;
  *(undefined2 *)(puVar3 + iVar1 + uVar2 + -0x24 + uVar11 + -6) = in_ES;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Type propagation algorithm not settling
// WARNING: Unknown calling convention yet parameter storage is locked

int atoi(char *__nptr)

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  byte bVar4;
  char cVar5;
  uint uVar6;
  uint *puVar7;
  byte *pbVar8;
  uint uVar9;
  char *pcVar10;
  uint uVar11;
  int in_ECX;
  int in_EDX;
  byte bVar12;
  uint *unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined auStack54 [6];
  undefined auStack48 [4];
  undefined auStack44 [4];
  undefined auStack40 [4];
  undefined auStack36 [4];
  undefined auStack32 [4];
  undefined auStack28 [4];
  undefined auStack24 [4];
  undefined auStack20 [4];
  undefined auStack16 [4];
  undefined auStack12 [4];
  undefined auStack8 [4];
  undefined auStack4 [4];
  
  bVar4 = (char)__nptr - 0x30;
  uVar6 = (uint)__nptr & 0xffff0000 |
          (uint)CONCAT11((char)(((uint)__nptr & 0xffffff00) >> 8) +
                         *(char *)(((uint)__nptr & 0xffffff00 | (uint)bVar4) + 2),bVar4);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar9 & 1) != 0);
  iVar1 = *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(&stack0x00000000 + iVar1 + (uVar2 - 4)) = puVar7;
  bVar4 = (char)puVar7 + 4;
  pbVar8 = (byte *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  bVar12 = (byte)((uint)unaff_EBX >> 8);
  *pbVar8 = *pbVar8 | bVar12;
  uVar9 = (uint)puVar7 & 0xffffff00 | (uint)(byte)(bVar4 - pbVar8[in_ECX]);
  pcVar10 = (char *)(uVar9 - 1);
  cVar5 = (char)pcVar10;
  *pcVar10 = *pcVar10 + cVar5;
  pcVar10[in_EDX * 8] = pcVar10[in_EDX * 8] + cVar5;
  uVar11 = (uint)pcVar10 & 0xffff0000 |
           (uint)CONCAT11((char)((uint)pcVar10 >> 8) + *(char *)(uVar9 + 1),cVar5);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar6 = (uint)((uVar9 & 1) != 0);
  puVar3 = &stack0x00000000 + iVar1 + *(int *)(uVar11 + 4) + (uVar2 - 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar11 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + (uVar6 - 4)) = puVar7;
  *(byte *)(in_EDX + (int)unaff_EBX) = *(byte *)(in_EDX + (int)unaff_EBX) | bVar12;
  bVar4 = (char)puVar7 + 0xc;
  pcVar10 = (char *)((uint)puVar7 & 0xffffff00 | (uint)bVar4);
  *(undefined **)(puVar3 + (uVar6 - 8)) = puVar3 + (uVar6 - 4);
  *pcVar10 = *pcVar10 + bVar4;
  pcVar10[in_EDX * 8] = pcVar10[in_EDX * 8] + bVar4;
  uVar11 = (uint)puVar7 & 0xffff0000 |
           (uint)CONCAT11((char)(((uint)puVar7 & 0xffffff00) >> 8) + pcVar10[2],bVar4);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar2 = (uint)((uVar9 & 1) != 0);
  puVar3 = puVar3 + *(int *)(uVar11 + 4) + (uVar6 - 8);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar11 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + (uVar2 - 4)) = puVar7;
  bVar4 = (char)puVar7 + 4;
  uVar9 = (uint)puVar7 & 0xffffff00;
  pbVar8 = (byte *)((uVar9 | (uint)bVar4) + 0x1a);
  *pbVar8 = *pbVar8 | bVar4;
  bVar4 = (char)puVar7 + 0xc;
  pcVar10 = (char *)(uVar9 | (uint)bVar4);
  *(char **)(puVar3 + (uVar2 - 8)) = pcVar10;
  *(int *)(puVar3 + (uVar2 - 0xc)) = in_ECX;
  *(int *)(puVar3 + (uVar2 - 0x10)) = in_EDX;
  *(uint **)(puVar3 + (uVar2 - 0x14)) = unaff_EBX;
  *(undefined **)(puVar3 + (uVar2 - 0x18)) = puVar3 + (uVar2 - 4);
  *(undefined4 *)(puVar3 + (uVar2 - 0x1c)) = unaff_EBP;
  *(undefined4 *)(puVar3 + (uVar2 - 0x20)) = unaff_ESI;
  *(undefined4 *)(puVar3 + (uVar2 - 0x24)) = unaff_EDI;
  *pcVar10 = *pcVar10 + bVar4;
  pcVar10[in_EDX * 8] = pcVar10[in_EDX * 8] + bVar4;
  uVar6 = (uint)puVar7 & 0xffff0000 | (uint)CONCAT11((char)(uVar9 >> 8) + pcVar10[2],bVar4);
  uVar9 = *unaff_EBX;
  *unaff_EBX = *unaff_EBX >> 1;
  uVar9 = (uint)((uVar9 & 1) != 0);
  iVar1 = *(int *)(uVar6 + 4);
  *unaff_EBX = *unaff_EBX >> 1;
  puVar7 = (uint *)(uVar6 + 2);
  *puVar7 = *puVar7 | (uint)puVar7;
  *(uint **)(puVar3 + iVar1 + (uVar2 - 0x24) + uVar9 + -4) = puVar7;
  bVar4 = (char)puVar7 + 4;
  pbVar8 = (byte *)(in_EDX + 4 + (int)unaff_EBX);
  *pbVar8 = *pbVar8 | bVar4;
  pbVar8 = (byte *)(((uint)puVar7 & 0xffffff00 | (uint)bVar4) * 2);
  *pbVar8 = *pbVar8 | (byte)((uint)in_ECX >> 8);
  DAT_0bd416d1 = DAT_0bd416d1 + (char)in_EDX;
  *(undefined2 *)(puVar3 + iVar1 + (uVar2 - 0x24) + uVar9 + -6) = in_ES;
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

void _fini(undefined param_1)

{
  out(0x2f,param_1);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


