typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned short    word;
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




// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_7030f4cf(char *pcParm1,int iParm2,char *pcParm3)

{
  code *pcVar1;
  uint uVar2;
  char cVar3;
  byte bVar4;
  char cVar10;
  int *piVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  char *pcVar9;
  char cVar11;
  char *pcVar12;
  char cVar13;
  char cVar14;
  uint unaff_EBX;
  int unaff_ESI;
  int unaff_EDI;
  
  bVar4 = (byte)pcParm1;
  *pcParm3 = *pcParm3 + bVar4;
  *pcParm1 = *pcParm1 + bVar4;
  cVar11 = (char)pcParm3;
  pcParm1[0x1000648] = pcParm1[0x1000648] + cVar11;
  piVar5 = (int *)((uint)pcParm1 & 0xffff0000 | (uint)CONCAT11(bVar4 / 1,bVar4) & 0xffffff00 |
                  (uint)pcParm1 & 1);
  cVar3 = (char)((uint)pcParm1 & 1);
  *(char *)piVar5 = *(char *)piVar5 + cVar3;
  *(char *)piVar5 = *(char *)piVar5 + cVar3;
  pcVar9 = (char *)((int)piVar5 + (int)pcParm3 * 2 + -0x2bfefffa);
  *pcVar9 = *pcVar9 + cVar11;
  *piVar5 = *piVar5 + (int)piVar5;
  *(char *)piVar5 = *(char *)piVar5 + cVar3;
  *(char *)piVar5 = *(char *)piVar5 + cVar3;
  iVar6 = (((uint)pcParm1 & 0xffff0000) >> 8 | unaff_EBX & 0xff) * 0x100;
  iVar7 = iVar6 + -2;
  uVar8 = (iVar6 - 0x100U | (uint)(byte)((char)iVar7 + (char)((uint)iVar7 >> 8))) - 2;
  cVar3 = (char)((uint)pcParm3 >> 8);
  uVar8 = (uVar8 & 0xffffff00 | (uint)(byte)((char)uVar8 + cVar3)) - 2;
  uVar8 = (uVar8 & 0xffff0000 | (uint)CONCAT11((char)(uVar8 >> 8) + cVar3,(char)uVar8)) - 2;
  cVar3 = (char)((uint)iParm2 >> 8);
  uVar8 = (uVar8 & 0xffff0000 | (uint)CONCAT11((char)(uVar8 >> 8) + cVar3,(char)uVar8)) - 2;
  cVar14 = (char)(unaff_EBX >> 8);
  bVar4 = (char)uVar8 + cVar14;
  uVar8 = uVar8 & 0xffffff00 | (uint)bVar4;
  pcVar9 = (char *)(uVar8 - 2);
  *pcVar9 = *pcVar9 + (char)pcVar9;
  pcVar12 = pcParm3 + -1;
  *(char *)((int)pcVar12 * 3) = *(char *)((int)pcVar12 * 3) + (bVar4 - 3);
  pcVar9 = (char *)(uVar8 - 4);
  *(char *)((int)pcVar12 * 3) = *(char *)((int)pcVar12 * 3) + (char)pcVar12;
  cVar10 = (char)((uint)pcVar9 >> 8);
  cVar13 = (char)iParm2;
  *pcVar9 = *pcVar9 + cVar13;
  *pcVar9 = *pcVar9 + (char)unaff_EBX;
  *(char *)((int)(pcParm3 + -6) * 3) = *(char *)((int)(pcParm3 + -6) * 3) + (char)unaff_EBX;
  *(char *)((int)(pcParm3 + -7) * 3) = *(char *)((int)(pcParm3 + -7) * 3) + cVar10;
  *pcVar9 = *pcVar9 + (char)((uint)(pcParm3 + -8) >> 8);
  *pcVar9 = *pcVar9 + cVar3;
  *(char *)((int)(pcParm3 + -0xc) * 3) = *(char *)((int)(pcParm3 + -0xc) * 3) + cVar3;
  cVar3 = (char)pcVar9;
  uVar8 = (uint)pcVar9 & 0xffff0000;
  uVar2 = (uint)CONCAT11(cVar10 + cVar14,cVar3);
  pcVar12 = (char *)(uVar8 | uVar2);
  *pcVar12 = *pcVar12 + cVar3;
  pcVar9 = (char *)((unaff_EBX - 1) + (int)(pcParm3 + -0xf) * 2);
  *pcVar9 = *pcVar9 + cVar3;
  *pcVar12 = *pcVar12 + cVar11 + -0x10;
  pcParm3 = pcParm3 + -0x11;
  pcVar9 = (char *)((unaff_EBX - 2) + (int)pcParm3 * 2);
  *pcVar9 = *pcVar9 + (char)pcParm3;
  *pcVar12 = *pcVar12 + cVar13 + -2;
  pcVar9 = (char *)((unaff_EBX - 3) + (int)pcParm3 * 2);
  *pcVar9 = *pcVar9 + cVar13 + -3;
  *pcVar12 = *pcVar12 + (char)(unaff_EBX - 3);
  uVar2 = (uint)CONCAT11((char)(uVar2 >> 8) + (char)(unaff_EBX - 4 >> 8),cVar3);
  pcVar9 = (char *)(uVar8 | uVar2);
  _DAT_064c0000 = _DAT_064c0000 + 1;
  _DAT_064c0400 = _DAT_064c0400 + 1;
  DAT_064c0800 = DAT_064c0800 + 1;
  DAT_064c0c00 = DAT_064c0c00 + 1;
  _DAT_064c1000 = _DAT_064c1000 + 1;
  _DAT_064c1400 = _DAT_064c1400 + 1;
  _DAT_064c1800 = _DAT_064c1800 + 1;
  _DAT_064c1c00 = _DAT_064c1c00 + 1;
  _DAT_064c2000 = _DAT_064c2000 + 1;
  _DAT_064c2400 = _DAT_064c2400 + 1;
  _DAT_064c3800 = _DAT_064c3800 + 1;
  _DAT_064c3c00 = _DAT_064c3c00 + 1;
  _DAT_064c4000 = _DAT_064c4000 + 1;
  _DAT_064c4400 = _DAT_064c4400 + 1;
  _DAT_064c4800 = _DAT_064c4800 + 1;
  _DAT_064c4c00 = _DAT_064c4c00 + 1;
  _DAT_064c5000 = _DAT_064c5000 + 1;
  _DAT_064c5400 = _DAT_064c5400 + 1;
  _DAT_064c5800 = _DAT_064c5800 + 1;
  _DAT_064c5c00 = _DAT_064c5c00 + 1;
  _DAT_064c6000 = _DAT_064c6000 + 1;
  _DAT_064c6400 = _DAT_064c6400 + 1;
  _DAT_064c6800 = _DAT_064c6800 + 1;
  _DAT_064c6c00 = _DAT_064c6c00 + 1;
  _DAT_064c7000 = _DAT_064c7000 + 1;
  _DAT_064c7400 = _DAT_064c7400 + 1;
  _DAT_064c7800 = _DAT_064c7800 + 1;
  _DAT_064c7c00 = _DAT_064c7c00 + 1;
  _DAT_064c8000 = _DAT_064c8000 + 1;
  _DAT_064cac00 = _DAT_064cac00 + 1;
  _DAT_064cb000 = _DAT_064cb000 + 1;
  _DAT_064ec000 = _DAT_064ec000 + 1;
  _DAT_064ec400 = _DAT_064ec400 + 1;
  _DAT_064ec800 = _DAT_064ec800 + 1;
  _DAT_064ecc00 = _DAT_064ecc00 + 1;
  _DAT_064ed000 = _DAT_064ed000 + 1;
  _DAT_064ed400 = _DAT_064ed400 + 1;
  _DAT_064ed800 = _DAT_064ed800 + 1;
  *pcParm3 = *pcParm3 + cVar3;
  *pcVar9 = *pcVar9 + cVar3;
  *pcVar9 = *pcVar9 + cVar3;
  cVar10 = (char)(unaff_EBX - 5);
  uVar2 = (uint)CONCAT11((char)(uVar2 >> 8) + cVar10,cVar3);
  pcVar9 = (char *)(uVar8 | uVar2);
  *pcParm3 = *pcParm3 + cVar3;
  *pcVar9 = *pcVar9 + cVar3;
  *pcVar9 = *pcVar9 + cVar3;
  bVar4 = cVar3 + (char)(uVar2 >> 8);
  pcVar9 = (char *)(uVar8 | uVar2 & 0xffffff00 | (uint)bVar4);
  *pcParm3 = *pcParm3 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  uVar2 = (uint)CONCAT11((char)((uVar2 & 0xffffff00) >> 8) * 2,bVar4);
  pcVar9 = (char *)(uVar8 | uVar2);
  *pcParm3 = *pcParm3 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  cVar11 = (char)((uint)pcParm3 >> 8);
  bVar4 = bVar4 + cVar11;
  uVar2 = uVar2 & 0xffffff00;
  pcVar9 = (char *)(uVar8 | uVar2 | (uint)bVar4);
  *pcParm3 = *pcParm3 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  uVar2 = (uint)CONCAT11((char)(uVar2 >> 8) + cVar11,bVar4);
  pcVar9 = (char *)(uVar8 | uVar2);
  *pcParm3 = *pcParm3 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  cVar13 = (char)((uint)(iParm2 + -5) >> 8);
  bVar4 = bVar4 + cVar13;
  uVar2 = uVar2 & 0xffffff00;
  uVar8 = uVar8 | uVar2;
  pcVar9 = (char *)(uVar8 | (uint)bVar4);
  pcVar12 = (char *)(unaff_ESI + -6);
  *pcParm3 = *pcParm3 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  *pcVar9 = *pcVar9 + bVar4;
  pcVar9[0x4f] = pcVar9[0x4f] + (char)(iParm2 + -5);
  *pcVar12 = *pcVar12 + bVar4;
  pcVar9[0x4f] = pcVar9[0x4f] + cVar10;
  cVar3 = *pcVar12;
  pcVar9 = (char *)(unaff_EDI + 6 + (int)pcParm3 * 2);
  *pcVar9 = *pcVar9 + cVar10;
  bVar4 = bVar4 + cVar3 + *pcVar12;
  pcVar9 = (char *)((uVar8 | (uint)bVar4) + 0x4f);
  cVar10 = (char)(uVar2 >> 8);
  *pcVar9 = *pcVar9 + cVar10;
  cVar3 = *pcVar12;
  pcVar9 = (char *)(unaff_EDI + 6 + (int)pcParm3 * 2);
  *pcVar9 = *pcVar9 + cVar10;
  bVar4 = bVar4 + cVar3 + *pcVar12;
  pcVar9 = (char *)((uVar8 | (uint)bVar4) + 0x4f);
  *pcVar9 = *pcVar9 + cVar11;
  cVar3 = *pcVar12;
  pcVar9 = (char *)(unaff_EDI + 6 + (int)pcParm3 * 2);
  *pcVar9 = *pcVar9 + cVar11;
  bVar4 = bVar4 + cVar3 + *pcVar12;
  pcVar9 = (char *)((uVar8 | (uint)bVar4) + 0x4f);
  *pcVar9 = *pcVar9 + cVar13;
  cVar3 = *pcVar12;
  pcVar9 = (char *)(unaff_EDI + 6 + (int)pcParm3 * 2);
  *pcVar9 = *pcVar9 + cVar13;
  bVar4 = bVar4 + cVar3 + *pcVar12;
  pcVar12 = (char *)(uVar8 | (uint)bVar4);
  pcVar12[0x4f] = pcVar12[0x4f] + (char)(unaff_EBX - 5 >> 8);
  pcVar9 = (char *)(unaff_EDI + 0xa50006 + (int)pcParm3 * 2);
  *pcVar9 = *pcVar9 + bVar4;
  *pcVar12 = *pcVar12 + bVar4;
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


