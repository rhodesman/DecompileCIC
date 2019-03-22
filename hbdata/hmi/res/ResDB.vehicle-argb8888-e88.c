typedef unsigned char   undefined;

typedef unsigned char    undefined1;
typedef unsigned int    undefined4;



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00028735(int iParm1,undefined4 uParm2,uint uParm3)

{
  uint uVar1;
  int extraout_ECX;
  int unaff_EBX;
  undefined4 *unaff_ESI;
  int unaff_EDI;
  byte in_CF;
  
  _DAT_4c42a4a1 = _DAT_4c42a4a1 + unaff_EDI + (uint)in_CF;
  *(byte *)(iParm1 + 0x3e) = *(byte *)(iParm1 + 0x3e) & (byte)iParm1;
  *unaff_ESI = *unaff_ESI;
  uVar1 = func_0x4694d131(iParm1 + 1,iParm1 >> 0x1f,
                          uParm3 & 0xffffff00 |
                          (uint)(byte)(*(char *)(unaff_EBX + 0x7f) - *(char *)(unaff_EDI + 0x27)));
  *(int *)(extraout_ECX + -0x28abeef1) =
       *(int *)(extraout_ECX + -0x28abeef1) -
       (uVar1 & 0xffffff00 | (uint)(byte)((byte)uVar1 | *(byte *)(unaff_EDI + -0x5e7895fc)));
                    // WARNING: Could not recover jumptable at 0x00028764. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(unaff_EBX + 1))(_DAT_b506f7a7);
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_00031ce0(uint uParm1,byte *pbParm2,int *piParm3)

{
  undefined4 uVar1;
  byte bVar2;
  byte bVar3;
  int unaff_EBX;
  uint unaff_ESI;
  undefined4 *unaff_EDI;
  
  bVar3 = (char)pbParm2 + DAT_18484b93 + ((byte)uParm1 < *pbParm2);
  out((ushort)pbParm2 & 0xff00 | (ushort)bVar3,
      uParm1 & 0xffffff00 | (uint)(byte)((byte)uParm1 - *pbParm2));
  *(undefined **)(int *)(unaff_EBX + 0x6c) = &DAT_ffffff98 + *(int *)(unaff_EBX + 0x6c);
  *piParm3 = *piParm3 + unaff_EBX;
  bVar2 = *(byte *)(unaff_EDI + 0x8961002);
  *(byte *)(piParm3 + 0x10) = *(byte *)(piParm3 + 0x10) & bVar3;
  *(byte *)unaff_EDI = *(char *)unaff_EDI - ((byte)unaff_EBX | bVar2);
  *(uint *)((int)unaff_EDI + 0x6f541016) = *(uint *)((int)unaff_EDI + 0x6f541016) ^ unaff_ESI;
  uVar1 = in(CONCAT11(0xd1,bVar3));
  *unaff_EDI = uVar1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0003226a) overlaps instruction at (ram,0x00032266)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00032207(undefined *puParm1,undefined4 uParm2,byte bParm3)

{
  byte *pbVar1;
  int iVar2;
  uint uVar3;
  byte bVar4;
  char *pcVar5;
  uint uVar6;
  int iVar7;
  uint *extraout_ECX;
  uint uVar8;
  uint extraout_EDX;
  int unaff_EBX;
  uint unaff_EBP;
  int *unaff_ESI;
  int *unaff_EDI;
  undefined in_CF;
  bool bVar9;
  unkbyte10 in_ST0;
  float10 in_ST1;
  
  *puParm1 = (char)(CONCAT11(in_CF,*puParm1) >> 1);
  uVar8 = *(int *)(puParm1 + -0x61) * -0x2bff7fe8;
  out((short)uVar8,puParm1);
  pcVar5 = (char *)((uint)puParm1 | 0x80);
  *pcVar5 = (*pcVar5 - (char)((uint)puParm1 >> 8)) - ((uint)unaff_EDI[-0x1e5bb7fa] < uVar8);
  pbVar1 = (byte *)(uVar8 - 0x56);
  bVar9 = CARRY1(*pbVar1,bParm3) || CARRY1(*pbVar1 + bParm3,(char *)0x5af39cee < pcVar5);
  *pbVar1 = *pbVar1 + bParm3 + ((char *)0x5af39cee < pcVar5);
  (*(code *)unaff_ESI)(pcVar5 + -0x5af39cef);
  uVar6 = func_0x9a5ae735();
  out(0x5a,uVar6);
  uVar3 = _DAT_668b589f & 0xfffffff;
  _DAT_668b589f = (_DAT_668b589f - extraout_EDX) - (uint)bVar9;
  uVar8 = *(uint *)(unaff_EBX + 0x1097a013);
  *(uint *)(unaff_EBX + 0x1097a013) = unaff_EBP;
  bVar4 = DAT_ab4bc41f;
  *extraout_ECX = ~*extraout_ECX;
  bVar9 = 9 < (bVar4 & 0xf) ||
          ((uVar3 - (extraout_EDX & 0xfffffff)) - (uint)bVar9 & 0x10000000) != 0;
  bVar4 = bVar4 + bVar9 * -6;
  bVar4 = bVar4 + (0x9f < bVar4 | CARRY4(uVar8,extraout_EDX) | bVar9 * (bVar4 < 6)) * -0x60;
  pcVar5 = (char *)(uVar6 & 0xffffff00 | (uint)bVar4);
  if (uVar8 + extraout_EDX == 0) {
    *(byte *)((int)extraout_ECX + -0x76) = *(byte *)((int)extraout_ECX + -0x76) & bVar4;
    *(unkbyte10 *)(pcVar5 + -0x50572750) = in_ST0;
    *pcVar5 = *pcVar5 - (char)unaff_EBX;
    iVar7 = iRam00000000;
    _DAT_b296a015 = (short)ROUND(in_ST1);
    DAT_f79a6c6b = DAT_f79a6c6b + 1;
    iVar2 = *unaff_ESI;
    *(int *)(extraout_EDX + 0x322d8d67) = *(int *)(extraout_EDX + 0x322d8d67) + iRam00000000;
    uVar8 = *(uint *)(&DAT_ffffffa7 + iVar7 + extraout_EDX);
    iVar7 = (iVar2 + 0x106f230dU) - *(uint *)(&DAT_ffffffa7 + iVar7 + extraout_EDX);
    *unaff_EDI = iVar7;
    *(char *)(unaff_EBX + -0x1a5a601) =
         (*(char *)(unaff_EBX + -0x1a5a601) - (char)((uint)extraout_ECX >> 8)) -
         (iVar2 + 0x106f230dU < uVar8);
    pcVar5 = _LAB_00000003_1;
    _LAB_00000003_1 = (char *)0xffffffff;
    pcVar5[-0x576ffe74] = pcVar5[-0x576ffe74] + (char)extraout_ECX;
    *(uint *)((int)extraout_ECX + 0x57) = *(uint *)((int)extraout_ECX + 0x57) ^ 0x42;
    *pcVar5 = *pcVar5 + (char)((uint)iVar7 >> 8);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  func_0xaa01adf7();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void FUN_000b7903(undefined4 uParm1,uint uParm2)

{
  code *pcVar1;
  int unaff_EBP;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined4 in_stack_00000000;
  
  *unaff_EDI = *unaff_ESI;
  out(0x83,uParm1);
  *(uint *)(&DAT_ffffff97 + unaff_EBP) = *(uint *)(&DAT_ffffff97 + unaff_EBP) | uParm2;
  pcVar1 = (code *)swi(0x6f);
  (*pcVar1)(in_stack_00000000,uParm2 & 0xffff0000 | (uint)CONCAT11(0x17,(char)uParm2));
  return;
}


