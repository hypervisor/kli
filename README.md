# kli

Simple kernel-mode alternative to [lazy_importer](https://github.com/JustasMasiulis/lazy_importer).

# Example

```cpp
KLI_FN(KeBugCheck)(XBOX_360_SYSTEM_CRASH); // Same as KeBugCheck(XBOX_360_SYSTEM_CRASH);
KLI_FN(ExAllocatePoolWithTag)(NonPagedPool, PAGE_SIZE, 'enoN'); // Same as ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'enoN');
```

# How it works
The macro ``KLI_FN`` hashes the name of desired function in compiletime (using fnv1a64), and in runtime it will enumerate the Export Address Table (EAT) of ntoskrnl.exe to compare against this hash.
To get the kernel base, it uses the SIDT instruction to find the ``nt!KiDivideErrorFault`` Interrupt Service Routine (ISR), and abuses the fact that ntoskrnl.exe is mapped using 2MiB pages to walk downwards until
a valid PE image is found. To avoid issues with discardable sections, checks are ran on the PE image to make sure it's ntoskrnl (otherwise you risk finding random drivers).

# Output

```cpp
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  unsigned __int64 i; // rdx
  __int64 v3; // rax
  __int64 v4; // rax
  unsigned __int64 v5; // r9
  __int128 v6; // xmm0
  __int64 v7; // xmm1_8
  char v8; // al
  __int128 *v9; // r9
  __int64 v10; // rcx
  _DWORD *v11; // rcx
  unsigned __int64 v12; // r11
  unsigned int *v13; // r9
  unsigned int v14; // edi
  unsigned __int64 v15; // rbx
  __int64 v16; // rdx
  __int64 v17; // r10
  char *v18; // rcx
  char v19; // al
  void (__fastcall *v21)(__int64, __int64, _QWORD, unsigned int *); // r8
  _WORD v22[8]; // [rsp+20h] [rbp-30h] BYREF
  __int128 v23; // [rsp+30h] [rbp-20h] BYREF
  __int64 v24; // [rsp+40h] [rbp-10h]
  int v25; // [rsp+48h] [rbp-8h]
  __int16 v26; // [rsp+4Ch] [rbp-4h]
  char v27; // [rsp+4Eh] [rbp-2h]
  char v28; // [rsp+4Fh] [rbp-1h]

  i = qword_140003000;
  if ( !qword_140003000 )
  {
    __sidt(v22);
    if ( !*(_QWORD *)&v22[1] )
      __debugbreak();
    for ( i = ((*(unsigned __int16 *)(*(_QWORD *)&v22[1] + 6i64) | ((unsigned __int64)*(unsigned int *)(*(_QWORD *)&v22[1] + 8i64) << 16)) & 0xFFFFFFFFFFFFFFE0ui64) << 16;
          ;
          i -= 0x200000i64 )
    {
      if ( *(_WORD *)i == 23117 )
      {
        v3 = *(int *)(i + 60);
        if ( *(_DWORD *)(v3 + i) == 17744 && *(_WORD *)(v3 + i + 4) == 0x8664 )
        {
          v4 = *(unsigned int *)(v3 + i + 136);
          v28 = 0;
          v5 = i + *(unsigned int *)(v4 + i + 12);
          v6 = *(_OWORD *)v5;
          v25 = *(_DWORD *)(v5 + 24);
          v7 = *(_QWORD *)(v5 + 16);
          v26 = *(_WORD *)(v5 + 28);
          v27 = *(_BYTE *)(v5 + 30);
          v23 = v6;
          v24 = v7;
          v8 = v6;
          v9 = &v23;
          v10 = 0xCBF29CE484222325ui64;
          if ( (_BYTE)v6 )
          {
            do
            {
              v9 = (__int128 *)((char *)v9 + 1);
              v10 = 0x100000001B3i64 * (v8 ^ (unsigned __int64)v10);
              v8 = *(_BYTE *)v9;
            }
            while ( *(_BYTE *)v9 );
            if ( v10 == 0x9BE7F70164F3DBF0ui64 )
              break;
          }
        }
      }
    }
    qword_140003000 = i;
  }
  v11 = (_DWORD *)(i + *(unsigned int *)(*(int *)(i + 60) + i + 136));
  v12 = i + (unsigned int)v11[7];
  v13 = (unsigned int *)(i + (unsigned int)v11[8]);
  v14 = v11[6];
  v15 = i + (unsigned int)v11[9];
  v16 = 0i64;
  if ( v14 )
  {
    while ( 1 )
    {
      v17 = 0xCBF29CE484222325ui64;
      v18 = (char *)(qword_140003000 + *v13);
      v19 = *v18;
      if ( *v18 )
      {
        do
        {
          ++v18;
          v17 = 0x100000001B3i64 * (v19 ^ (unsigned __int64)v17);
          v19 = *v18;
        }
        while ( *v18 );
        if ( v17 == 0xDA68D5AF5F40988Fui64 )
          break;
      }
      v16 = (unsigned int)(v16 + 1);
      ++v13;
      if ( (unsigned int)v16 >= v14 )
        goto LABEL_18;
    }
    v21 = (void (__fastcall *)(__int64, __int64, _QWORD, unsigned int *))(qword_140003000
                                                                        + *(unsigned int *)(v12
                                                                                          + 4i64
                                                                                          * *(unsigned __int16 *)(v15 + 2i64 * (unsigned int)v16)));
    v21(864i64, v16, v21, v13);
  }
  else
  {
LABEL_18:
    __debugbreak();
    MEMORY[0](864i64, v16, 0i64, v13);
  }
  return 0;
}
```

# Credits
- https://twitter.com/JustasMasiulis for making [lazy_importer](https://github.com/JustasMasiulis/lazy_importer)
- https://twitter.com/Ch40zz_ codereview/debugging
- https://twitter.com/duk_37 codereview
