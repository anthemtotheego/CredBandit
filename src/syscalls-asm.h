#pragma once
#include "syscalls.h"

#define ZwCreateFile NtCreateFile
__asm__("NtCreateFile: \n\
	mov rax, gs:[0x60]                       \n\
NtCreateFile_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtCreateFile_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtCreateFile_Check_10_0_XXXX \n\
	jmp NtCreateFile_SystemCall_Unknown \n\
NtCreateFile_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtCreateFile_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtCreateFile_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtCreateFile_SystemCall_6_3_XXXX \n\
	jmp NtCreateFile_SystemCall_Unknown \n\
NtCreateFile_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtCreateFile_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtCreateFile_SystemCall_6_1_7601 \n\
	jmp NtCreateFile_SystemCall_Unknown \n\
NtCreateFile_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtCreateFile_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtCreateFile_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtCreateFile_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtCreateFile_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtCreateFile_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtCreateFile_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtCreateFile_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtCreateFile_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtCreateFile_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtCreateFile_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtCreateFile_SystemCall_10_0_19042 \n\
	jmp NtCreateFile_SystemCall_Unknown \n\
NtCreateFile_SystemCall_6_1_7600:           \n\
	mov eax, 0x0052 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_6_1_7601:           \n\
	mov eax, 0x0052 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0053 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0054 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_10240:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_10586:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_14393:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_15063:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_16299:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_17134:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_17763:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_18362:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_18363:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_19041:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_10_0_19042:         \n\
	mov eax, 0x0055 \n\
	jmp NtCreateFile_Epilogue \n\
NtCreateFile_SystemCall_Unknown:            \n\
	ret \n\
NtCreateFile_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwCreateSection NtCreateSection
__asm__("NtCreateSection: \n\
	mov rax, gs:[0x60]                          \n\
NtCreateSection_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtCreateSection_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtCreateSection_Check_10_0_XXXX \n\
	jmp NtCreateSection_SystemCall_Unknown \n\
NtCreateSection_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtCreateSection_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtCreateSection_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtCreateSection_SystemCall_6_3_XXXX \n\
	jmp NtCreateSection_SystemCall_Unknown \n\
NtCreateSection_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtCreateSection_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtCreateSection_SystemCall_6_1_7601 \n\
	jmp NtCreateSection_SystemCall_Unknown \n\
NtCreateSection_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtCreateSection_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtCreateSection_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtCreateSection_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtCreateSection_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtCreateSection_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtCreateSection_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtCreateSection_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtCreateSection_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtCreateSection_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtCreateSection_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtCreateSection_SystemCall_10_0_19042 \n\
	jmp NtCreateSection_SystemCall_Unknown \n\
NtCreateSection_SystemCall_6_1_7600:           \n\
	mov eax, 0x0047 \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_6_1_7601:           \n\
	mov eax, 0x0047 \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0048 \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0049 \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_10240:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_10586:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_14393:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_15063:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_16299:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_17134:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_17763:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_18362:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_18363:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_19041:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_19042:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_Unknown:            \n\
	ret \n\
NtCreateSection_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwCreateTransaction NtCreateTransaction
__asm__("NtCreateTransaction: \n\
	mov rax, gs:[0x60]                              \n\
NtCreateTransaction_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtCreateTransaction_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtCreateTransaction_Check_10_0_XXXX \n\
	jmp NtCreateTransaction_SystemCall_Unknown \n\
NtCreateTransaction_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtCreateTransaction_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtCreateTransaction_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtCreateTransaction_SystemCall_6_3_XXXX \n\
	jmp NtCreateTransaction_SystemCall_Unknown \n\
NtCreateTransaction_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtCreateTransaction_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtCreateTransaction_SystemCall_6_1_7601 \n\
	jmp NtCreateTransaction_SystemCall_Unknown \n\
NtCreateTransaction_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtCreateTransaction_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtCreateTransaction_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtCreateTransaction_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtCreateTransaction_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtCreateTransaction_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtCreateTransaction_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtCreateTransaction_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtCreateTransaction_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtCreateTransaction_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtCreateTransaction_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtCreateTransaction_SystemCall_10_0_19042 \n\
	jmp NtCreateTransaction_SystemCall_Unknown \n\
NtCreateTransaction_SystemCall_6_1_7600:           \n\
	mov eax, 0x00a8 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_6_1_7601:           \n\
	mov eax, 0x00a8 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x00b3 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x00b5 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_10240:         \n\
	mov eax, 0x00b8 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_10586:         \n\
	mov eax, 0x00b9 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_14393:         \n\
	mov eax, 0x00bb \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_15063:         \n\
	mov eax, 0x00be \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_16299:         \n\
	mov eax, 0x00bf \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_17134:         \n\
	mov eax, 0x00c0 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_17763:         \n\
	mov eax, 0x00c1 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_18362:         \n\
	mov eax, 0x00c2 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_18363:         \n\
	mov eax, 0x00c2 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_19041:         \n\
	mov eax, 0x00c6 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_10_0_19042:         \n\
	mov eax, 0x00c6 \n\
	jmp NtCreateTransaction_Epilogue \n\
NtCreateTransaction_SystemCall_Unknown:            \n\
	ret \n\
NtCreateTransaction_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwMapViewOfSection NtMapViewOfSection
__asm__("NtMapViewOfSection: \n\
	mov rax, gs:[0x60]                             \n\
NtMapViewOfSection_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtMapViewOfSection_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtMapViewOfSection_Check_10_0_XXXX \n\
	jmp NtMapViewOfSection_SystemCall_Unknown \n\
NtMapViewOfSection_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtMapViewOfSection_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtMapViewOfSection_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtMapViewOfSection_SystemCall_6_3_XXXX \n\
	jmp NtMapViewOfSection_SystemCall_Unknown \n\
NtMapViewOfSection_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtMapViewOfSection_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtMapViewOfSection_SystemCall_6_1_7601 \n\
	jmp NtMapViewOfSection_SystemCall_Unknown \n\
NtMapViewOfSection_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtMapViewOfSection_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtMapViewOfSection_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtMapViewOfSection_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtMapViewOfSection_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtMapViewOfSection_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtMapViewOfSection_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtMapViewOfSection_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtMapViewOfSection_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtMapViewOfSection_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtMapViewOfSection_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtMapViewOfSection_SystemCall_10_0_19042 \n\
	jmp NtMapViewOfSection_SystemCall_Unknown \n\
NtMapViewOfSection_SystemCall_6_1_7600:           \n\
	mov eax, 0x0025 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_6_1_7601:           \n\
	mov eax, 0x0025 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0026 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0027 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_10240:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_10586:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_14393:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_15063:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_16299:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_17134:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_17763:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_18362:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_18363:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_19041:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_19042:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_Unknown:            \n\
	ret \n\
NtMapViewOfSection_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__("NtAdjustPrivilegesToken: \n\
	mov rax, gs:[0x60]                                  \n\
NtAdjustPrivilegesToken_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtAdjustPrivilegesToken_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtAdjustPrivilegesToken_Check_10_0_XXXX \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtAdjustPrivilegesToken_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_3_XXXX \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7601 \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19042 \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_SystemCall_6_1_7600:           \n\
	mov eax, 0x003e \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_6_1_7601:           \n\
	mov eax, 0x003e \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x003f \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0040 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_10240:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_10586:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_14393:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_15063:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_16299:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_17134:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_17763:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_18362:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_18363:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_19041:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_19042:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_Unknown:            \n\
	ret \n\
NtAdjustPrivilegesToken_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__("NtReadVirtualMemory: \n\
	mov rax, gs:[0x60]                              \n\
NtReadVirtualMemory_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtReadVirtualMemory_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtReadVirtualMemory_Check_10_0_XXXX \n\
	jmp NtReadVirtualMemory_SystemCall_Unknown \n\
NtReadVirtualMemory_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtReadVirtualMemory_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtReadVirtualMemory_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtReadVirtualMemory_SystemCall_6_3_XXXX \n\
	jmp NtReadVirtualMemory_SystemCall_Unknown \n\
NtReadVirtualMemory_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtReadVirtualMemory_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtReadVirtualMemory_SystemCall_6_1_7601 \n\
	jmp NtReadVirtualMemory_SystemCall_Unknown \n\
NtReadVirtualMemory_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_19042 \n\
	jmp NtReadVirtualMemory_SystemCall_Unknown \n\
NtReadVirtualMemory_SystemCall_6_1_7600:           \n\
	mov eax, 0x003c \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_6_1_7601:           \n\
	mov eax, 0x003c \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x003d \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x003e \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_10240:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_10586:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_14393:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_15063:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_16299:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_17134:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_17763:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_18362:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_18363:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_19041:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_19042:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_Unknown:            \n\
	ret \n\
NtReadVirtualMemory_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenProcessToken NtOpenProcessToken
__asm__("NtOpenProcessToken: \n\
	mov rax, gs:[0x60]                             \n\
NtOpenProcessToken_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtOpenProcessToken_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtOpenProcessToken_Check_10_0_XXXX \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtOpenProcessToken_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtOpenProcessToken_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtOpenProcessToken_SystemCall_6_3_XXXX \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtOpenProcessToken_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtOpenProcessToken_SystemCall_6_1_7601 \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtOpenProcessToken_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtOpenProcessToken_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtOpenProcessToken_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtOpenProcessToken_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtOpenProcessToken_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtOpenProcessToken_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtOpenProcessToken_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtOpenProcessToken_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtOpenProcessToken_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtOpenProcessToken_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtOpenProcessToken_SystemCall_10_0_19042 \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_SystemCall_6_1_7600:           \n\
	mov eax, 0x00f9 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_6_1_7601:           \n\
	mov eax, 0x00f9 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x010b \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x010e \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_10240:         \n\
	mov eax, 0x0114 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_10586:         \n\
	mov eax, 0x0117 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_14393:         \n\
	mov eax, 0x0119 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_15063:         \n\
	mov eax, 0x011d \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_16299:         \n\
	mov eax, 0x011f \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_17134:         \n\
	mov eax, 0x0121 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_17763:         \n\
	mov eax, 0x0122 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_18362:         \n\
	mov eax, 0x0123 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_18363:         \n\
	mov eax, 0x0123 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_19041:         \n\
	mov eax, 0x0128 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_19042:         \n\
	mov eax, 0x0128 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_Unknown:            \n\
	ret \n\
NtOpenProcessToken_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	mov rax, gs:[0x60]                        \n\
NtOpenProcess_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtOpenProcess_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtOpenProcess_Check_10_0_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtOpenProcess_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtOpenProcess_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtOpenProcess_SystemCall_6_3_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtOpenProcess_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtOpenProcess_SystemCall_6_1_7601 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtOpenProcess_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtOpenProcess_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtOpenProcess_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtOpenProcess_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtOpenProcess_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtOpenProcess_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtOpenProcess_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtOpenProcess_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtOpenProcess_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtOpenProcess_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtOpenProcess_SystemCall_10_0_19042 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_SystemCall_6_1_7600:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_1_7601:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0024 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0025 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10240:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10586:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_14393:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_15063:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_16299:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17134:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17763:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18362:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18363:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19041:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19042:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_Unknown:            \n\
	ret \n\
NtOpenProcess_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwClose NtClose
__asm__("NtClose: \n\
	mov rax, gs:[0x60]                  \n\
NtClose_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtClose_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtClose_Check_10_0_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtClose_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtClose_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtClose_SystemCall_6_3_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtClose_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtClose_SystemCall_6_1_7601 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtClose_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtClose_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtClose_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtClose_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtClose_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtClose_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtClose_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtClose_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtClose_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtClose_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtClose_SystemCall_10_0_19042 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_SystemCall_6_1_7600:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_1_7601:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x000d \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x000e \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10240:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10586:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_14393:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_15063:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_16299:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17134:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17763:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18362:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18363:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19041:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19042:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_Unknown:            \n\
	ret \n\
NtClose_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwQuerySystemInformation NtQuerySystemInformation
__asm__("NtQuerySystemInformation: \n\
	mov rax, gs:[0x60]                                   \n\
NtQuerySystemInformation_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtQuerySystemInformation_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtQuerySystemInformation_Check_10_0_XXXX \n\
	jmp NtQuerySystemInformation_SystemCall_Unknown \n\
NtQuerySystemInformation_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtQuerySystemInformation_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtQuerySystemInformation_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtQuerySystemInformation_SystemCall_6_3_XXXX \n\
	jmp NtQuerySystemInformation_SystemCall_Unknown \n\
NtQuerySystemInformation_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtQuerySystemInformation_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtQuerySystemInformation_SystemCall_6_1_7601 \n\
	jmp NtQuerySystemInformation_SystemCall_Unknown \n\
NtQuerySystemInformation_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_19042 \n\
	jmp NtQuerySystemInformation_SystemCall_Unknown \n\
NtQuerySystemInformation_SystemCall_6_1_7600:           \n\
	mov eax, 0x0033 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_6_1_7601:           \n\
	mov eax, 0x0033 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0034 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0035 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_10240:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_10586:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_14393:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_15063:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_16299:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_17134:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_17763:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_18362:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_18363:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_19041:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_19042:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_Unknown:            \n\
	ret \n\
NtQuerySystemInformation_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");
