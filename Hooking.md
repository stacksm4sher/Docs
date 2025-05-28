# Understanding Hooking

## Simple hooking

Simply taking the address of the function and the hook and then inserting the shell code

```cpp
// Example CPP code

void hook()
{
    printf("Function hooked!");
}

void foo()
{
    printf("Original function");
}
```

```nasm
; Same functions but in asm

.data
FUNCTION_HOOKED_STR db "Function hooked!", 0
ORIGINAL_FUNCTION_STR db "Original function", 0

.text
hook proc
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    lea rcx, [FUNCTION_HOOKED_STR]
    call printf
    mov rsp, rbp
    pop rbp
    ret
hook endp

foo proc
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    lea rcx, [ORIGINAL_FUNCTION_STR]
    call printf
    mov rsp, rbp
    pop rbp
    ret
foo endp
```

Now we need to install hook and here is how we can do it

```cpp

/*
Also consider not just returning void.
Save the original bytes of the function to restore the function later.
*/
void InstallHook(PVOID target, PVOID hook)
{
    /* 
    we are going to use jmp [rip + 0x0]
    but mov rax, call rax or push 0x00, ret is valid as well
    */
    const BYTE shellCode[14] = { 0 };
    const BYTE jumpRip[6] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00 };
    memcpy((PVOID)shellCode, jumpRip, sizeof(jumpRip)); 
    memcpy((PVOID)((ULONG_PTR)shellCode + sizeof(jumpRip)), hook, sizeof(PVOID));

    /*
    After this operation our

    foo proc
        push rbp
        mov rbp, rsp
        sub rsp, 20h
        lea rcx, [ORIGINAL_FUNCTION_STR]
        call printf
        mov rsp, rbp
        pop rbp
        ret
    foo endp

    should turn into

    foo proc
        jmp [rip + 0x0]
        0xFFFFFFFFFFFFFFFF (ADDRESS OF THE HOOK)
        0x00 0x00 (leftover of lea rcx, ORIGINAL_FUNCTION_STR)
        call printf
        mov rsp, rbp
        pop rbp
        ret
    foo endp
    */
    DWORD oldProtect;
    VirtualProtect((PVOID)((ULONG_PTR)Foo + prologueEndOffset), sizeof(SHELL_CODE), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(target, shellCode, sizeof(shellCode));
    VirtualProtect((PVOID)((ULONG_PTR)Foo + prologueEndOffset), sizeof(SHELL_CODE), oldProtect, &oldProtect);
}
```

And that was the simple hook.

## Advanced hooking. Prologue-Epilogue bounds. (First method)

Anti-cheats usually detect prologue/epilogue modifications with mov rax, jmp rax or similar operations. 
So we should move our hook deeper into the code.

Firstly we need to determine where prologue ends an where epilogue starts to set the bounds,
then we need to find any safe instruction in procedure body to avoid code corruption.

For example we will to use such assembly code:

```nasm
; Our goal is to determine prologue and epilogue offsets
; so we can insert our hook inside the body of the procedure
Foo proc
	push rbp
	mov rbp, rsp
	sub rsp, 28h    ; prologue ends here

	mov rax, 1h     ; here is our body we can modify
	mov rbx, 8h
	sub rbx, rax
	mov rax, rbx

	mov rsp, rbp    ; epilogue starts here
	pop rbp
	ret
Foo endp
```

Time to code!

```cpp
#include <Zydis/Zydis.h>

#define DETERMINATION_ERROR -1
#define SUB_RSP_TYPE 0
#define ADD_RSP_TYPE 1
#define MOV_RSP_RBP_TYPE 2
#define NOT_STACK_OPERATION 3

typedef struct _SAFE_INSTRUCTION
{
	ULONG_PTR SafeInstructionOffset;
	ULONG64 SafeInstructionLength;
} SAFE_INSTRUCTION, *PSAFE_INSTRUCTION;

typedef struct _FUNCTION_INFO
{
	ULONG_PTR PrologueEndOffset;
	ULONG_PTR EpilogueStartOffset;
	PSAFE_INSTRUCTION SafeInstuctions;
	ULONG64 SafeInstructionsSize;

	ULONG64 CalculateTotalSafeInstructionsLength()
	{
		ULONG64 totalLength = 0;
		for (ULONG64 i = 0; i < SafeInstructionsSize; i++)
		{
			SAFE_INSTRUCTION instruction = SafeInstuctions[i];
			totalLength += instruction.SafeInstructionLength;
		}
		return totalLength;
	}
} FUNCTION_INFO;

/*
Using Zydis disassembler because I don't really want to implement it myself now
*/
ULONG32 DetermineStackOperationType(ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operands)
{
    // Each stack forming operation ends with sub rsp, %value%
	if (instruction->mnemonic == ZYDIS_MNEMONIC_SUB)
	{
		ZydisRegister firstOperand = operands[0].reg.value;
		if (firstOperand == ZYDIS_REGISTER_RSP)
		{
			return SUB_RSP_TYPE;
		}
	}

    // but for stack clean-up we should either look for add rsp, or mov rsp, rbp
	if (instruction->mnemonic == ZYDIS_MNEMONIC_ADD)
	{
		ZydisRegister firstOperand = operands[0].reg.value;
		if (firstOperand == ZYDIS_REGISTER_RSP)
		{
			return ADD_RSP_TYPE;
		}
	}

	if (instruction->mnemonic == ZYDIS_MNEMONIC_MOV)
	{
		ZydisRegister firstOperand = operands[0].reg.value;
		ZydisRegister secondOperand = operands[1].reg.value;

		if (firstOperand == ZYDIS_REGISTER_RSP && secondOperand == ZYDIS_REGISTER_RBP)
		{
			return MOV_RSP_RBP_TYPE;
		}
	}

	return NOT_STACK_OPERATION;
}

template<typename T>
void ReallocMemory(T** memory, ULONG64& size, ULONG64 multiplier)
{
	size = size * multiplier;
	T* newMem = new T[size]{ 0 };
	memcpy(newMem, *memory, size * sizeof(T));
	delete[] * memory;
	*memory = newMem;
}

template<typename T>
void ShrinkMemoryZeroes(T** memory, ULONG64 size)
{
	T* newMem = new T[size]{ 0 };
	memcpy(newMem, *memory, size * sizeof(T));
	delete[] * memory;
	*memory = newMem;
}

HOOKAPI FUNCTION_INFO ScanFunction(PVOID target)
{
	PVOID scanFunction = target;

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	FUNCTION_INFO functionInfo = { NULL, NULL, NULL, NULL };

	ULONG_PTR prologueEndOffset = NULL;
	ULONG_PTR epilogueStartOffset = NULL;
	ULONG64 safeInstructionOffsetsMaxSize = 16;
	PSAFE_INSTRUCTION safeInstructions = new SAFE_INSTRUCTION[safeInstructionOffsetsMaxSize]{ 0 };
	ULONG64 safeInstructionsSize = 0;

	BOOL bEpilogueReached = FALSE;
	BOOL bIsInPrologue = TRUE;
	while (!bEpilogueReached)
	{
		ZydisDecodedInstruction* instruction = new ZydisDecodedInstruction;
		ZydisDecodedOperand* operands = new ZydisDecodedOperand[ZYDIS_MAX_OPERAND_COUNT]{ 0 };
		ZyanStatus status = ZydisDecoderDecodeFull(&decoder, scanFunction, 15, instruction, operands);

		if (!ZYAN_SUCCESS(status))
		{
			printf("Failed to decode instruction at %p\n", scanFunction);
			break;
		}

		ULONG32 operationType = DetermineStackOperationType(instruction, operands);

		if (operationType == SUB_RSP_TYPE)
		{
			prologueEndOffset = ((ULONG_PTR)scanFunction + instruction->length) - (ULONG_PTR)target;
			bIsInPrologue = FALSE;
		}

		if (operationType == ADD_RSP_TYPE || operationType == MOV_RSP_RBP_TYPE)
		{
			epilogueStartOffset = (ULONG_PTR)scanFunction - (ULONG_PTR)target;
			bEpilogueReached = TRUE;
		}

		if (operationType == NOT_STACK_OPERATION && !bIsInPrologue)
		{
			if (safeInstructionsSize >= safeInstructionOffsetsMaxSize - 1)
			{
				ReallocMemory<SAFE_INSTRUCTION>(&safeInstructions, safeInstructionOffsetsMaxSize, 2);
			}
			safeInstructions[safeInstructionsSize].SafeInstructionOffset = (ULONG_PTR)scanFunction - (ULONG_PTR)target;
			safeInstructions[safeInstructionsSize++].SafeInstructionLength = instruction->length;
		}


		scanFunction = (PVOID)((ULONG_PTR)scanFunction + instruction->length);
	}

	ShrinkMemoryZeroes<SAFE_INSTRUCTION>(&safeInstructions, safeInstructionsSize);

	functionInfo.PrologueEndOffset = prologueEndOffset;
	functionInfo.EpilogueStartOffset = epilogueStartOffset;
	functionInfo.SafeInstuctions = safeInstructions;
	functionInfo.SafeInstructionsSize = safeInstructionsSize;

	return functionInfo;
}
```

And now its testing time!

```cpp
int main()
{
	ULONG_PTR scanFunc = (ULONG_PTR)Foo;

	FUNCTION_INFO fi = ScanFunction((PVOID)scanFunc);

	ULONG_PTR prologueEndOffset = fi.PrologueEndOffset;
	ULONG_PTR epilogueStartOffset = fi.EpilogueStartOffset;
	PSAFE_INSTRUCTION safeInstructions = fi.SafeInstuctions;
	ULONG64 safeInstructionsSize = fi.SafeInstructionsSize;

	printf("[+] Original function info: \n\n");
	printf("[+] Function address: %p\n", Foo);
	printf("[+] Prologue end address: %p\n", prologueEndOffset);
	printf("[+] Epilogue start address: %p\n", epilogueStartOffset);
	printf("[+] Safe instructions(found %d): \n", safeInstructionsSize);
	for (ULONG64 i = 0; i < safeInstructionsSize; i++)
	{
		SAFE_INSTRUCTION instruction = safeInstructions[i];
		printf("\t[+] Safe instruction #%d address: %p, length: %d\n", i, instruction.SafeInstructionOffset, instruction.SafeInstructionLength);
	}
	printf("\t[+] Total safe instructions length: %d\n", fi.CalculateTotalSafeInstructionsLength());

	ULONG64 originalReturnValue = Foo();
	printf("\n[+] Original function return value: %d\n", originalReturnValue);

	const BYTE MOV_RAX_1[7] = { 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00 };
	const BYTE NOP[13] = { 0 };
	const BYTE SHELL_CODE[20] = { 0 };

	memset((PVOID)NOP, 0x90, sizeof(NOP));
	memset((PVOID)SHELL_CODE, 0, sizeof(SHELL_CODE));

	memcpy((PVOID)SHELL_CODE, (PVOID)MOV_RAX_1, sizeof(MOV_RAX_1));
	memcpy((PVOID)((ULONG_PTR)SHELL_CODE + sizeof(MOV_RAX_1)), (PVOID)NOP, sizeof(NOP));

	DWORD oldProtect;
	VirtualProtect((PVOID)((ULONG_PTR)Foo + prologueEndOffset), sizeof(SHELL_CODE), PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy((PVOID)((ULONG_PTR)Foo + prologueEndOffset), SHELL_CODE, sizeof(SHELL_CODE));
	VirtualProtect((PVOID)((ULONG_PTR)Foo + prologueEndOffset), sizeof(SHELL_CODE), oldProtect, &oldProtect);
	
    printf("\n-----------------------------------------------------------------------\n\n");

	printf("\n[+] Hooked function info: \n\n");

	ULONG_PTR scanHookFunc = (ULONG_PTR)Foo;

	FUNCTION_INFO hfi = ScanFunction((PVOID)scanHookFunc);

	ULONG_PTR hPrologueEndOffset = hfi.PrologueEndOffset;
	ULONG_PTR hEpilogueStartOffset = hfi.EpilogueStartOffset;
	PSAFE_INSTRUCTION hSafeInstructions = hfi.SafeInstuctions;
	ULONG64 hSafeInstructionsSize = hfi.SafeInstructionsSize;

	printf("[+] Function address: %p\n", Foo);
	printf("[+] Prologue end address: %p\n", hPrologueEndOffset);
	printf("[+] Epilogue start address: %p\n", hEpilogueStartOffset);
	printf("[+] Safe instructions(found %d): \n", hSafeInstructionsSize);
	for (ULONG64 i = 0; i < hSafeInstructionsSize; i++)
	{
		SAFE_INSTRUCTION instruction = hSafeInstructions[i];
		printf("\t[+] Safe instruction #%d address: %p, length: %d\n", i, instruction.SafeInstructionOffset, instruction.SafeInstructionLength);
	}
	printf("\t[+] Total safe instructions length: %d\n", hfi.CalculateTotalSafeInstructionsLength());

	ULONG64 hookedReturnValue = Foo();
	printf("\n[+] Hooked function return value: %d", hookedReturnValue);

	return NULL;
}
```

Our assembly code returns rax after a few operations (rax = 1, rbx = 8; rbx = rbx - rax; rax = rbx) 
which means it returns 7 when not hooked.

our goal is to replace `mov rax, 1h` with the same `mov rax, 1h` but instructions ahead will be `nop`'ed so the Foo procedure will return 1

and here is our output:
```text
[+] Original function info:

[+] Function address: 00007FF793581360
[+] Prologue end address: 0000000000000008
[+] Epilogue start address: 000000000000001C
[+] Safe instructions(found 4):
        [+] Safe instruction #0 address: 0000000000000008, length: 7
        [+] Safe instruction #1 address: 000000000000000F, length: 7
        [+] Safe instruction #2 address: 0000000000000016, length: 3
        [+] Safe instruction #3 address: 0000000000000019, length: 3
        [+] Total safe instructions length: 20

[+] Original function return value: 7

-----------------------------------------------------------------------

[+] Hooked function info:

[+] Function address: 00007FF793581360
[+] Prologue end address: 0000000000000008
[+] Epilogue start address: 000000000000001C
[+] Safe instructions(found 14):
        [+] Safe instruction #0 address: 0000000000000008, length: 7
        [+] Safe instruction #1 address: 000000000000000F, length: 1
        [+] Safe instruction #2 address: 0000000000000010, length: 1
        [+] Safe instruction #3 address: 0000000000000011, length: 1
        [+] Safe instruction #4 address: 0000000000000012, length: 1
        [+] Safe instruction #5 address: 0000000000000013, length: 1
        [+] Safe instruction #6 address: 0000000000000014, length: 1
        [+] Safe instruction #7 address: 0000000000000015, length: 1
        [+] Safe instruction #8 address: 0000000000000016, length: 1
        [+] Safe instruction #9 address: 0000000000000017, length: 1
        [+] Safe instruction #10 address: 0000000000000018, length: 1
        [+] Safe instruction #11 address: 0000000000000019, length: 1
        [+] Safe instruction #12 address: 000000000000001A, length: 1
        [+] Safe instruction #13 address: 000000000000001B, length: 1
        [+] Total safe instructions length: 20

[+] Hooked function return value: 1
```

For better security and detection avoiding we should randomize our hook, and this code will help us create bounds for our hook, so we can just pick random place between offset `08` and `1c` to insert our hook, 
also we can randomize hooking by picking random technique: mov rax, call rax; push rax, ret; call [rip + 0x0]

## Advanced hooking. Code Caves (Second method)

WIP