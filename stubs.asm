.code

EXTERN SyscallNum: PROC

EXTERN GetNTDLLFunc: PROC

MyNtCreateSection PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00805225dh
	call GetNTDLLFunc
	mov r15, rax
	mov ecx, 00805225dh
	call SyscallNum
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15
MyNtCreateSection ENDP

MyNtCreateProcessEx PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 007d59987h
	call GetNTDLLFunc
	mov r15, rax
	mov ecx, 007d59987h
	call SyscallNum
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15
MyNtCreateProcessEx ENDP

MyNtCreateFile PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 005bc6255h
	call GetNTDLLFunc
	mov r15, rax
	mov ecx, 005bc6255h
	call SyscallNum
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15
MyNtCreateFile ENDP

MyNtAllocateVirtualMemory PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0077d1149h
	call GetNTDLLFunc
	mov r15, rax
	mov ecx, 0077d1149h
	call SyscallNum
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15
MyNtAllocateVirtualMemory ENDP

MyNtReadVirtualMemory PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 006bc8205h
	call GetNTDLLFunc
	mov r15, rax
	mov ecx, 006bc8205h
	call SyscallNum
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15
MyNtReadVirtualMemory ENDP

MyNtFreeVirtualMemory PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0051f1149h
	call GetNTDLLFunc
	mov r15, rax
	mov ecx, 0051f1149h
	call SyscallNum
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15
MyNtFreeVirtualMemory ENDP

MyNtTerminateProcess PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0070e4ee3h
	call GetNTDLLFunc
	mov r15, rax
	mov ecx, 0070e4ee3h
	call SyscallNum
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15
MyNtTerminateProcess ENDP

MyNtProtectVirtualMemory PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0094cbf49h
	call GetNTDLLFunc
	mov r15, rax
	mov ecx, 0094cbf49h
	call SyscallNum
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15
MyNtProtectVirtualMemory ENDP

MyNtMapViewOfSection PROC
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 005bd8999h
	call GetNTDLLFunc
	mov r15, rax
	mov ecx, 005bd8999h
	call SyscallNum
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15
MyNtMapViewOfSection ENDP

end
