.code
	SysNtCreateSection10 proc
			mov r10, rcx
			mov eax, 4Ah
			syscall
			ret
	SysNtCreateSection10 endp

	SysNtCreateProcessEx10 proc
			mov r10, rcx
			mov eax, 4Dh
			syscall
			ret
	SysNtCreateProcessEx10 endp

	SysNtCreateThreadEx10 proc
			mov r10, rcx
			mov eax, 0C1h
			syscall
			ret
	SysNtCreateThreadEx10 endp

	SysNtQueryInformationProcess10 proc
			mov r10, rcx
			mov eax, 19h
			syscall
			ret
	SysNtQueryInformationProcess10 endp

	SysNtReadVirtualMemory10 proc
			mov r10, rcx
			mov eax, 3Fh
			syscall
			ret
	SysNtReadVirtualMemory10 endp

	SysNtCreateTransaction10 proc
			mov r10, rcx
			mov eax, 0C6h
			syscall
			ret
	SysNtCreateTransaction10 endp

	SysNtCreateFile10 proc
			mov r10, rcx
			mov eax, 55h
			syscall
			ret
	SysNtCreateFile10 endp

	SysNtOpenProcess10 proc
			mov r10, rcx
			mov eax, 26h
			syscall
			ret
	SysNtOpenProcess10 endp

	SysNtWriteVirtualMemory10 proc
			mov r10, rcx
			mov eax, 3Ah
			syscall
			ret
	SysNtWriteVirtualMemory10 endp

	SysNtAllocateVirtualMemory10 proc
			mov r10, rcx
			mov eax, 18h
			syscall
			ret
	SysNtAllocateVirtualMemory10 endp

	SysNtWriteFile10 proc
			mov r10, rcx
			mov eax, 08h
			syscall
			ret
	SysNtWriteFile10 endp
end