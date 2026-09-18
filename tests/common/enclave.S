/* Test-only position independent enclave. Never use for secrets.
 * op 1: return all arguments folded into two registers.
 * op 2: one usercall, op 3: panic, op 4: #UD, op 5: three usercalls.
 * TCS +0, SSA +4096, code +8192, scratch +12288.
 */
.pushsection .rodata
.balign 16
.global test_enclave_start
.global test_enclave_end
test_enclave_start:
    mov rbx, rcx
    lea r11, [rip + test_enclave_start]
    add r11, 4096
    test rdi, rdi
    jz .Lresume
    cmp rdi, 2
    je .Lusercall
    cmp rdi, 3
    je .Lpanic
    cmp rdi, 4
    je .Lfault
    cmp rdi, 5
    je .Lmultiple
    add rsi, r8
    add rdx, r9
    xor edi, edi
    jmp .Lexit
.Lusercall:
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, r8
    mov r8, r9
    xor r9d, r9d
    jmp .Lexit
.Lpanic:
    mov word ptr [r10], 0x0058
    mov edi, {exit_usercall}
    mov esi, 1
    jmp .Lexit
.Lfault:
    ud2
.Lmultiple:
    mov qword ptr [r11], 3
    mov qword ptr [r11 + 8], 0
.Lnext:
    mov edi, 0x80000001
    mov rsi, [r11]
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    jmp .Lexit
.Lresume:
    cmp qword ptr [r11], 0
    je .Lexit
    add [r11 + 8], rsi
    dec qword ptr [r11]
    jnz .Lnext
    mov rsi, [r11 + 8]
    xor edi, edi
.Lexit:
    mov eax, 4
    enclu
    ud2
test_enclave_end:
.popsection
