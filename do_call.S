global do_call
section .text

do_call:
    ; Simplified version for CreateThread (6 parameters)
    ; Input: rcx=funcaddr, rdx=nargs, r8=arg0, r9=arg1, [rsp+40]=arg2, [rsp+48]=arg3, [rsp+56]=arg4, [rsp+64]=arg5
    ; Output: call funcaddr(arg0, arg1, arg2, arg3, arg4, arg5)
    
    ; Save function address
    mov rax, rcx
    
    ; Allocate shadow space (32 bytes) + space for 2 extra args (16 bytes) = 48 bytes
    sub rsp, 48
    
    ; Load arguments from stack to temporary locations
    mov r10, [rsp + 48 + 40]  ; arg2 (original rsp + 40)
    mov r11, [rsp + 48 + 48]  ; arg3 (original rsp + 48) 
    
    ; Set up function arguments
    mov rcx, r8         ; arg0 -> rcx
    mov rdx, r9         ; arg1 -> rdx
    mov r8, r10         ; arg2 -> r8
    mov r9, r11         ; arg3 -> r9
    
    ; Put arg4 and arg5 on stack (after shadow space)
    mov r10, [rsp + 48 + 56]  ; arg4
    mov [rsp + 32], r10       ; Store arg4 at shadow space + 0
    
    mov r10, [rsp + 48 + 64]  ; arg5  
    mov [rsp + 40], r10       ; Store arg5 at shadow space + 8
    
    ; Call the function
    call rax
    
    ; Restore stack
    add rsp, 48
    
    ret 
    