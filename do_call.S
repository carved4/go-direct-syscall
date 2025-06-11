global do_call
section .text

do_call:
    mov rax, rcx
    
    sub rsp, 48
    
  
    mov r10, [rsp + 48 + 40]  ; arg2 (original rsp + 40)
    mov r11, [rsp + 48 + 48]  ; arg3 (original rsp + 48) 
    
    
    mov rcx, r8         ; arg0 -> rcx
    mov rdx, r9         ; arg1 -> rdx
    mov r8, r10         ; arg2 -> r8
    mov r9, r11         ; arg3 -> r9
    
   
    mov r10, [rsp + 48 + 56]  ; arg4
    mov [rsp + 32], r10       ; Store arg4 at shadow space + 0
    
    mov r10, [rsp + 48 + 64]  ; arg5  
    mov [rsp + 40], r10       ; Store arg5 at shadow space + 8
    
  
    call rax
    

    add rsp, 48
    
    ret 
    