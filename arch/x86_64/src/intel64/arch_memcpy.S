/************************************************************************************
 * Public Symbols
 ************************************************************************************/

	.file		"arch_memcpy.S"

/************************************************************************************
 * .text
 ************************************************************************************/


/************************************************************************************
 * Public Functions
 ************************************************************************************/
/************************************************************************************
 * Name: memcpy
 *
 * Description:
 *   Optimized "general" copy routine
 *
 * Input Parameters:
 *   rdi = destination, rsi = source, rdx = length
 *
 * Returned Value:
 *   rax = destination
 *
 ************************************************************************************/

    .text
    .align 4

    .global memcpy
    .type   memcpy, @function
memcpy:
    push    %rbp
    movq    %rsp, %rbp

    movq    %rdx, %rcx
    and     $0xfffffffffffffff8, %rcx
    sub     %rcx, %rdx

    cld
    rep movsq

    movq    %rdx, %rcx
    
    rep movsb

    leaveq
    retq
    .size	memcpy, .-memcpy
    .end
