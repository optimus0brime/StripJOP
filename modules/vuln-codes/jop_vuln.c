#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

/* 
 * JOP test binary — intentionally packed with 250 short JOP gadgets
 * in .text so the jop-detector script (static JOP-alarm via Capstone)
 * will detect Gadgets >> 0 and Score > 120 → ALERT: Yes
 *
 * Each gadget pattern:   pop %rax ; jmp *%rbx
 * → 2-instruction functional gadget ending in indirect jump.
 * .rept unrolls them at assembly time → lots of gadgets in the binary.
 *
 * The gadgets are placed in a never-executed function (via volatile pointer)
 * so the process stays alive for the detector to attach and scan .text.
 */

void __attribute__((used, noinline)) insert_jop_gadgets(void) {
    __asm__ volatile (
        ".rept 250\n\t"          /* 250 gadgets — way over threshold */
        "pop %%rax\n\t"
        "jmp *%%rbx\n\t"
        ".endr\n\t"
        ::: "rax", "rbx"
    );
}

int main(void) {
    /* Force the compiler to emit the gadget function even though we never call it */
    void (*volatile gadget_ptr)(void) = insert_jop_gadgets;

    printf("╔════════════════════════════════════════════╗\n");
    printf("║          JOP-VULN TEST BINARY              ║\n");
    printf("║  (250 artificial short JOP gadgets in .text)║\n");
    printf("╚════════════════════════════════════════════╝\n");
    printf("PID: %d\n", getpid());
    printf("This binary is designed to trigger the JOP-alarm detector.\n");
    printf("Run the detector now → it should show high gadget count + ALERT!\n\n");

    /* Keep the process alive forever so ptrace can attach */
    while (1) {
        sleep(1);
    }

    return 0; /* unreachable */
}
