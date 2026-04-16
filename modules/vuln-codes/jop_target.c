/*
 * vuln-07: JOP-Rich Target
 * Designed to maximise indirect jmp/call gadgets for JOPBench testing.
 * Vulnerability: memcpy with attacker-controlled length.
 * Impact: Stack overflow → hijack dispatcher register → JOP chain.
 * Compile: gcc -o jop_target jop_target.c -fno-stack-protector -no-pie -O0
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* function table — indirect calls through pointer array (JOP gadgets) */
typedef void (*handler_t)(char *);

void do_upper(char *s) { for(; *s; s++) if(*s>='a'&&*s<='z') *s-=32; }
void do_lower(char *s) { for(; *s; s++) if(*s>='A'&&*s<='Z') *s+=32; }
void do_print(char *s) { printf(">> %s\n", s); }
void do_shell(char *s) { printf("[!] shell\n"); system("/bin/sh"); }

handler_t dispatch[] = { do_upper, do_lower, do_print, do_shell };

void vuln(char *data, int len) {
    char buf[128];
    memcpy(buf, data, len);    /* VULN: len is attacker-controlled   */
    buf[127] = '\0';

    /* indirect call through table — JOP dispatcher pattern */
    int idx = buf[0] % 3;      /* attacker influences idx via buf[0] */
    dispatch[idx](buf + 1);    /* indirect call — core JOP gadget    */
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <data> <len>\n", argv[0]);
        printf("dispatch table @ %p\n", (void *)dispatch);
        return 1;
    }
    int len = atoi(argv[2]);
    printf("dispatch[] @ %p\n", (void *)dispatch);
    printf("do_shell() @ %p\n", (void *)do_shell);
    vuln(argv[1], len);
    return 0;
}
