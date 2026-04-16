/*
 * vuln-06: ret2libc target
 * Vulnerability: scanf into fixed buffer, no stack canary.
 * Classic target for ret2libc: overflow → overwrite RIP with system()
 * using a "/bin/sh" string already present in libc.
 * Compile: gcc -o ret2libc ret2libc.c -fno-stack-protector -no-pie
 * Attack:  find gadgets with: ROPgadget --binary ret2libc
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>   /* for execve() */


/* hint: these symbols stay in the binary, useful for ROP chain building */
void hints() {
    system("");         /* pulls system() into PLT                  */
    execve("", 0, 0);  /* pulls execve() into PLT                  */
}

void vuln() {
    char buf[64];
    printf("Input (no limit): ");
    scanf("%s", buf);   /* VULN: %s reads until whitespace, no limit */
    printf("Got: %s\n", buf);
}

int main() {
    printf("=== ret2libc Demo ===\n");
    vuln();
    return 0;
}
