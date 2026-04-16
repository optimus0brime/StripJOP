/*
 * vuln-05: Format String + Stack Buffer Overflow
 * Vulnerability 1: printf(buf) — format string, leaks stack/heap addresses.
 * Vulnerability 2: read() into stack buf without null-termination.
 * Impact: Use fmt-string to leak canary/addresses, then BOF to hijack RIP.
 * Compile: gcc -o format_bof format_bof.c -fno-stack-protector -no-pie
 * Trigger (leak): printf "%p %p %p %p %p %p" | ./format_bof
 */
#include <stdlib.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win() {
    printf("[!] win() — got shell\n");
    system("/bin/sh");
}

void vuln() {
    char buf[128];
    int n;

    printf("Enter format string: ");
    fflush(stdout);
    n = read(0, buf, 256);      /* VULN 1: reads 256 into 128-byte buf */
    buf[n-1] = '\0';

    printf("Echo: ");
    printf(buf);                /* VULN 2: user-controlled format string */
    printf("\n");
}

int main() {
    printf("win() @ %p\n", (void *)win);
    vuln();
    return 0;
}
