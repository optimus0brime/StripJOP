/*
 * vuln-02: strcpy Stack Buffer Overflow
 * Vulnerability: strcpy() copies argv[1] into a 32-byte buffer without limit.
 * Impact: Stack smash → overwrite return address.
 * Compile: gcc -o strcpy_bof strcpy_bof.c -fno-stack-protector -no-pie
 * Trigger: ./strcpy_bof $(python3 -c "print('A'*200)")
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win() {
    printf("[!] win() reached!\n");
    system("/bin/sh");
}

void vuln(char *input) {
    char buf[32];           /* only 32 bytes on stack               */
    strcpy(buf, input);     /* VULN: copies without length check     */
    printf("buf = %s\n", buf);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    printf("win() @ %p\n", (void *)win);
    vuln(argv[1]);
    return 0;
}
