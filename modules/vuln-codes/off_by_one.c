/*
 * vuln-03: Off-By-One Stack Buffer Overflow
 * Vulnerability: loop runs <= size instead of < size, writing one byte past buf.
 * Impact: On x86-64, overwrites the low byte of saved RBP → frame pointer hijack.
 * Compile: gcc -o off_by_one off_by_one.c -fno-stack-protector -no-pie
 * Trigger: ./off_by_one $(python3 -c "print('A'*65)")
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vuln(char *input) {
    char buf[64];
    int i;
    for (i = 0; i <= 64; i++) {  /* VULN: should be i < 64           */
        buf[i] = input[i];
        if (input[i] == '\0') break;
    }
    printf("buf = %s\n", buf);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { printf("Usage: %s <input>\n", argv[0]); return 1; }
    vuln(argv[1]);
    return 0;
}
