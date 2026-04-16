/*
 * vuln-04: Heap Buffer Overflow
 * Vulnerability: strcpy into a heap chunk smaller than the input.
 * Impact: Corrupt adjacent heap metadata / function pointers.
 * Compile: gcc -o heap_bof heap_bof.c
 * Trigger: ./heap_bof $(python3 -c "print('A'*200)")
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];          /* 32-byte heap buffer                  */
    void (*fp)();           /* function pointer in adjacent chunk   */
} Record;

void normal() { printf("[ ] normal()\n"); }
void shell()  { printf("[!] shell()!\n"); system("/bin/sh"); }

int main(int argc, char *argv[]) {
    if (argc < 2) { printf("Usage: %s <input>\n", argv[0]); return 1; }

    Record *r = malloc(sizeof(Record));
    r->fp = normal;

    printf("normal() @ %p\n", (void *)normal);
    printf("shell()  @ %p\n", (void *)shell);

    strcpy(r->name, argv[1]);   /* VULN: overflows into r->fp        */

    printf("Calling fp...\n");
    r->fp();                    /* if fp was overwritten → shell()   */

    free(r);
    return 0;
}
