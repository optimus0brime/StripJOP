#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *gets(char *s); /* for lab/test only — gets is removed from modern standards */

void secret() {
    printf("[!] secret() called — shell spawned\n");
    system("/bin/sh");
}

void vuln() {
    char buf[64];
    printf("Input: ");
    gets(buf);              /* VULN: no bounds check, no limit */
    printf("You said: %s\n", buf);
}

int main() {
    printf("=== Stack BOF Demo ===\n");
    printf("secret() @ %p\n", (void *)secret);
    vuln();
    return 0;
}
