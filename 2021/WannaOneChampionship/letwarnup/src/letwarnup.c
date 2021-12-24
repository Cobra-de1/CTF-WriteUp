// gcc -no-pie -fstack-protector -m64 -o letwarnup letwarnup.c
#include <stdio.h>
#include <stdlib.h>

void vuln() {    
    char* buf = malloc(0x60);
    printf("Enter your string:\n");
    fgets(buf, 0x60, stdin);
    printf(buf);
    exit(0);    
}

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    vuln();
    return 0;
}
