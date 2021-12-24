// gcc fsop.c -o fsop
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <signal.h>
#include <time.h>
#include <stddef.h>
#include <string.h>

#define max_length 8
#define max_size 0x600

char* note[max_length];
size_t length[max_length];

void read_array(char* a, size_t b) {
    int t = read(0, a, b);
    if (t <= 0) {
        exit(-1);
    }
    a[b] = 0;
}

void create_note() {
    printf("Index: ");
    unsigned int i;
    scanf("%u", &i);
    printf("Size: ");
    size_t size;
    scanf("%zu", &size);
    if (i >= max_length || size > max_size) {
        exit(-1);
    }
    note[i] = malloc(size);
    length[i] = size;
    printf("Data: ");
    read_array(note[i], size);
}

void delete_note() {
    printf("What index you want to delete: ");
    unsigned int i;
    scanf("%u", &i);
    if (i < max_length && note[i]) {
        free(note[i]);
        note[i] = 0;
    }
}

void timeout() {
    puts("Sorry, timeout!!!");
    exit(0);
}

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    ssignal(14, timeout);
    alarm(60);
    int* p = malloc(0x10);
    printf("I have a gift for you: %p\n", p);
}

void menu() {
    puts("Welcome to my note");
    puts("1. Create Note");
    puts("2. Delete Note");
    puts("3. Exit");
    printf("> ");
}

int main() {
    setup();
    while (1) {
        menu();
        int i;
        scanf("%d", &i);
        if (i == 1) {
            create_note();
        } else if (i == 2) {
            delete_note();
        } else if (i == 3) {
            break;
        }else {
            puts("Invalid choice");
        }
    }
    exit(0);
}