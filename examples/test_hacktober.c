#include <stdlib.h>
#include <stdio.h>

int main() {
    int *leak = malloc(sizeof(int) * 5); // intentional memory leak
    int *arr = malloc(sizeof(int) * 10);
    free(arr);  // properly freed
    printf("Hello Hacktoberfest!\n");
    return 0;
}
