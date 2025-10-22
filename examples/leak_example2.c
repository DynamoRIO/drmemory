#include <stdlib.h>
#include <stdio.h>

/* leak_example2.c
 * Intentional small memory leak for Dr. Memory demos
 */

int main(void) {
    int *p = malloc(5 * sizeof(int));  // intentionally not freed
    if (!p) return 1;
    p[0] = 42;  // use the memory so it's not optimized away
    printf("Leak example 2\n");
    return 0;
}
