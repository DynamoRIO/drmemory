#include <stdlib.h>
#include <stdio.h>

#define SIGNAL_SIZE 1000

int main() {
    printf("Running signal_buffer_leak...\n");
    float *signal = (float *)malloc(SIGNAL_SIZE * sizeof(float));

    for (int i = 0; i < SIGNAL_SIZE; i++)
        signal[i] = i * 0.01f;

    printf("Signal processed.\n");

    return 0;
}
