/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
 * Copyright (c) 2009 VMware, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* **********************************************************
 * Copyright (c) 2003 VMware, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Largely identical to DynamoRIO's pthreads test */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

volatile double pi = 0.0;  /* Approximation to pi (shared) */
pthread_mutex_t pi_lock;   /* Lock for above */
volatile double intervals; /* How many intervals? */

void *
process(void *arg)
{
    register double width, localsum;
    register intptr_t i;
    register intptr_t iproc;

    /* Ensure new thread stacks are marked unaddr beyond TOS, but only for
     * threads we know will get here, to avoid flakiness.
     */
    if ((intptr_t)arg < 2) {
        int buf[4];
        i = 0;
        i = buf[i - 64];
    }

#if VERBOSE
    fprintf(stderr, "\tthread %d starting\n", id);
#endif
    iproc = (intptr_t) arg;

    /* Set width */
    width = 1.0 / intervals;

    /* Do the local computations */
    localsum = 0;
    for (i=iproc; i<intervals; i+=2) {
	register double x = (i + 0.5) * width;
	localsum += 4.0 / (1.0 + x * x);
        /* Make a system call to trigger DR operations that might
         * crash in a race (PR 470957)
         */
        sigprocmask(SIG_BLOCK, NULL, NULL);
    }
    localsum *= width;

    /* Lock pi for update, update it, and unlock */
    pthread_mutex_lock(&pi_lock);
    pi += localsum;
    pthread_mutex_unlock(&pi_lock);

#if VERBOSE
    fprintf(stderr, "\tthread %d exiting\n", id);
#endif
    return(NULL);
}

#define NUM_THREADS 10

void
test_join(const char *app)
{
    pthread_t thread0, thread1;
    void * retval;

    intervals = 10;

    /* Initialize the lock on pi */
    pthread_mutex_init(&pi_lock, NULL);

    /* Make the two threads */
    if (pthread_create(&thread0, NULL, process, (void *)(intptr_t)0) ||
	pthread_create(&thread1, NULL, process, (void *)(intptr_t)1)) {
	fprintf(stderr, "%s: cannot make thread\n", app);
	exit(1);
    }

    /* Join (collapse) the two threads */
    if (pthread_join(thread0, &retval) ||
	pthread_join(thread1, &retval)) {
	fprintf(stderr, "%s: thread join failed\n", app);
	exit(1);
    }

    /* Print the result */
    printf("Estimation of pi is %16.15f\n", pi);
}

int
main(int argc, char **argv)
{
    pthread_t thread[NUM_THREADS];
    int i;

    test_join(argv[0]);

    /* now make a lot of threads and then just exit while they're still
     * running to test exit races (PR 470957)
     */
    intervals = 10000000;
    for (i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&thread[i], NULL, process, (void *)(intptr_t)(i+2))) {
            fprintf(stderr, "%s: cannot make thread\n", argv[0]);
            exit(1);
        }
    }

    return 0;
}
