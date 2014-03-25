/*
 * This test program checks for the presence of preemption delay feature
 * in the kernel. If the feature is present, it exercises it by running
 * a number of threads that ask for preemption delay and checks if they
 * are granted these preemption delays. It then runs the threads again
 * without requesting preemption delays and verifies preemption delays
 * are not granted when not requested (negative test).
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define NUMTHREADS	1000

pthread_mutex_t		mylock = PTHREAD_MUTEX_INITIALIZER;
unsigned long		iterations;
unsigned long		delays_granted = 0;
unsigned long		request_delay = 1;

#define BUFSIZE		1024

int
feature_check()
{
	unsigned char buf[BUFSIZE];

	sprintf(buf, "/proc/%d/task/%ld/sched_preempt_delay",
					getpid(), syscall(SYS_gettid));
	if (access(buf, F_OK))
		return 1;
	return 0;
}

void
do_some_work(void *param)
{
	struct timespec timeout;
	int i, j, tid, fd, fsz;
	unsigned long sum;
	unsigned char buf[BUFSIZE];
	unsigned char delay[4];
	int cnt = 0;

	/*
	 * mmap the sched_preempt_delay file
	 */
	sprintf(buf, "/proc/%d/task/%ld/sched_preempt_delay",
					getpid(), syscall(SYS_gettid));
	fd = open(buf, O_RDWR);
	if (fd == -1) {
		perror("Error opening sched_preemp_delay file");
		return;
	}

	for (i = 0; i < 4; i++)
		delay[i] = 0;

	if (request_delay) {
		*(unsigned int **)buf = (unsigned int *) &delay;
		if (write(fd, buf, sizeof(unsigned int *)) < 0) {
			perror("Error writing flag address");
			close(fd);
			return;
		}
	}

	tid = *(int *) param;

	for (i = 0; i < iterations; i++) {
		/* start by locking the resource */
		if (request_delay)
			delay[0] = 1;
		if (pthread_mutex_lock(&mylock)) {
			perror("mutex_lock():");
			delay[0] = 0;
			return;
		}

		/* Do some busy work */
		sum = 0;
		for (j = 0; j < (iterations*(tid+1)); j++)
			sum += sum;
		for (j = 0; j < iterations/(tid+1); j++)
			sum += i^2;

		/* Now unlock the resource */
		if (pthread_mutex_unlock(&mylock)) {
			perror("mutex_unlock():");
			delay[0] = 0;
			return;
		}
		delay[0] = 0;

		if (delay[1]) {
			delay[1] = 0;
			cnt++;
			sched_yield();
		}
	}

	if (request_delay) {
		*(unsigned int **)buf = 0;
		if (write(fd, buf, sizeof(unsigned int *)) < 0) {
			perror("Error clearing flag address");
			close(fd);
			return;
		}
	}
	close(fd);

	/*
	 * Update global count of delays granted. Need to grab a lock
	 * since this is a global.
	 */
	if (pthread_mutex_lock(&mylock)) {
		perror("mutex_lock():");
		delay[0] = 0;
		return;
	}
	delays_granted += cnt;
	if (pthread_mutex_unlock(&mylock)) {
		perror("mutex_unlock():");
		delay[0] = 0;
		return;
	}
}

void
help(char *progname)
{
	fprintf(stderr, "Usage: %s <number of threads> ", progname);
	fprintf(stderr, "<number of iterations>\n");
	fprintf(stderr, "   Notes: (1) Maximum number of threads is %d\n",
								NUMTHREADS);
	fprintf(stderr, "          (2) Suggested number of iterations is ");
	fprintf(stderr, "300-10000\n");
	fprintf(stderr, "          (3) Exit codes are: 1 = Failed with no ");
	fprintf(stderr, "preemption delays granted\n");
	fprintf(stderr, "                              2 = Failed with ");
	fprintf(stderr, "preemption delays granted when\n");
	fprintf(stderr, "                                  not requested\n");
	fprintf(stderr, "                              3 = Error in test ");
	fprintf(stderr, "arguments\n");
	fprintf(stderr, "                              4 = Other errors\n");
}

int main(int argc, char **argv)
{
	pthread_t	thread[NUMTHREADS];
	int		ret, i, tid[NUMTHREADS];
	unsigned long	nthreads;

	/* check arguments */
	if (argc < 3) {
		help(argv[0]);
		exit(3);
	}

	nthreads = atoi(argv[1]);
	iterations = atoi(argv[2]);
	if (nthreads > NUMTHREADS) {
		fprintf(stderr, "ERROR: exceeded maximum number of threads\n");
		exit(3);
	}

	/*
	 * Check for the presence of feature
	 */
	if (feature_check()) {
		printf("INFO: Pre-emption delay feature is not present in ");
		printf("this kernel\n");
		exit(0);
	}

	/*
	 * Create a bunch of threads that will compete for the
	 * same mutex. Run these threads first while requesting
	 * preemption delay.
	 */
	for (i = 0; i < nthreads; i++) {
		tid[i] = i;
		ret = pthread_create(&thread[i], NULL, (void *)&do_some_work,
				&tid[i]);
		if (ret) {
			perror("pthread_create(): ");
			exit(4);
		}
	}

	printf("Threads started. Waiting......\n");
	/* Now wait for threads to get done */
	for (i = 0; i < nthreads; i++) {
		ret = pthread_join(thread[i], NULL);
		if (ret) {
			perror("pthread_join(): ");
			exit(4);
		}
	}

	/*
	 * We started out with requesting pre-emption delays, check if
	 * we got at least a few.
	 */
	if (delays_granted == 0) {
		fprintf(stderr, "FAIL: No delays granted at all.\n");
		exit(1);
	}

	/*
	 * Run the threads again, this time not requesting preemption delays
	 */
	request_delay = 0;
	delays_granted = 0;
	for (i = 0; i < nthreads; i++) {
		tid[i] = i;
		ret = pthread_create(&thread[i], NULL, (void *)&do_some_work,
				&tid[i]);
		if (ret) {
			perror("pthread_create(): ");
			exit(4);
		}
	}

	printf("Threads started. Waiting......\n");
	/* Now wait for threads to get done */
	for (i = 0; i < nthreads; i++) {
		ret = pthread_join(thread[i], NULL);
		if (ret) {
			perror("pthread_join(): ");
			exit(4);
		}
	}

	/*
	 * Check if preemption delays were granted even though we
	 * did not ask for them
	 */
	if (delays_granted > 0) {
		fprintf(stderr, "FAIL: delays granted when not requested.\n");
		exit(2);
	}
}
