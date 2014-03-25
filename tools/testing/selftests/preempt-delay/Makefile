all:
	gcc -pthread preempt-delay.c -o preempt-delay -lrt

run_tests: all
	./preempt-delay 300 400

clean:
	rm -f ./preempt-delay
