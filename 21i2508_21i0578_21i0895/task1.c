#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <stdbool.h>

#define MAX_LINE_LENGTH 1024
#define MAX_IP_LENGTH 64
#define MAX_SUSPICIOUS_IPS 1000


typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char proto[16];
    char service[64];
    double duration;
    long orig_bytes;
    long resp_bytes;
    char conn_state[16];
    int local_orig;
    long missed_bytes;
    char history[64];
    long orig_pkts;
    long orig_ip_bytes;
    long resp_pkts;
    long resp_ip_bytes;
    char tunnel_parents[128];
} ConnLog;

typedef struct {
    int fuzzers;
    int analysis;
    int backdoors;
    int dos;
    int exploits;
    int generic;
    int reconnaissance;
    int shellcode;
    int worms;
} SuspiciousActivity;

void parse_conn_log(char *line, ConnLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %15s %63s %lf %ld %ld %15s %d %ld %63s %ld %ld %ld %ld %127s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->proto,
           entry->service, &entry->duration, &entry->orig_bytes, &entry->resp_bytes, entry->conn_state,
           &entry->local_orig, &entry->missed_bytes, entry->history, &entry->orig_pkts, &entry->orig_ip_bytes,
           &entry->resp_pkts, &entry->resp_ip_bytes, entry->tunnel_parents);
}

/*
### Detection Functions for Analyzing Activities

1. **Fuzzers**:
   - Detect unusual or malformed requests.
   - Example: High source or destination port numbers.
   - Detection Logic: If the source port (orig_p) or destination port (resp_p) is greater than 50000, it is considered a fuzzer.

2. **Analysis**:
   - Detect requests to known analysis tools or services.
   - Example: Specific services or ports associated with analysis tools.
   - Detection Logic: If the service is "http" and the destination port (resp_p) is 80, it is considered an analysis request.

3. **Backdoors**:
   - Detect connections to unusual ports or IPs.
   - Example: Connections to high or uncommon ports.
   - Detection Logic: If the destination port (resp_p) is 5555, it is considered a backdoor connection.

4. **DoS**:
   - Detect high volume of requests in a short period.
   - Example: High orig_bytes or resp_bytes in a short duration.
   - Detection Logic: If the duration (duration) is less than 1.0 and the original bytes (orig_bytes) are greater than 10000, it is considered a DoS attack.

5. **Exploits**:
   - Detect known exploit signatures.
   - Example: Specific conn_state values or unusual proto values.
   - Detection Logic: If the connection state (conn_state) is "SF" and the original bytes (orig_bytes) are greater than 1000, it is considered an exploit.

6. **Generic**:
   - Detect general suspicious behavior.
   - Example: Unusual patterns in data transfer.
   - Detection Logic: If the original bytes (orig_bytes) are greater than 1000000, it is considered generic suspicious behavior.

7. **Reconnaissance**:
   - Detect scanning activities.
   - Example: Short duration connections to many different IPs.
   - Detection Logic: If the duration (duration) is less than 0.1 and the destination port (resp_p) is not 80 or 443, it is considered reconnaissance.

8. **Shellcode**:
   - Detect known shellcode patterns.
   - Example: Specific conn_state values.
   - Detection Logic: If the connection state (conn_state) is "ShADfFa", it is considered shellcode.

9. **Worms**:
   - Detect known worm signatures.
   - Example: Specific proto values.
   - Detection Logic: If the protocol (proto) is "tcp" and the destination port (resp_p) is 25, it is considered a worm.
*/
int detect_fuzzers(ConnLog *entry) {
    // Example: Detect unusual or malformed requests
    if (entry->orig_p > 50000 || entry->resp_p > 50000) {
        return 1;
    }
    return 0;
}

int detect_analysis(ConnLog *entry) {
    // Example: Detect requests to known analysis tools or services
    if (strcmp(entry->service, "http") == 0 && entry->resp_p == 80) {
        return 1;
    }
    return 0;
}

int detect_backdoors(ConnLog *entry) {
    // Example: Detect connections to unusual ports or IPs
    if (entry->resp_p == 5555) { // Example unusual port
        return 1;
    }
    return 0;
}

int detect_dos(ConnLog *entry) {
    // Example: Detect high volume of requests in a short period
    if (entry->duration < 1.0 && entry->orig_bytes > 10000) {
        return 1;
    }
    return 0;
}

int detect_exploits(ConnLog *entry) {
    // Example: Detect known exploit signatures
    if (strcmp(entry->conn_state, "SF") == 0 && entry->orig_bytes > 1000) {
        return 1;
    }
    return 0;
}

int detect_generic(ConnLog *entry) {
    // Example: Detect general suspicious behavior
    if (entry->orig_bytes > 1000000) {
        return 1;
    }
    return 0;
}

int detect_reconnaissance(ConnLog *entry) {
    // Example: Detect scanning activities
    if (entry->duration < 0.1 && entry->resp_p != 80 && entry->resp_p != 443) {
        return 1;
    }
    return 0;
}

int detect_shellcode(ConnLog *entry) {
    // Example: Detect known shellcode patterns
    if (strcmp(entry->conn_state, "ShADfFa") == 0) {
        return 1;
    }
    return 0;
}

int detect_worms(ConnLog *entry) {
    // Example: Detect known worm signatures
    if (strcmp(entry->proto, "tcp") == 0 && entry->resp_p == 25) {
        return 1;
    }
    return 0;
}




void detect_suspicious_activity(ConnLog *entry, SuspiciousActivity *activity) {
    if (detect_fuzzers(entry)) {
        activity->fuzzers++;
        //printf("Fuzzers detected: %s\n", entry->uid);
    }
    if (detect_analysis(entry)) {
        activity->analysis++;
        //printf("Analysis detected: %s\n", entry->uid);
    }
    if (detect_backdoors(entry)) {
        activity->backdoors++;
        //printf("Backdoor detected: %s\n", entry->uid);
    }
    if (detect_dos(entry)) {
        activity->dos++;
        //printf("DoS detected: %s\n", entry->uid);
    }
    if (detect_exploits(entry)) {
        activity->exploits++;
        //printf("Exploits detected: %s\n", entry->uid);
    }
    if (detect_generic(entry)) {
        activity->generic++;
        //printf("Generic detected: %s\n", entry->uid);
    }
    if (detect_reconnaissance(entry)) {
        activity->reconnaissance++;
        //printf("Reconnaissance detected: %s\n", entry->uid);
    }
    if (detect_shellcode(entry)) {
        activity->shellcode++;
        //printf("Shellcode detected: %s\n", entry->uid);
    }
    if (detect_worms(entry)) {
        activity->worms++;
        //printf("Worms detected: %s\n", entry->uid);
    }
}



int main(int argc, char **argv) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    char *buffer = NULL;
    long file_size = 0;
    char *local_buffer = NULL;
    int local_size = 0;

    // Root process reads entire file
    if (rank == 0) {
        // Get file size
        fseek(stdin, 0, SEEK_END);
        file_size = ftell(stdin);
        rewind(stdin);

        // Allocate buffer and read file
        buffer = (char *)malloc(file_size + 1);
        if (buffer == NULL) {
            fprintf(stderr, "Failed to allocate buffer\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        fread(buffer, 1, file_size, stdin);
        buffer[file_size] = '\0';
    }

    // Broadcast file size to all processes
    MPI_Bcast(&file_size, 1, MPI_LONG, 0, MPI_COMM_WORLD);

    // Calculate local buffer size
    local_size = file_size / size + (file_size % size ? 1 : 0);
    local_buffer = (char *)malloc(local_size + 1);
    if (local_buffer == NULL) {
        fprintf(stderr, "Failed to allocate local buffer\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    // Scatter data to all processes
    MPI_Scatter(buffer, local_size, MPI_CHAR,
                local_buffer, local_size, MPI_CHAR,
                0, MPI_COMM_WORLD);

    // Process local portion
    char line[MAX_LINE_LENGTH];
    ConnLog entry;
    SuspiciousActivity activity = {0};
    int pos = 0;

    while (pos < local_size) {
        int line_len = 0;
        // Find end of line
        while (pos + line_len < local_size && local_buffer[pos + line_len] != '\n') {
            line_len++;
        }
        if (line_len > 0) {
            strncpy(line, &local_buffer[pos], line_len);
            line[line_len] = '\0';
            parse_conn_log(line, &entry);
            detect_suspicious_activity(&entry, &activity);
        }
        pos += line_len + 1;
    }

    // Combine results from all processes
    SuspiciousActivity global_activity;
    MPI_Reduce(&activity, &global_activity, sizeof(SuspiciousActivity)/sizeof(int), 
               MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    // Master process prints results
    if (rank == 0) {
        int total_attacks = global_activity.fuzzers + 
                           global_activity.analysis + 
                           global_activity.backdoors + 
                           global_activity.dos + 
                           global_activity.exploits + 
                           global_activity.generic + 
                           global_activity.reconnaissance + 
                           global_activity.shellcode + 
                           global_activity.worms;

        printf("\n=== Attack Detection Summary ===\n");
        printf("Total Attacks Detected: %d\n\n", total_attacks);
        
        printf("Attack Distribution:\n");
        printf("- Fuzzers: %d (%.2f%%)\n", global_activity.fuzzers, 
               (float)global_activity.fuzzers/total_attacks * 100);
        printf("- Analysis: %d (%.2f%%)\n", global_activity.analysis,
               (float)global_activity.analysis/total_attacks * 100);
        printf("- Backdoors: %d (%.2f%%)\n", global_activity.backdoors,
               (float)global_activity.backdoors/total_attacks * 100);
        printf("- DoS: %d (%.2f%%)\n", global_activity.dos,
               (float)global_activity.dos/total_attacks * 100);
        printf("- Exploits: %d (%.2f%%)\n", global_activity.exploits,
               (float)global_activity.exploits/total_attacks * 100);
        printf("- Generic: %d (%.2f%%)\n", global_activity.generic,
               (float)global_activity.generic/total_attacks * 100);
        printf("- Reconnaissance: %d (%.2f%%)\n", global_activity.reconnaissance,
               (float)global_activity.reconnaissance/total_attacks * 100);
        printf("- Shellcode: %d (%.2f%%)\n", global_activity.shellcode,
               (float)global_activity.shellcode/total_attacks * 100);
        printf("- Worms: %d (%.2f%%)\n", global_activity.worms,
               (float)global_activity.worms/total_attacks * 100);

        printf("\nProcess Distribution:\n");
        printf("- Number of MPI Processes: %d\n", size);
        printf("- Average Attacks per Process: %.2f\n", (float)total_attacks/size);
    }

    // Cleanup
    free(local_buffer);
    if (rank == 0) {
        free(buffer);
    }

    MPI_Finalize();
    return 0;
}