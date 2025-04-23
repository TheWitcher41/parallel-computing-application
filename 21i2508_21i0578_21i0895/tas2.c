#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <stdbool.h>


#define MAX_LINE_LENGTH 1024
#define MAX_IP_LENGTH 64
#define MAX_SUSPICIOUS_IPS 1000
#define MIN_DURATION_THRESHOLD 0.1
#define FUZZER_THRESHOLD 1000
#define DOS_THRESHOLD 500
#define RECON_THRESHOLD 5000


#define CRITICAL_THRESHOLD 0.25  // 25% of total traffic
#define HIGH_THRESHOLD 0.15      // 15% of total traffic
#define MEDIUM_THRESHOLD 0.05    // 5% of total traffic


// Add these constants at the top
#define DDOS_CONNECTION_THRESHOLD 500  // Lower from 1000 to catch more attacks
#define DDOS_DURATION_THRESHOLD 0.1    // Quick connections
#define DDOS_PORT_THRESHOLD 5          // Lower from 10 to catch more port scanning




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



typedef struct {
    char ip[MAX_IP_LENGTH];
    int connection_count;
    long total_bytes;
    double min_duration;
    int port_scan_count;
    int failed_login_count;
} IPStats;


// Add risk scoring structure
typedef struct {
    double fuzzer_score;
    double dos_score;
    double recon_score;
    int total_records;
    int critical_alerts;
    int high_alerts;
} RiskMetrics;


// Add these structures after existing ones
typedef struct {
    char ip[MAX_IP_LENGTH];
    int *ports;
    int port_count;
    int port_capacity;
} PortScanTracker;

typedef struct {
    char ip[MAX_IP_LENGTH];
    double avg_duration;
    int connection_count;
    long total_bytes;
    int unique_ports;
} DDosStats;


void parse_conn_log(char *line, ConnLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %15s %63s %lf %ld %ld %15s %d %ld %63s %ld %ld %ld %ld %127s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->proto,
           entry->service, &entry->duration, &entry->orig_bytes, &entry->resp_bytes, entry->conn_state,
           &entry->local_orig, &entry->missed_bytes, entry->history, &entry->orig_pkts, &entry->orig_ip_bytes,
           &entry->resp_pkts, &entry->resp_ip_bytes, entry->tunnel_parents);
}



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


unsigned long calculate_checksum(char *data, int length) {
    unsigned long checksum = 0;
    for (int i = 0; i < length; i++) {
        checksum += data[i];
    }
    return checksum;
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

bool is_ip_in_list(char ip_list[][MAX_IP_LENGTH], int count, char *ip) {
    for (int i = 0; i < count; i++) {
        if (strcmp(ip_list[i], ip) == 0) {
            return true;
        }
    }
    return false;
}

// Function to track IP statistics
void update_ip_stats(IPStats *stats, int stats_count, ConnLog *entry, int *current_count) {
    bool found = false;
    for (int i = 0; i < *current_count; i++) {
        if (strcmp(stats[i].ip, entry->orig_h) == 0) {
            stats[i].connection_count++;
            stats[i].total_bytes += entry->orig_bytes;
            if (entry->duration < stats[i].min_duration) {
                stats[i].min_duration = entry->duration;
            }
            if (entry->duration < MIN_DURATION_THRESHOLD) {
                stats[i].port_scan_count++;
            }
            found = true;
            break;
        }
    }

    if (!found && *current_count < MAX_SUSPICIOUS_IPS) {
        strncpy(stats[*current_count].ip, entry->orig_h, MAX_IP_LENGTH);
        stats[*current_count].connection_count = 1;
        stats[*current_count].total_bytes = entry->orig_bytes;
        stats[*current_count].min_duration = entry->duration;
        stats[*current_count].port_scan_count = (entry->duration < MIN_DURATION_THRESHOLD) ? 1 : 0;
        (*current_count)++;
    }
}

// Add these functions before main()
void track_port_scan(PortScanTracker *tracker, int port) {
    for (int i = 0; i < tracker->port_count; i++) {
        if (tracker->ports[i] == port) return;
    }
    
    if (tracker->port_count >= tracker->port_capacity) {
        tracker->port_capacity *= 2;
        tracker->ports = realloc(tracker->ports, tracker->port_capacity * sizeof(int));
    }
    
    tracker->ports[tracker->port_count++] = port;
}


// Function to calculate risk metrics
RiskMetrics calculate_risk_metrics(SuspiciousActivity *activity, int total_records) {
    RiskMetrics metrics = {0};
    metrics.total_records = total_records;
    
    // Calculate percentages
    double fuzzer_pct = (double)activity->fuzzers / total_records;
    double dos_pct = (double)activity->dos / total_records;
    double recon_pct = (double)activity->reconnaissance / total_records;
    
    // Calculate risk scores
    metrics.fuzzer_score = fuzzer_pct > CRITICAL_THRESHOLD ? 1.0 : 
                          fuzzer_pct > HIGH_THRESHOLD ? 0.7 : 
                          fuzzer_pct > MEDIUM_THRESHOLD ? 0.4 : 0.1;
                          
    metrics.dos_score = dos_pct > CRITICAL_THRESHOLD ? 1.0 :
                       dos_pct > HIGH_THRESHOLD ? 0.7 :
                       dos_pct > MEDIUM_THRESHOLD ? 0.4 : 0.1;
                       
    metrics.recon_score = recon_pct > CRITICAL_THRESHOLD ? 1.0 :
                         recon_pct > HIGH_THRESHOLD ? 0.7 :
                         recon_pct > MEDIUM_THRESHOLD ? 0.4 : 0.1;
    
    // Count alerts by severity
    if (fuzzer_pct > CRITICAL_THRESHOLD) metrics.critical_alerts++;
    if (dos_pct > CRITICAL_THRESHOLD) metrics.critical_alerts++;
    if (recon_pct > CRITICAL_THRESHOLD) metrics.critical_alerts++;
    
    if (fuzzer_pct > HIGH_THRESHOLD) metrics.high_alerts++;
    if (dos_pct > HIGH_THRESHOLD) metrics.high_alerts++;
    if (recon_pct > HIGH_THRESHOLD) metrics.high_alerts++;
    
    return metrics;
}


// Add this function for analyzing results
void analyze_and_print_results(SuspiciousActivity *activity, unsigned long checksum, 
                             int total_records, RiskMetrics *metrics) {
    printf("\n=== Detection Summary ===\n");
    printf("Total Records Processed: %d\n", total_records);
    printf("Data Integrity Checksum: %lu\n\n", checksum);
    
    printf("Risk Assessment:\n");
    printf("Critical Alerts: %d\n", metrics->critical_alerts);
    printf("High Alerts: %d\n", metrics->high_alerts);
    printf("Overall Risk Scores:\n");
    printf("- Fuzzing Risk: %.2f\n", metrics->fuzzer_score);
    printf("- DoS Risk: %.2f\n", metrics->dos_score);
    printf("- Reconnaissance Risk: %.2f\n", metrics->recon_score);
    
    printf("\nDetailed Statistics:\n");
    printf("%-20s %8d (%.2f%%)\n", "Fuzzers:", activity->fuzzers, 
           (float)activity->fuzzers/total_records * 100);
    printf("%-20s %8d (%.2f%%)\n", "Analysis:", activity->analysis,
           (float)activity->analysis/total_records * 100);
    printf("%-20s %8d (%.2f%%)\n", "Backdoors:", activity->backdoors,
           (float)activity->backdoors/total_records * 100);
    printf("%-20s %8d (%.2f%%)\n", "DoS:", activity->dos,
           (float)activity->dos/total_records * 100);
    printf("%-20s %8d (%.2f%%)\n", "Exploits:", activity->exploits,
           (float)activity->exploits/total_records * 100);
    printf("%-20s %8d (%.2f%%)\n", "Generic:", activity->generic,
           (float)activity->generic/total_records * 100);
    printf("%-20s %8d (%.2f%%)\n", "Reconnaissance:", activity->reconnaissance,
           (float)activity->reconnaissance/total_records * 100);
    printf("%-20s %8d (%.2f%%)\n", "Shellcode:", activity->shellcode,
           (float)activity->shellcode/total_records * 100);
    printf("%-20s %8d (%.2f%%)\n", "Worms:", activity->worms,
           (float)activity->worms/total_records * 100);
}

void cleanup_resources(IPStats *local_stats, DDosStats *ddos_stats, 
                      PortScanTracker *port_trackers, int rank,
                      DDosStats *all_ddos_stats, int *recv_counts, int *displs) {
    if (local_stats) free(local_stats);
    if (ddos_stats) free(ddos_stats);
    
    if (port_trackers) {
        for (int i = 0; i < MAX_SUSPICIOUS_IPS; i++) {
            if (port_trackers[i].ports) {
                free(port_trackers[i].ports);
            }
        }
        free(port_trackers);
    }

    if (rank == 0) {
        if (all_ddos_stats) free(all_ddos_stats);
        if (recv_counts) free(recv_counts);
        if (displs) free(displs);
    }
}

int main(int argc, char **argv) {
    int rank = 0, size = 0, ret = 0;
    
    // Local statistics tracking
    IPStats *local_stats = NULL;
    DDosStats *ddos_stats = NULL;
    PortScanTracker *port_trackers = NULL;
    DDosStats *all_ddos_stats = NULL;
    int *recv_counts = NULL;
    int *displs = NULL;
    int local_stats_count = 0;
    int ddos_count = 0;
    int total_ddos_stats = 0;

    // Log processing variables
    char line[MAX_LINE_LENGTH];
    ConnLog entry;
    SuspiciousActivity activity = {0};
    unsigned long local_checksum = 0;
    
    // Initialize MPI
    ret = MPI_Init(&argc, &argv);
    if (ret != MPI_SUCCESS) {
        fprintf(stderr, "Failed to initialize MPI\n");
        return 1;
    }

    double start_time = MPI_Wtime();

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    // Allocate memory with error checking
    local_stats = calloc(MAX_SUSPICIOUS_IPS, sizeof(IPStats));
    ddos_stats = calloc(MAX_SUSPICIOUS_IPS, sizeof(DDosStats));
    port_trackers = calloc(MAX_SUSPICIOUS_IPS, sizeof(PortScanTracker));

    if (!local_stats || !ddos_stats || !port_trackers) {
        fprintf(stderr, "Failed to allocate memory\n");
        goto cleanup;
    }

    // Initialize port trackers
    for (int i = 0; i < MAX_SUSPICIOUS_IPS; i++) {
        port_trackers[i].ports = malloc(100 * sizeof(int));
        if (!port_trackers[i].ports) {
            fprintf(stderr, "Failed to allocate port tracker memory\n");
            cleanup_resources(local_stats, ddos_stats, port_trackers, 
                            rank, all_ddos_stats, recv_counts, displs);
            MPI_Finalize();
            return 1;
        }
        port_trackers[i].port_capacity = 100;
        port_trackers[i].port_count = 0;
    }

    // Verify allocations
    if (!local_stats || !ddos_stats || !port_trackers) {
        fprintf(stderr, "Failed to allocate memory\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    // Process log entries
    while (fgets(line, MAX_LINE_LENGTH, stdin) != NULL) {
        parse_conn_log(line, &entry);
        detect_suspicious_activity(&entry, &activity);
        local_checksum += calculate_checksum(line, strlen(line));
        update_ip_stats(local_stats, MAX_SUSPICIOUS_IPS, &entry, &local_stats_count);
        
        // Update DDoS statistics
        bool found_ddos = false;
        for (int i = 0; i < ddos_count; i++) {
            if (strcmp(ddos_stats[i].ip, entry.orig_h) == 0) {
                ddos_stats[i].connection_count++;
                ddos_stats[i].total_bytes += entry.orig_bytes;
                ddos_stats[i].avg_duration = 
                    (ddos_stats[i].avg_duration * (ddos_stats[i].connection_count - 1) + 
                     entry.duration) / ddos_stats[i].connection_count;
                
                // Track unique ports
                bool port_found = false;
                for (int j = 0; j < port_trackers[i].port_count; j++) {
                    if (port_trackers[i].ports[j] == entry.resp_p) {
                        port_found = true;
                        break;
                    }
                }
                if (!port_found) {
                    track_port_scan(&port_trackers[i], entry.resp_p);
                    ddos_stats[i].unique_ports++;
                }
                found_ddos = true;
                break;
            }
        }

        // Add new DDoS entry if not found
        if (!found_ddos && ddos_count < MAX_SUSPICIOUS_IPS) {
            strncpy(ddos_stats[ddos_count].ip, entry.orig_h, MAX_IP_LENGTH);
            ddos_stats[ddos_count].connection_count = 1;
            ddos_stats[ddos_count].total_bytes = entry.orig_bytes;
            ddos_stats[ddos_count].avg_duration = entry.duration;
            ddos_stats[ddos_count].unique_ports = 1;
            track_port_scan(&port_trackers[ddos_count], entry.resp_p);
            ddos_count++;
        }
    }

    // Combine activity data
    SuspiciousActivity global_activity;
    MPI_Reduce(&activity, &global_activity, sizeof(SuspiciousActivity)/sizeof(int), 
               MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    // Gather DDoS statistics counts first
    if (rank == 0) {
        recv_counts = calloc(size, sizeof(int));
        displs = calloc(size, sizeof(int));
        if (!recv_counts || !displs) {
            fprintf(stderr, "Failed to allocate arrays on root\n");
            goto cleanup;
        }
    }

    // Share ddos_count across processes
    ret = MPI_Gather(&ddos_count, 1, MPI_INT,
                     recv_counts, 1, MPI_INT,
                     0, MPI_COMM_WORLD);
    if (ret != MPI_SUCCESS) {
        fprintf(stderr, "Failed to gather counts\n");
        goto cleanup;
    }

    // Calculate total size and displacements on root
    if (rank == 0) {
        int total_count = 0;
        displs[0] = 0;
        
        for (int i = 0; i < size; i++) {
            total_count += recv_counts[i];
            if (i > 0) {
                displs[i] = displs[i-1] + recv_counts[i-1] * sizeof(DDosStats);
            }
            recv_counts[i] *= sizeof(DDosStats);  // Convert counts to bytes
        }
        
        total_ddos_stats = total_count;  // Store actual count
        
        // Allocate receive buffer
        all_ddos_stats = calloc(total_count, sizeof(DDosStats));
        if (!all_ddos_stats) {
            fprintf(stderr, "Failed to allocate receive buffer\n");
            goto cleanup;
        }
    }

    // Gather DDoS statistics
    ret = MPI_Gatherv(ddos_stats, ddos_count * sizeof(DDosStats), MPI_BYTE,
                      all_ddos_stats, recv_counts, displs, MPI_BYTE,
                      0, MPI_COMM_WORLD);
    if (ret != MPI_SUCCESS) {
        char error_string[MPI_MAX_ERROR_STRING];
        int length;
        MPI_Error_string(ret, error_string, &length);
        fprintf(stderr, "MPI_Gatherv failed: %s\n", error_string);
        goto cleanup;
    }

    // Calculate global checksum
    unsigned long global_checksum = 0;
    MPI_Reduce(&local_checksum, &global_checksum, 1, MPI_UNSIGNED_LONG, 
               MPI_SUM, 0, MPI_COMM_WORLD);

    // Master process analyzes results
   if (rank == 0) {
        int total_records = global_activity.fuzzers + global_activity.analysis + 
                           global_activity.backdoors + global_activity.dos + 
                           global_activity.exploits + global_activity.generic + 
                           global_activity.reconnaissance + global_activity.shellcode + 
                           global_activity.worms;
        
        RiskMetrics metrics = calculate_risk_metrics(&global_activity, total_records);
        analyze_and_print_results(&global_activity, global_checksum, total_records, &metrics);

        printf("\nDistributed Attack Analysis:\n");
        printf("%-20s %-12s %-15s %-12s %s\n", 
               "IP Address", "Connections", "Total Bytes", "Unique Ports", "Avg Duration");
        
        int ddos_detected = 0;
        printf("\nDebug Information:\n");
        for (int i = 0; i < total_ddos_stats; i++) {
            if (all_ddos_stats[i].connection_count > 0) {
                printf("Debug: IP %s - Conn: %d, Duration: %.3f, Ports: %d\n",
                       all_ddos_stats[i].ip,
                       all_ddos_stats[i].connection_count,
                       all_ddos_stats[i].avg_duration,
                       all_ddos_stats[i].unique_ports);

                if (all_ddos_stats[i].connection_count > DDOS_CONNECTION_THRESHOLD && 
                    all_ddos_stats[i].avg_duration < DDOS_DURATION_THRESHOLD &&
                    all_ddos_stats[i].unique_ports > DDOS_PORT_THRESHOLD) {
                    printf("\nDDoS Attack Detected:\n");
                    printf("%-20s %-12d %-15ld %-12d %.3f\n",
                           all_ddos_stats[i].ip,
                           all_ddos_stats[i].connection_count,
                           all_ddos_stats[i].total_bytes,
                           all_ddos_stats[i].unique_ports,
                           all_ddos_stats[i].avg_duration);
                    ddos_detected++;
                }
            }
        }
        
        printf("\nAnalysis Summary:\n");
        if (ddos_detected == 0) {
            printf("No DDoS attacks detected with current thresholds.\n");
            printf("Thresholds: Connections > %d, Duration < %.3f, Unique Ports > %d\n",
                   DDOS_CONNECTION_THRESHOLD, DDOS_DURATION_THRESHOLD, DDOS_PORT_THRESHOLD);
        } else {
            printf("Total DDoS attacks detected: %d\n", ddos_detected);
        }
    }

cleanup:
    cleanup_resources(local_stats, ddos_stats, port_trackers, 
                     rank, all_ddos_stats, recv_counts, displs);

    double end_time = MPI_Wtime();

    double elapsed_time = end_time - start_time;

    printf("Elapsed time: %f seconds\n", elapsed_time);



    MPI_Finalize();
    return ret != MPI_SUCCESS;
}