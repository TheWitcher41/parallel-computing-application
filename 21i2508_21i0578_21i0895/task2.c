#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>

#define MAX_LINE_LENGTH 1024
#define MAX_IP_LENGTH 64
#define INITIAL_SUSPICIOUS_IPS 1000  // Define INITIAL_SUSPICIOUS_IPS

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
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char proto[16];
    char facility[64];
    char severity[64];
    char message[256];
} SysLog;

typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char mac[32];
    char assigned_ip[64];
    double lease_time;
    unsigned int trans_id;
} DhcpLog;


typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char proto[16];
    unsigned int trans_id;
    char query[256];
    int qclass;
    char qclass_name[64];
    int qtype;
    char qtype_name[64];
    int rcode;
    char rcode_name[64];
    int AA;
    int TC;
    int RD;
    int RA;
    int Z;
    char answers[512];
    char TTLs[256];
    int rejected;
} DnsLog;

typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char proto[16];
    char analyzer[64];
    char failure_reason[128];
} DpdLog;


typedef struct {
    char ts[64];
    char fuid[64];
    char tx_hosts[256];
    char rx_hosts[256];
    char conn_uids[256];
    char source[64];
    int depth;
    char analyzers[256];
    char mime_type[128];
    char filename[256];
    double duration;
    bool local_orig;
    bool is_orig;
    long seen_bytes;
    long total_bytes;
    long missing_bytes;
    long overflow_bytes;
    bool timedout;
    char parent_fuid[64];
    char md5[64];
    char sha1[64];
    char sha256[64];
    char extracted[256];
} FilesLog;


typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char user[64];
    char password[64];
    char command[64];
    char arg[256];
    char mime_type[128];
    long file_size;
    int reply_code;
    char reply_msg[256];
    bool data_channel_passive;
    char data_channel_orig_h[64];
    char data_channel_resp_h[64];
    int data_channel_resp_p;
    char fuid[64];
} FtpLog;


typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    int trans_depth;
    char method[16];
    char host[256];
    char uri[1024];
    char referrer[1024];
    char user_agent[256];
    int request_body_len;
    int response_body_len;
    int status_code;
    char status_msg[256];
    int info_code;
    char info_msg[256];
    char filename[256];
    char tags[256]; // Assuming a set of enums
    char username[64];
    char password[64];
    char proxied[256];
    char orig_fuids[256]; // Assuming set of strings
    char orig_mime_types[256]; // Assuming vector of strings
    char resp_fuids[256]; // Assuming vector of strings
    char resp_mime_types[256]; // Assuming vector of strings
} HttpLog;

typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char nick[64];
    char user[64];
    char command[64];
    char value[256];
    char addl[256];
    char dcc_file_name[256];
    long dcc_file_size;
    char dcc_mime_type[128];
    char fuid[64];
} IrcLog;


typedef struct {
    char ts[64];
    char node[64];
    char filter[256];
    bool init;
    bool success;
} PacketFilterLog;

typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char username[64];
    char mac[64];
    char remote_ip[64];
    char connect_info[256];
    char result[64];
} RadiusLog;

typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    int trans_depth;
    char helo[64];
    char mailfrom[64];
    char rcptto[256]; // assuming set[string] is comma-separated
    char date[64];
    char from[64];
    char to[256]; // assuming set[string] is comma-separated
    char reply_to[64];
    char msg_id[64];
    char in_reply_to[64];
    char subject[256];
    char x_originating_ip[64];
    char first_received[256];
    char second_received[256];
    char last_reply[256];
    char path[256]; // assuming vector[addr] is comma-separated
    char user_agent[256];
    bool tls;
    char fuids[256]; // assuming vector[string] is comma-separated
} SmtpLog;



typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    double duration;
    char version[16];
    char community[64];
    int get_requests;
    int get_bulk_requests;
    int get_responses;
    int set_requests;
    char display_string[256];
    char up_since[64];
} SnmpLog;

typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char status[64];
    char direction[16];
    char client[64];
    char server[64];
} SshLog;

typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char version[16];
    char cipher[64];
    char curve[64];
    char server_name[256];
    char session_id[64];
    char last_alert[64];
    bool established;
    char cert_chain_fuids[256]; // assuming vector[string] is comma-separated
    char client_cert_chain_fuids[256]; // assuming vector[string] is comma-separated
    char subject[256];
    char issuer[256];
    char client_subject[256];
    char client_issuer[256];
} SslLog;


typedef struct {
    char ts[64];
    char uid[64];
    char orig_h[64];
    int orig_p;
    char resp_h[64];
    int resp_p;
    char name[256];
    char addl[256];
    bool notice;
    char peer[256];
} WeirdLog;

typedef struct {
    char ts[64];
    char id[64];
    int certificate_version;
    char certificate_serial[64];
    char certificate_subject[256];
    char certificate_issuer[256];
    char certificate_not_valid_before[64];
    char certificate_not_valid_after[64];
    char certificate_key_alg[64];
    char certificate_sig_alg[64];
    char certificate_key_type[64];
    int certificate_key_length;
    char certificate_exponent[64];
    char certificate_curve[64];
    char san_dns[256];
    char san_uri[256];
    char san_email[256];
    char san_ip[256];
    bool basic_constraints_ca;
    int basic_constraints_path_len;
} X509Log;


//we have to implement this function to read the log files

//parse the log file and store the data in the structure

void parse_conn_log(char *line, ConnLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %15s %63s %63s %lf %ld %ld %15s %d %ld %63s %ld %ld %ld %ld %63s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->proto,
           entry->service, &entry->duration, &entry->orig_bytes, &entry->resp_bytes, entry->conn_state,
           &entry->local_orig, &entry->missed_bytes, entry->history, &entry->orig_pkts, &entry->orig_ip_bytes,
           &entry->resp_pkts, &entry->resp_ip_bytes, entry->tunnel_parents);
}

void parse_sys_log(char *line, SysLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %15s %63s %63s %255s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->proto,
           entry->facility, entry->severity, entry->message);
}

void parse_dhcp_log(char *line, DhcpLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %31s %63s %lf %u",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p,
           entry->resp_h, &entry->resp_p, entry->mac, entry->assigned_ip,
           &entry->lease_time, &entry->trans_id);
}


void parse_dns_log(char *line, DnsLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %15s %u %255s %d %63s %d %63s %d %63s %d %d %d %d %d %d %511s %255s %d",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->proto,
           &entry->trans_id, entry->query, &entry->qclass, entry->qclass_name, &entry->qtype, entry->qtype_name,
           &entry->rcode, entry->rcode_name, &entry->AA, &entry->TC, &entry->RD, &entry->RA, &entry->Z,
           entry->answers, entry->TTLs, &entry->rejected);
}

void parse_dpd_log(char *line, DpdLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %15s %63s %127s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->proto,
           entry->analyzer, entry->failure_reason);
}

void parse_files_log(char *line, FilesLog *entry) {
    sscanf(line, "%63s %63s %255s %255s %255s %63s %d %255s %127s %255s %lf %d %d %ld %ld %ld %ld %d %63s %63s %63s %63s %255s",
           entry->ts, entry->fuid, entry->tx_hosts, entry->rx_hosts, entry->conn_uids, entry->source, &entry->depth,
           entry->analyzers, entry->mime_type, entry->filename, &entry->duration, &entry->local_orig, &entry->is_orig,
           &entry->seen_bytes, &entry->total_bytes, &entry->missing_bytes, &entry->overflow_bytes, &entry->timedout,
           entry->parent_fuid, entry->md5, entry->sha1, entry->sha256, entry->extracted);
}

void parse_ftp_log(char *line, FtpLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %63s %63s %63s %255s %127s %ld %d %255s %d %63s %63s %d %63s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->user,
           entry->password, entry->command, entry->arg, entry->mime_type, &entry->file_size, &entry->reply_code,
           entry->reply_msg, &entry->data_channel_passive, entry->data_channel_orig_h, entry->data_channel_resp_h,
           &entry->data_channel_resp_p, entry->fuid);
}

void parse_http_log(char *line, HttpLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %d %15s %255s %1023s %1023s %255s %d %d %d %255s %d %255s %255s %255s %63s %63s %255s %255s %255s %255s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, &entry->trans_depth,
           entry->method, entry->host, entry->uri, entry->referrer, entry->user_agent, &entry->request_body_len,
           &entry->response_body_len, &entry->status_code, entry->status_msg, &entry->info_code, entry->info_msg,
           entry->filename, entry->tags, entry->username, entry->password, entry->proxied, entry->orig_fuids,
           entry->orig_mime_types, entry->resp_fuids, entry->resp_mime_types);
}

void parse_irc_log(char *line, IrcLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %63s %63s %63s %255s %255s %255s %ld %127s %63s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->nick,
           entry->user, entry->command, entry->value, entry->addl, entry->dcc_file_name, &entry->dcc_file_size,
           entry->dcc_mime_type, entry->fuid);
}

void parse_packet_filter_log(char *line, PacketFilterLog *entry) {
    sscanf(line, "%63s %63s %255s %d %d",
           entry->ts, entry->node, entry->filter, &entry->init, &entry->success);
}

void parse_radius_log(char *line, RadiusLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %63s %63s %63s %255s %63s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->username,
           entry->mac, entry->remote_ip, entry->connect_info, entry->result);
}

void parse_smtp_log(char *line, SmtpLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %d %63s %63s %255s %63s %63s %255s %63s %63s %63s %255s %63s %255s %255s %255s %255s %255s %d %255s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, &entry->trans_depth,
           entry->helo, entry->mailfrom, entry->rcptto, entry->date, entry->from, entry->to, entry->reply_to,
           entry->msg_id, entry->in_reply_to, entry->subject, entry->x_originating_ip, entry->first_received,
           entry->second_received, entry->last_reply, entry->path, entry->user_agent, &entry->tls, entry->fuids);
}

void parse_snmp_log(char *line, SnmpLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %lf %15s %63s %d %d %d %d %255s %63s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, &entry->duration,
           entry->version, entry->community, &entry->get_requests, &entry->get_bulk_requests, &entry->get_responses,
           &entry->set_requests, entry->display_string, entry->up_since);
}

void parse_ssh_log(char *line, SshLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %63s %15s %63s %63s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->status,
           entry->direction, entry->client, entry->server);
}

void parse_ssl_log(char *line, SslLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %15s %63s %63s %255s %63s %63s %d %255s %255s %255s %255s %255s %255s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->version,
           entry->cipher, entry->curve, entry->server_name, entry->session_id, entry->last_alert, &entry->established,
           entry->cert_chain_fuids, entry->client_cert_chain_fuids, entry->subject, entry->issuer, entry->client_subject,
           entry->client_issuer);
}

void parse_weird_log(char *line, WeirdLog *entry) {
    sscanf(line, "%63s %63s %63s %d %63s %d %255s %255s %d %255s",
           entry->ts, entry->uid, entry->orig_h, &entry->orig_p, entry->resp_h, &entry->resp_p, entry->name,
           entry->addl, &entry->notice, entry->peer);
}

void parse_x509_log(char *line, X509Log *entry) {
    sscanf(line, "%63s %63s %d %63s %255s %255s %63s %63s %63s %63s %63s %d %63s %63s %255s %255s %255s %255s %d %d",
           entry->ts, entry->id, &entry->certificate_version, entry->certificate_serial, entry->certificate_subject,
           entry->certificate_issuer, entry->certificate_not_valid_before, entry->certificate_not_valid_after,
           entry->certificate_key_alg, entry->certificate_sig_alg, entry->certificate_key_type, &entry->certificate_key_length,
           entry->certificate_exponent, entry->certificate_curve, entry->san_dns, entry->san_uri, entry->san_email,
           entry->san_ip, &entry->basic_constraints_ca, &entry->basic_constraints_path_len);
}



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

/*
Q2: Cross-Process Correlation and Error Checking
1. Distributed Attack Detection:
Some attacks, such as distributed denial-of-service (DDoS) or port scanning, may involve activities
spread across different log file segments. To detect such attacks, use MPI_Allreduce to combine
data from all processes and analyze patterns involving multiple IP addresses or ports.
For example, if multiple processes detect login attempts or network connections from the same
IP address, use MPI_Allreduce to consolidate this data and flag it as a potential distributed attack.

2. Error Checking and Validation:
Implement a checksum system to validate that all log file segments have been processed
correctly. Each process should calculate a checksum for the portion of the log it analyzes.
Use MPI_Reduce to compute the global checksum and verify that no part of the log file was
skipped or misprocessed.
3. Cross-checking Suspicious IPs:
After each process identifies suspicious IP addresses, use MPI_Gather to collect the list of flagged
IPs.
The master process should cross-check this list to ensure there is no overlap or redundancy, and
then broadcast the final list of suspicious IPs to all processes using MPI_Bcast.


*/


//function for checksum

unsigned long calculate_checksum(char *data, size_t length) {
    unsigned long checksum = 0;
    for (size_t i = 0; i < length; i++) {
        checksum += (unsigned char)data[i];
    }
    return checksum;
}

//function to compare the suspicious IPs

int compare_suspicious_ips(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

//make a list to store ips and count the number of suspicious ips

void scan_for_patterns(ConnLog *entry, SuspiciousActivity *activity, char ***suspicious_ips, int *suspicious_ip_count, int *max_suspicious_ips) {
    if (*suspicious_ip_count >= *max_suspicious_ips) {
        *max_suspicious_ips *= 2;
        *suspicious_ips = realloc(*suspicious_ips, (*max_suspicious_ips) * sizeof(char *));
        if (*suspicious_ips == NULL) {
            fprintf(stderr, "Error: Memory reallocation failed for suspicious_ips array\n");
            exit(EXIT_FAILURE);
        }
        for (int i = *suspicious_ip_count; i < *max_suspicious_ips; i++) {
            (*suspicious_ips)[i] = malloc(MAX_IP_LENGTH * sizeof(char));
            if ((*suspicious_ips)[i] == NULL) {
                fprintf(stderr, "Error: Memory allocation failed for suspicious_ips[%d]\n", i);
                exit(EXIT_FAILURE);
            }
        }
    }

    if (detect_fuzzers(entry)) {
        activity->fuzzers++;
        strcpy((*suspicious_ips)[*suspicious_ip_count], entry->orig_h);
        (*suspicious_ip_count)++;
    }
    if (detect_analysis(entry)) {
        activity->analysis++;
        strcpy((*suspicious_ips)[*suspicious_ip_count], entry->orig_h);
        (*suspicious_ip_count)++;
    }
    if (detect_backdoors(entry)) {
        activity->backdoors++;
        strcpy((*suspicious_ips)[*suspicious_ip_count], entry->orig_h);
        (*suspicious_ip_count)++;
    }
    if (detect_dos(entry)) {
        activity->dos++;
        strcpy((*suspicious_ips)[*suspicious_ip_count], entry->orig_h);
        (*suspicious_ip_count)++;
    }
    if (detect_exploits(entry)) {
        activity->exploits++;
        strcpy((*suspicious_ips)[*suspicious_ip_count], entry->orig_h);
        (*suspicious_ip_count)++;
    }
    if (detect_generic(entry)) {
        activity->generic++;
        strcpy((*suspicious_ips)[*suspicious_ip_count], entry->orig_h);
        (*suspicious_ip_count)++;
    }
    if (detect_reconnaissance(entry)) {
        activity->reconnaissance++;
        strcpy((*suspicious_ips)[*suspicious_ip_count], entry->orig_h);
        (*suspicious_ip_count)++;
    }
    if (detect_shellcode(entry)) {
        activity->shellcode++;
        strcpy((*suspicious_ips)[*suspicious_ip_count], entry->orig_h);
        (*suspicious_ip_count)++;
    }
    if (detect_worms(entry)) {
        activity->worms++;
        strcpy((*suspicious_ips)[*suspicious_ip_count], entry->orig_h);
        (*suspicious_ip_count)++;
    }
}



void create_suspicious_activity_type(MPI_Datatype *mpi_suspicious_activity_type) {
    int lengths[9] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    MPI_Aint displacements[9];
    SuspiciousActivity dummy;

    MPI_Aint base_address;
    MPI_Get_address(&dummy, &base_address);
    MPI_Get_address(&dummy.fuzzers, &displacements[0]);
    MPI_Get_address(&dummy.analysis, &displacements[1]);
    MPI_Get_address(&dummy.backdoors, &displacements[2]);
    MPI_Get_address(&dummy.dos, &displacements[3]);
    MPI_Get_address(&dummy.exploits, &displacements[4]);
    MPI_Get_address(&dummy.generic, &displacements[5]);
    MPI_Get_address(&dummy.reconnaissance, &displacements[6]);
    MPI_Get_address(&dummy.shellcode, &displacements[7]);
    MPI_Get_address(&dummy.worms, &displacements[8]);

    for (int i = 0; i < 9; i++) {
        displacements[i] -= base_address;
    }

    MPI_Datatype types[9] = {MPI_INT, MPI_INT, MPI_INT, MPI_INT, MPI_INT, MPI_INT, MPI_INT, MPI_INT, MPI_INT};
    MPI_Type_create_struct(9, lengths, displacements, types, mpi_suspicious_activity_type);
    MPI_Type_commit(mpi_suspicious_activity_type);
}

void suspicious_activity_reduce(void *in, void *inout, int *len, MPI_Datatype *dptr) {
    SuspiciousActivity *in_vals = (SuspiciousActivity *)in;
    SuspiciousActivity *inout_vals = (SuspiciousActivity *)inout;
    for (int i = 0; i < *len; i++) {
        inout_vals[i].fuzzers += in_vals[i].fuzzers;
        inout_vals[i].analysis += in_vals[i].analysis;
        inout_vals[i].backdoors += in_vals[i].backdoors;
        inout_vals[i].dos += in_vals[i].dos;
        inout_vals[i].exploits += in_vals[i].exploits;
        inout_vals[i].generic += in_vals[i].generic;
        inout_vals[i].reconnaissance += in_vals[i].reconnaissance;
        inout_vals[i].shellcode += in_vals[i].shellcode;
        inout_vals[i].worms += in_vals[i].worms;
    }
}

int main(int argc, char **argv) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc < 2) {
        if (rank == 0) {
            fprintf(stderr, "Usage: %s <log_file>\n", argv[0]);
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    char *log_file = argv[1];
    FILE *file = fopen(log_file, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Could not open file %s\n", log_file);
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    // Determine the total number of lines in the file
    int total_lines = 0;
    char line[MAX_LINE_LENGTH];
    while (fgets(line, MAX_LINE_LENGTH, file) != NULL) {
        total_lines++;
    }
    fclose(file);

    // Calculate the number of lines each process will handle
    int lines_per_process = total_lines / size;
    int remaining_lines = total_lines % size;

    // Allocate memory for lines to be scattered
    char **lines = malloc(lines_per_process * sizeof(char *));
    if (lines == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for lines array\n");
        MPI_Finalize();
        return EXIT_FAILURE;
    }
    for (int i = 0; i < lines_per_process; i++) {
        lines[i] = malloc(MAX_LINE_LENGTH * sizeof(char));
        if (lines[i] == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for line %d\n", i);
            MPI_Finalize();
            return EXIT_FAILURE;
        }
    }

    // Scatter lines to each process
    file = fopen(log_file, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Could not open file %s\n", log_file);
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    for (int i = 0; i < rank * lines_per_process; i++) {
        fgets(line, MAX_LINE_LENGTH, file);
    }

    for (int i = 0; i < lines_per_process; i++) {
        if (fgets(lines[i], MAX_LINE_LENGTH, file) == NULL) {
            break;
        }
    }
    fclose(file);

    // Each process scans its lines for suspicious patterns
    SuspiciousActivity local_activity = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    ConnLog entry;
    int max_suspicious_ips = INITIAL_SUSPICIOUS_IPS;
    char **suspicious_ips = malloc(max_suspicious_ips * sizeof(char *));
    if (suspicious_ips == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for suspicious_ips array\n");
        MPI_Finalize();
        return EXIT_FAILURE;
    }
    for (int i = 0; i < max_suspicious_ips; i++) {
        suspicious_ips[i] = malloc(MAX_IP_LENGTH * sizeof(char));
        if (suspicious_ips[i] == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for suspicious_ips[%d]\n", i);
            MPI_Finalize();
            return EXIT_FAILURE;
        }
    }
    int suspicious_ip_count = 0;
    unsigned long local_checksum = 0;

    for (int i = 0; i < lines_per_process; i++) {
        parse_conn_log(lines[i], &entry);
        scan_for_patterns(&entry, &local_activity, &suspicious_ips, &suspicious_ip_count, &max_suspicious_ips);
        local_checksum += calculate_checksum(lines[i], strlen(lines[i]));
    }

    // Create custom MPI datatype for SuspiciousActivity
    MPI_Datatype mpi_suspicious_activity_type;
    create_suspicious_activity_type(&mpi_suspicious_activity_type);

    // Create custom reduction operation for SuspiciousActivity
    MPI_Op mpi_suspicious_activity_op;
    MPI_Op_create((MPI_User_function *)suspicious_activity_reduce, 1, &mpi_suspicious_activity_op);

    // Use MPI_Reduce to count total suspicious activities
    SuspiciousActivity global_activity = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    MPI_Reduce(&local_activity, &global_activity, 1, mpi_suspicious_activity_type, mpi_suspicious_activity_op, 0, MPI_COMM_WORLD);

    // Use MPI_Reduce to calculate global checksum
    unsigned long global_checksum = 0;
    MPI_Reduce(&local_checksum, &global_checksum, 1, MPI_UNSIGNED_LONG, MPI_SUM, 0, MPI_COMM_WORLD);

    // Use MPI_Gather to collect suspicious IPs from each process
    int *all_suspicious_ip_counts = NULL;
    char **all_suspicious_ips = NULL;
    if (rank == 0) {
        all_suspicious_ip_counts = malloc(size * sizeof(int));
        all_suspicious_ips = malloc(size * max_suspicious_ips * sizeof(char *));
        for (int i = 0; i < size * max_suspicious_ips; i++) {
            all_suspicious_ips[i] = malloc(MAX_IP_LENGTH * sizeof(char));
        }
    }
    MPI_Gather(&suspicious_ip_count, 1, MPI_INT, all_suspicious_ip_counts, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Gather(*suspicious_ips, suspicious_ip_count * MAX_IP_LENGTH, MPI_CHAR, *all_suspicious_ips, max_suspicious_ips * MAX_IP_LENGTH, MPI_CHAR, 0, MPI_COMM_WORLD);

    // Use MPI_Bcast to broadcast results
    MPI_Bcast(&global_activity, 1, mpi_suspicious_activity_type, 0, MPI_COMM_WORLD);

    // Root process can now use total_activity and distributed_activity
    if (rank == 0) {
        printf("Total Fuzzers: %d\n", global_activity.fuzzers);
        printf("Total Analysis: %d\n", global_activity.analysis);
        printf("Total Backdoors: %d\n", global_activity.backdoors);
        printf("Total DoS: %d\n", global_activity.dos);
        printf("Total Exploits: %d\n", global_activity.exploits);
        printf("Total Generic: %d\n", global_activity.generic);
        printf("Total Reconnaissance: %d\n", global_activity.reconnaissance);
        printf("Total Shellcode: %d\n", global_activity.shellcode);
        printf("Total Worms: %d\n", global_activity.worms);

        // Cross-check suspicious IPs
        printf("Global Checksum: %lu\n", global_checksum);
        printf("Suspicious IPs:\n");
        for (int i = 0; i < size; i++) {
            for (int j = 0; j < all_suspicious_ip_counts[i]; j++) {
                printf("%s\n", all_suspicious_ips[i * max_suspicious_ips + j]);
            }
        }
    }

    // Free allocated memory
    for (int i = 0; i < lines_per_process; i++) {
        free(lines[i]);
    }
    free(lines);
    for (int i = 0; i < max_suspicious_ips; i++) {
        free(suspicious_ips[i]);
    }
    free(suspicious_ips);
    if (rank == 0) {
        for (int i = 0; i < size * max_suspicious_ips; i++) {
            free(all_suspicious_ips[i]);
        }
        free(all_suspicious_ips);
        free(all_suspicious_ip_counts);
    }

    MPI_Op_free(&mpi_suspicious_activity_op);
    MPI_Type_free(&mpi_suspicious_activity_type);
    MPI_Finalize();
    return EXIT_SUCCESS;
}