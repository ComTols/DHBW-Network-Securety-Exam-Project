#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#define SUCCESS_IP "85.143.80.47"
#define ERROR_IP "47.81.64.105"
#define BUFFER_SIZE 512
#define HEMMING_BLOCK_SIZE 100

// Decode a Base64-encoded string
void base64_decode(const char *input, char *output) {
    const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j;
    unsigned int buffer = 0;
    int bits_left = 0;

    for (i = 0, j = 0; input[i] != '\0' && input[i] != '='; i++) {
        char *p = strchr(base64_table, input[i]);
        if (p) {
            buffer = (buffer << 6) | (p - base64_table);
            bits_left += 6;

            // When we have a full byte, we add it to the output
            if (bits_left >= 8) {
                bits_left -= 8;
                output[j++] = (buffer >> bits_left) & 0xFF;
            }
        }
    }
    output[j] = '\0';
}

// Encode a 4-bit data byte 3 error
uint8_t hamming_encode(uint8_t data) {
    uint8_t d1 = (data >> 3) & 1;
    uint8_t d2 = (data >> 2) & 1;
    uint8_t d3 = (data >> 1) & 1;
    uint8_t d4 = data & 1;

    uint8_t p1 = d1 ^ d2 ^ d4;
    uint8_t p2 = d1 ^ d3 ^ d4;
    uint8_t p3 = d2 ^ d3 ^ d4;


    return (p1 << 6) | (p2 << 5) | (d1 << 4) | (p3 << 3) | (d2 << 2) | (d3 << 1) | d4;
}

//4 bits nachricht 3 error correction
uint8_t hamming_decode(uint8_t codeword, bool *error_corrected) {
    uint8_t p1 = (codeword >> 6) & 1;
    uint8_t p2 = (codeword >> 5) & 1;
    uint8_t d1 = (codeword >> 4) & 1;
    uint8_t p3 = (codeword >> 3) & 1;
    uint8_t d2 = (codeword >> 2) & 1;
    uint8_t d3 = (codeword >> 1) & 1;
    uint8_t d4 = codeword & 1;

    uint8_t s1 = p1 ^ d1 ^ d2 ^ d4;
    uint8_t s2 = p2 ^ d1 ^ d3 ^ d4;
    uint8_t s3 = p3 ^ d2 ^ d3 ^ d4;

    uint8_t error_position = (s1 << 2) | (s2 << 1) | s3;

    *error_corrected = false;
    if (error_position != 0) {
        // If there's an error, flip the bit at the error position
        codeword ^= (1 << (7 - error_position));
        *error_corrected = true;
    }

    return (d1 << 3) | (d2 << 2) | (d3 << 1) | d4;
}

int hamming_check_and_correct(char *data, int len) {
    int corrections = 0;
    bool error_corrected;

    for (int i = 0; i < len; i++) {
        uint8_t original_byte = data[i];
        uint8_t decoded_data = hamming_decode(original_byte, &error_corrected);
        data[i] = decoded_data;

        if (error_corrected) {
            corrections++;
        }
    }
    return corrections;
}

// Display decoded data as UTF-8
void display_received_data(const char *data) {
    printf("Decoded Data: %s\n", data);
}

// Process DNS packet to extract data
void process_dns_packet(const u_char *packet, int packet_len) {
    struct ip *ip_hdr = (struct ip *)(packet);
    int ip_header_len = ip_hdr->ip_hl * 4;
    struct udphdr *udp_hdr = (struct udphdr *)(packet + ip_header_len);
    char *dns_data = (char *)(packet + ip_header_len + sizeof(struct udphdr));

    // Extract DNS query Geht gerade noch davon aus dass es immer base 64 encodet ist
    char base64_encoded[BUFFER_SIZE];
    snprintf(base64_encoded, sizeof(base64_encoded), "%s", dns_data);

    char decoded_data[BUFFER_SIZE];
    base64_decode(base64_encoded, decoded_data);

    int corrections = hamming_check_and_correct(decoded_data, strlen(decoded_data));

    display_received_data(decoded_data);

    if (corrections == 0) {
        printf("Return IP: %s (Data successfully received)\n", SUCCESS_IP);
    } else {
        printf("Return IP: %s (Errors detected)\n", ERROR_IP);
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    process_dns_packet(packet, header->len);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 2;
    }

    struct bpf_program fp;
    char filter_exp[] = "udp port 53";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter: %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    printf("Listening for DNS packets...\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
