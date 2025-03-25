#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include<string.h>
#include<time.h>
#include<hiredis/hiredis.h>
#include"sok.h"
#include"oer.h"
#include"CertificateBase.h"
#include <curl/curl.h>

#define OER_SIZE 128
#define API_URL "http://localhost:5000/get_cert"

// Struct to store the response data
struct MemoryStruct {
    unsigned char *memory;
    size_t size;
};

#define a_str  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
#define b_str  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
#define q_str  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define x_str  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define y_str  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define n_str  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"

#define PORT 12345
#define BUFFER_SIZE 1024


void create_udp_socket(int *sock, struct sockaddr_in *server_addr);
void print_hex(const uint8_t *data, size_t size);
size_t udp_receive(int sock, char* buffer) ;
size_t parse_msg(char* encoded_msg,char* msg, char* c,signature_t sig);
void retriev_apk(unsigned char* cid, unsigned char* c);
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp); 



int main() {
    miracl* mip = mirsys(100,16);
    mip->IOBASE = 16;
    big a = mirvar(0);
    big b = mirvar(0);
    big q = mirvar(0);

    cinstr(a, a_str);
    cinstr(b, b_str);
    cinstr(q, q_str);
    ecurve_init(a,b,q,MR_PROJECTIVE);
    cinstr(a, x_str);
    cinstr(b, y_str);
    epoint* p = epoint_init();
    int n = epoint_set(a,b,1,p);
    cinstr(q, n_str);

    unsigned char msg[200];
    size_t msg_size;
    char c[128];
    unsigned char cid[32];
    unsigned char encoded_msg[300];
    size_t encoded_msg_size;
    signature_t sig;
    int t = 0;
    int sock;
    struct sockaddr_in server_addr;

    create_udp_socket(&sock, &server_addr);

    while(1){
        encoded_msg_size = udp_receive(sock, encoded_msg);
        msg_size = parse_msg(encoded_msg, msg, cid, sig);
        printf("Message received from id : \n");
        print_hex(cid, 32);
        printf("Received message contents : \n");
        print_hex(msg, msg_size);
        retriev_apk(cid, c);
        n = verify_proof(q, p, c, msg, msg_size, t, sig);
        printf("\nReceived message ");
        n == 1 ? printf("Authenticated \n") : printf("Rejected\n");
        printf("\n\n\n");
    }

    close(sock);
    return 0;
}



// Function to create and initialize a UDP socket
void create_udp_socket(int *sock, struct sockaddr_in *server_addr) {
    *sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = INADDR_ANY;
    server_addr->sin_port = htons(PORT);

    if (bind(*sock, (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
}

void print_hex(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
        else if ((i + 1) % 4 == 0)
            printf(" ");
    }
    printf("\n");
}

// Function to receive a UDP message
size_t udp_receive(int sock, char* buffer) {
    
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);


    int len = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &addr_len);
    if (len < 0) {
        perror("Receive failed");
        exit(EXIT_FAILURE);
    }
    
}

size_t parse_msg(char* encoded_msg,char* msg, char* cid,signature_t sig){
    struct oer_send_data_send_data_t decoded_message;
    ssize_t decoded_size;
    decoded_size = oer_send_data_send_data_decode(&decoded_message, encoded_msg, 219);
    
    memcpy(msg, decoded_message.content.value.signedData.data.buf, 120);
    memcpy(cid, decoded_message.content.value.signedData.signer.buf, 32);
    memcpy(sig,  decoded_message.content.value.signedData.signature.buf, 65);
    return 120;
}

void retriev_apk(unsigned char* cid, unsigned char* c){
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1);  // Store directly in provided buffer
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    
    if (curl) {
        char post_fields[200];  // JSON payload
        char hex_cid[65];  

        for (int i = 0; i < 32; i++) {
            sprintf(&hex_cid[i*2], "%02x", cid[i]);
        }
        hex_cid[64] = '\0';
        snprintf(post_fields, sizeof(post_fields), "{\"cid\":\"%s\"}", hex_cid);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, API_URL);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            memset(c, 0, OER_SIZE);  // Clear buffer on failure
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    struct oer_certificate_base_certificate_base_t decoded_cert;
    size_t decoded_size = oer_certificate_base_certificate_base_decode(&decoded_cert, chunk.memory, chunk.size);
    if (decoded_size < 0) {
        printf("Decoding failed with error code: %zd\n", decoded_size);
        return ;
    }

    memcpy(c, decoded_cert.tobeSignedData.anonymousPK.buf, 128);
}


static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}
