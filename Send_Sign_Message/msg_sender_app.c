#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include<string.h>
#include<time.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <asm-generic/socket.h>
#include"sok.h"
#include"oer.h"

#define a_str  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
#define b_str  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
#define q_str  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define x_str  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define y_str  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define n_str  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
#define COUNTER_FILE "sends/counter.txt"
#define FILE_PREFIX "sends/data"


#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345

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

// Function to create and initialize a UDP socket
void create_udp_socket(int *sock, struct sockaddr_in *server_addr) {
    *sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(SERVER_PORT);
    server_addr->sin_addr.s_addr = inet_addr(SERVER_IP);
}

// Function to send a UDP message
void udp_send(int sock, struct sockaddr_in *server_addr, unsigned char *message, size_t msg_size) {



    if (sendto(sock, message, msg_size , 0, (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }
    printf("\n\nSent: message + signature\n");
    print_hex(message, msg_size);
}



void read_keys_init(big sk, char* c, epoint* c1, char* cid);
size_t read_message(char* msg);
size_t encode_message_and_sign(char* msg, size_t msg_size, char* c, signature_t sig, char* cid, uint8_t* encoded_data);
void send_enc_data(char* encoded_buffer,size_t encoded_msg_size);


int main() {
    int sock;
    struct sockaddr_in server_addr;

    create_udp_socket(&sock, &server_addr);
    miracl* mip = mirsys(100,16);
    mip->IOBASE = 16;

    
    signature_t sig;

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
    
    

    big sk = mirvar(0);
    epoint* c1 = epoint_init();
    unsigned char c[128];
    unsigned char cid[32];
    unsigned char encoded_buffer[300];
    
    char msg[200];
    size_t msg_size;
    size_t encoded_msg_size;
    int t = 0;
    
    //use a file with sk,c1_x,c1_y,c2_x,c2_y,cid stored in continuos byte stream. (read using "rb")
    
    read_keys_init(sk, c, c1, cid);    //read apk and public key part c1
    msg_size = read_message(msg);
    gen_proof(q, p, sk, c, msg, msg_size, t, sig);
    encoded_msg_size = encode_message_and_sign(msg, msg_size, c,  sig,cid, (uint8_t*)encoded_buffer);
    printf("\n\nsignature: ");
    for(int i = 0; i < 65; i++){

        if(i % 32 == 0)
            printf("\n");
        printf("%02x",(unsigned char)sig[i]);
    }




    udp_send(sock, &server_addr, encoded_buffer, encoded_msg_size);
    
    close(sock);
    return 0;
}

void read_keys_init(big sk, char* c, epoint* c1, char* cid)
{
    big a = mirvar(0);
    big b = mirvar(0);
    FILE* f = fopen("apk.key","rb");
    fread(c, 32, 1, f);
    bytes_to_big(32, c, sk);
    fread(c, 32, 4, f);
    bytes_to_big(32, c, a);
    bytes_to_big(32, c+32, b);
    int n = epoint_set(a,b,0,c1);
    fread(cid,32,1,f);


    fclose(f);
    mirkill(a);
    mirkill(b);
}


size_t read_message(char* msg) {
    
    ssize_t valread  = 120;

    srand(time(NULL));

    // Fill the buffer with random bytes (0-255)
    for (int i = 0; i < 120; i++) {
        msg[i] = rand() % 256;  // Generate a random byte
    }

    printf("\nTransmitted message in hex : \n");
    print_hex(msg,120); 

    return (size_t)valread;
}

size_t encode_message_and_sign(char* msg, size_t msg_size, char* c, signature_t sig, char* cid, uint8_t* encoded_data){
    struct oer_send_data_send_data_t message;
    struct oer_send_data_send_data_t decoded_message;
    size_t encoded_size = 300;
    ssize_t decoded_size;

    message.protocolVersion = 3;
    message.content.choice = oer_send_data_content_choice_signedData_e;
    memcpy(message.content.value.signedData.data.buf, msg, msg_size);
    memcpy(message.content.value.signedData.signer.buf, cid, 32);
    memcpy(message.content.value.signedData.signature.buf, sig, 65);

    encoded_size = oer_send_data_send_data_encode(encoded_data, encoded_size, &message);
    if(encoded_size < 0){
        printf("Error encoding SignedData message: %zd\n", encoded_size);
    }

    
    //print_hex(encoded_data, encoded_size);
    //printf("Size of encoded message : %ld", encoded_size);
    //decode_example(encoded_data, encoded_size);

    return encoded_size;
}   