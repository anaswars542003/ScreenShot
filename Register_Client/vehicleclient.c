#include<stdio.h>
#include<time.h>
#include<string.h>
#include"include/miracl.h"
#include<arpa/inet.h>
#include<unistd.h>
#include<stdlib.h>
#include<hiredis/hiredis.h>

#define HOST "127.0.0.1"
#define PORT 12346
#define P "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define A "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
#define B "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
#define G_X "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define G_Y "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define N "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"

void gen_priv_key(miracl* mip, big sk, big q);
void register_vehicle();


void register_vehicle(miracl* mip)
{
    mip->IOBASE = 16;
    big sk = mirvar(0);
    big q = mirvar(0);
    big a = mirvar(0);
    big b = mirvar(0);
    epoint* p = epoint_init();
    epoint* pk = epoint_init();
    unsigned char pk_raw_bytes[64];
    memset(pk_raw_bytes, 0, 64);
    unsigned char cid[32];
    unsigned char apk_as_bytes[128];

    int sock;
    struct sockaddr_in server_addr;

    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, HOST, &server_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to the server failed");
        close(sock);
        exit(EXIT_FAILURE);
    }


    // Send the 64-byte string
    

    // Close the socket


    cinstr(a, A);
    cinstr(b, B);
    cinstr(q, P);
    ecurve_init(a,b,q,MR_PROJECTIVE);
    cinstr(a, G_X);
    cinstr(b, G_Y);
    epoint_set(a,b,1,p);
    cinstr(q, N);                    //curve initialisation and generator point initialisation
    
    gen_priv_key(mip, sk, q);
    cotnum(sk,stdout);
    ecurve_mult(sk, p, pk);         //generate private key and calculate public key

    epoint_get(pk, a, b);
    big_to_bytes(32, a, pk_raw_bytes, TRUE);
    big_to_bytes(32, b, pk_raw_bytes + 32, TRUE);  //checked correct points

    

    if (send(sock, pk_raw_bytes, 64, 0) < 0) {
        perror("Failed to send data");
    }

    printf("\npk_x: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",pk_raw_bytes[i]);
    printf("\npk_y: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",(pk_raw_bytes+32)[i]);
    
    recv(sock, cid, 32, 0);

    printf("\nhash: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",cid[i]);


    recv(sock, apk_as_bytes, 128, 0);

    printf("\nc1_x: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",apk_as_bytes[i]);
    printf("\nc1_y: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",(apk_as_bytes+32)[i]);
    printf("\nc2_x: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",(apk_as_bytes+64)[i]);
    printf("\nc2_y: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",(apk_as_bytes+96)[i]);


    //write to apk.keys
    FILE* f = fopen("apk.key","wb");
    char sk_str[32];
    int i_ind = 1;
    big_to_bytes(32, sk, sk_str, TRUE);
    fwrite(sk_str,32,1,f);
    fwrite(apk_as_bytes,128,1,f);
    fwrite(cid,32, 1, f);
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        i_ind = htole32(i_ind);  // Convert to little-endian if system is big-endian
    #endif
    fwrite(&i_ind, 4, 1, f);
    

    fclose(f);
    //written to apk.keys
    close(sock);
    epoint_free(p);
    epoint_free(pk);
    mirkill(sk);
    mirkill(q);
    mirkill(a);
    mirkill(b);
}

void gen_priv_key(miracl* mip, big sk, big q)
{   
    csprng rng;
    long tod;
    char raw[30] = "09ojnsdj19hsdu213-911wda";
    int rawlen = 30;
    tod = time(NULL);
    strong_init(&rng, rawlen, raw, tod);
    strong_bigrand(&rng, q, sk);
    strong_kill(&rng);
}

int main()
{
    miracl* mip = mirsys(256,50);
    register_vehicle(mip);
    mirexit();
}
