#include"miracl.h"
#ifndef SOK_H
#define SOK_H


typedef char signature_t[65]; 

//signature_t is in the format z [32] , Rx[32], Ry[32]

void gen_proof( big q, epoint* p, big sk, char* c, char* msg,  size_t msg_size, int t, signature_t sig);
BOOL verify_proof( big q, epoint* p, char* c, char* msg, size_t msg_size, int t, signature_t sig);
BOOL batch_verify_proof(big q, epoint* p, int n, char* c[], char* msg[], size_t msg_size[], int t[], signature_t sig[] );


#endif
