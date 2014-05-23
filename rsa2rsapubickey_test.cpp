#include <stdio.h>
#include "rsa/rsa.h"
#include "rsa/x509.h"
#include "mincrypt/rsa.h"

extern int RSA_to_RSAPublicKey(rsa_context *rsa, RSAPublicKey *pkey);

//32 bit limb
uint32_t mpi_get_word(mpi * x){
    // 4 bytes
	if (mpi_size(x) > 4)
		return 0xffffffff;
	else
        return x->p[0];
	//return 0;   
}


/* Convert OpenSSL RSA public key to android pre-computed RSAPublicKey format */

int RSA_to_RSAPublicKey(rsa_context *rsa, RSAPublicKey *pkey)
{
    int ret = 1;
    unsigned int i;
    mpi r32;
    mpi rr;
    mpi r;
    mpi rem;
    mpi n;
    mpi n0inv;
    mpi divid;

    mpi_init(&r32);
    mpi_init(&rr);
    mpi_init(&r);
    mpi_init(&rem);
    mpi_init(&n);
    mpi_init(&n0inv);

    
    if(rsa->len != RSANUMBYTES){
       ret = 0;
       goto out;
    }

    mpi_set_bit(&r32, 32, 1);
    mpi_copy(&n, &rsa->N);
    
    //mpi_lset(&r, 1);
    //mpi_shift_l(&r, rsa->N.n *32);
    mpi_set_bit(&r, RSANUMWORDS * 32, 1);

    mpi_lset(&rr, 1 );
    mpi_shift_l(&rr, rsa->N.n * 2 * 32);    
    mpi_mod_mpi(&rr, &rr, &rsa->N);
    
    mpi_div_mpi(NULL, &rem ,&n, &r32);
    mpi_inv_mod(&n0inv, &rem, &r32);

    pkey->len = RSANUMWORDS;
    pkey->n0inv = 0 - mpi_get_word(&n0inv);

    for (i = 0; i < RSANUMWORDS; i++) {
        mpi_div_mpi(&divid, &rem, &rr, &r32);
        pkey->rr[i] = mpi_get_word(&rem);
        mpi_copy(&rr, &divid);
        mpi_div_mpi(&divid, &rem, &n, &r32);
        pkey->n[i] = mpi_get_word(&rem);
        mpi_copy(&n, &divid);
    }
    pkey->exponent = mpi_get_word(&rsa->E);
        
out:
    mpi_free(&r32);
    mpi_free(&rr);
    mpi_free(&r);
    mpi_free(&rem);
    mpi_free(&n);
    mpi_free(&n0inv);
    
    return ret;
}

static void dumpKey(RSAPublicKey *pkey){
       int version=1;
       if(pkey->exponent == 3){
           version = 1;
       }else if(pkey->exponent == 65537){
           version = 2;
       }else{
          printf("unknown public key exponent\n");
          return; 
       }

       if(pkey->len != RSANUMWORDS){
          printf("unknown key length\n");
          return;
       }

       if(version > 1){
           printf("v%d ",version);
       }

       printf("{%d,", RSANUMWORDS);
       printf("0x%x,{", pkey->n0inv);

       for(int i = 0; i < RSANUMWORDS; i++){
           printf("%u", pkey->n[i]);
           if(i < RSANUMWORDS - 1)
             printf(",");
       }

       printf("},{");

       for(int i = 0; i < RSANUMWORDS; i++){
           printf("%u", pkey->rr[i]);
           if(i < RSANUMWORDS - 1)
             printf(",");           
       }

       printf("}}\n");
}

int main(int argc, char **argv){
   if(argc != 2){
       printf("Usage: rsapublickey_test pem_public_key_file");
       return -1;
   }
   
   FILE *file = fopen(argv[1], "r");
   if(file == NULL){
       printf("cannot open %s\n", argv[1]);
       return -1;
   }

   char envval[1024]={0};
   int  envvallen=sizeof(envval);
   int  readed = 0;
   RSAPublicKey pubkey;
   rsa_context rsa;      
   
   fseek(file, 0, SEEK_END);
   int size = ftell(file);
   fseek(file, 0, SEEK_SET);
   
   if(size > envvallen){
       printf("file size too large\n");
       goto END;
   }
   
   readed = fread(envval, 1, size, file);
   if(readed != size){
       printf("read error %d, size = %d\n", readed, size);
       goto END;
   }
    
   rsa_init(&rsa, RSA_PKCS_V15, 0);
   if(x509parse_public_key(&rsa, (unsigned char*)envval, envvallen) != 0){
       rsa_free(&rsa);
       return NULL;
   }

   RSA_to_RSAPublicKey(&rsa, &pubkey);
   rsa_free(&rsa);   
   
   dumpKey(&pubkey);   
END:   
   fclose(file);
  
   
}