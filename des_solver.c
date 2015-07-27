#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <openssl/crypto.h>
#include <string.h>

int break_loop = 0;

static const unsigned char odd_parity[256] = {
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110,
    110,
    112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127,
    127,
    128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143,
    143,
    145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158,
    158,
    161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174,
    174,
    176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191,
    191,
    193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206,
    206,
    208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223,
    223,
    224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239,
    239,
    241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254,
    254
};

void print_DES_cblock(char *head, DES_cblock *key){
  printf("%s", head);
  for(int i=0;i<sizeof(DES_cblock);i++){
    printf("%02x ",((unsigned char *)key)[i]);
  }
  printf("\n");
  return;
}

int des_solver(DES_cblock *result_key, int stage, DES_cblock *enc_m, DES_cblock *dec_m){
  DES_cblock stage_key;

  int local_flag = 0;
#ifdef _OPENMP
#pragma omp atomic read
#endif
    local_flag = break_loop;
    
    if(local_flag == 1) {
      return -1;
    }

  memcpy(&stage_key, result_key,sizeof(DES_cblock));
  int i;

  for(i=0;i<=0xfe;i+=2)
  {
    ((unsigned char *)stage_key)[stage] = i;
    // set parity
    ((unsigned char *)stage_key)[stage] = odd_parity[stage_key[stage]];

    if(stage < (sizeof(DES_cblock)-1)){
      int res = des_solver(&stage_key, stage + 1, enc_m, dec_m);
      if(res == 0){
	break;
      }
    }
    else{
      // solve key
      DES_key_schedule schedule = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
      DES_cblock output = {0,0,0,0,0,0,0,0};
      DES_set_key_checked(&stage_key, &schedule);
      DES_ecb_encrypt(enc_m, &output, &schedule, DES_DECRYPT);
      // 鍵を見つけたなら終了
      if(memcmp(&output, dec_m, sizeof(DES_cblock)) == 0){
	break;
      }
    }
  }
  if(i > 0xfe){
    // key not found
    return -1;
  }
  // key found
  memcpy(result_key, &stage_key, sizeof(DES_cblock));
  return 0;
}

int main(void){
  DES_cblock mes = {0,0,0,0,0,0,0,0};
  DES_cblock correct_key = {1,1,1,1,1,1,1,1};  // for test
  DES_cblock enc_mes;
  DES_cblock key = {0,0,0,0,0,0,0,0};
  DES_key_schedule schedule = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

  strcpy(mes, "hello");
  memset(&schedule,0,sizeof(DES_key_schedule));

  // make chiper text
  DES_random_key(&correct_key);
  DES_set_key_checked(&correct_key, &schedule);
  DES_ecb_encrypt(&mes, &enc_mes, &schedule, DES_ENCRYPT);

  print_DES_cblock("message: ", &mes);
  print_DES_cblock("Enc Key: ", &correct_key);
  print_DES_cblock("chiper text: ", &enc_mes);

  // 探索開始
#ifdef _OPENMP
#pragma omp parallel for
#endif
  for(int i=0;i<=0xfe;i+=2){
    int local_flag;
#ifdef _OPENMP
#pragma omp atomic read
#endif
    local_flag = break_loop;
    
    if(local_flag == 1) {
      //      printf("local_flag = %d\n",local_flag);
      continue;
    }
    
    ((unsigned char *)key)[0] = i;
    // set parity
    ((unsigned char *)key)[0] = odd_parity[key[0]];
    
    int res = des_solver(&key, 1, &enc_mes, &mes);

/* #ifdef _OPENMP */
/* #pragma omp cancel for if(res) */
/* #endif */

    if(res == 0){
#ifdef _OPENMP
#pragma omp atomic write
#endif
      break_loop = 1;
      //      printf("res = %d\n",res);
      //      printf("break_loop = %d\n",break_loop);
    }
    
  }

    //  printf("end\n");
  print_DES_cblock("solve Key: ", &key);
  return 0;
}
