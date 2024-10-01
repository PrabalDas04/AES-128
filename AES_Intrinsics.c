#include <stdio.h>
#include <wmmintrin.h>

// display function
void print_state(__m128i state) {
    unsigned char buffer[16];
    _mm_storeu_si128((__m128i*)buffer, state);
    for (int i = 0; i < 16; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}

// AES-128 key expansion helper function
__m128i  AES_128_ASSIST(__m128i key,__m128i temp) {
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));// shifth then xor
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));//out put ->  key[0], key[0]^key[1], key[0]^key[1]^key[2], key[0]^key[1]^key[2]^key[3]
            key = _mm_xor_si128(key, _mm_shuffle_epi32(temp, _MM_SHUFFLE(3, 3, 3, 3)));//each key[0], key[1], key[2], key[3] are all xor with temp[3] 
    return key;
}

// all the round key generation
void AES_128_Key_Expansion (const unsigned char *userkey,unsigned char *key)
{
	__m128i temp1, temp2;
	__m128i *Key_Schedule = (__m128i*)key;

	temp1 = _mm_loadu_si128((__m128i*)userkey);
	Key_Schedule[0] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[1] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[2] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[3] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[4] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[5] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[6] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[7] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[8] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[9] = temp1;

	temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[10] = temp1;
}



// AES-128 encryption function
__m128i aes128_encrypt(__m128i plaintext, const unsigned char *userkey) {
    // Buffer to store the expanded key schedule (11 rounds, each 16 bytes)
    unsigned char key_schedule[176];

    // Perform AES-128 key expansion
    AES_128_Key_Expansion(userkey, key_schedule);
    
    // Initial AddRoundKey
    __m128i state = _mm_xor_si128(plaintext, ((__m128i*)key_schedule)[0]);

    // Rounds 1 to 9
    for (int i = 1; i < 10; i++) {
        state = _mm_aesenc_si128(state, ((__m128i*)key_schedule)[i]);
    }

    // Final round (without MixColumns)
    state = _mm_aesenclast_si128(state, ((__m128i*)key_schedule)[10]);

    return state;
}


// AES-128 decryption function
__m128i aes128_decrypt(__m128i ciphertext, const unsigned char *userkey) {
     // Buffer to store the expanded key schedule (11 rounds, each 16 bytes)
    unsigned char key_schedule[176];

    // Perform AES-128 key expansion
    AES_128_Key_Expansion(userkey, key_schedule);

    __m128i state = ciphertext;

    // Perform initial AddRoundKey
    state = _mm_xor_si128(state, ((__m128i*)key_schedule)[10]);

    // AES rounds (1 to 9)
    for (int i = 9; i >= 1; i--) {
        state = _mm_aesdec_si128(state, ((__m128i*)key_schedule)[i]);
        state = _mm_xor_si128(state, ((__m128i*)key_schedule)[i]);   //InvMixColumn(ShiftRows(SubByte(state)))
        __m128i temp = _mm_aesimc_si128 (((__m128i*)key_schedule)[i]);  //InvMixColumns(key_schedule[i])
        state = _mm_xor_si128(state,temp);
    }

    // Final round (without MixColumns)
    state = _mm_aesdeclast_si128(state, ((__m128i*)key_schedule)[0]);

    return state;
}


int main() {
    // Example 128-bit AES key (16 bytes)
    unsigned char userkey[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    // plain text
    unsigned char plaintext_bytes[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    
    // Buffer to store the expanded key schedule (11 rounds, each 16 bytes)
    unsigned char expanded_key[176];

    // Perform AES-128 key expansion
    AES_128_Key_Expansion(userkey, expanded_key);

    // Print each round key
    printf("Expanded AES-128 Key Schedule:\n");
    for (int i = 0; i < 11; i++) {
        printf("Round %d: ", i);
        print_state(((__m128i*)expanded_key)[i]);
    }
    
    // Load plaintext into a __m128i register
    __m128i plaintext = _mm_loadu_si128((__m128i*)plaintext_bytes);

    // Perform AES-128 encryption
    __m128i ciphertext = aes128_encrypt(plaintext, userkey);

    // Print ciphertext
    printf("Ciphertext:\n");
    print_state(ciphertext);
    
    //Perform AES-128 decryption
    __m128i plain_text = aes128_decrypt(ciphertext,userkey);

    // Print ciphertext
    printf("Plaintext:\n");
    print_state(plain_text);
    return 0;
}






