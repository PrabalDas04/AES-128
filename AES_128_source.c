#include <stdio.h>
//#include <stdlib.h>
#include "AES_128.h"

////////////////////////////////////////// global variables ////////////////////////////////
// round constants for each round (globally defined)
unsigned char round_constants[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// MixColumn matrix
unsigned char mix_columns_matrix[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

// Inverse MixColumns Matrix
unsigned char inv_mix_columns_matrix[4][4] = {
    {0x0e, 0x0b, 0x0d, 0x09},
    {0x09, 0x0e, 0x0b, 0x0d},
    {0x0d, 0x09, 0x0e, 0x0b},
    {0x0b, 0x0d, 0x09, 0x0e}
};
///////////////////////// Key Scheduling Algorithm and key structure /////////////////////////////////

//Function to rotate bytes in a Word
void RotWord(Word * temp)
{
    unsigned char t = temp->bytes[0];
    temp->bytes[0] = temp->bytes[1];
    temp->bytes[1] = temp->bytes[2];
    temp->bytes[2] = temp->bytes[3];
    temp->bytes[3] = t;
}

// function for xor-ing two words
Word * xorWords(const Word *a, const Word *b, Word *result)
{
    for (int i = 0; i < 4; i++)
    {
        result->bytes[i] = a->bytes[i] ^ b->bytes[i];
    }
    return result;
}

// Display function for KeyWords
void KeyDisplayFunction(Word * KeyWords[])
{
    int i, j;
    for (j = 0; j < 44; j++)
    {
        printf("KeyWords %d:\n", j);
        for (i = 0; i < 4; i++)
            printf("\t0x%02X\n", KeyWords[j]->bytes[i]);
    }
}

// key expansion function, which stores all key words in array KeyWords
Word ** KeyExpansionFunction(Word * KeyWords[])
{
    int i = 4, j;
    Word temp;
    
    while(i < 44)
    {
    	// Copy the previous word
    	for (j = 0; j < 4; j++)
    	{
        	temp.bytes[j] = KeyWords[i-1]->bytes[j];
    	}
    	
    	if(i%4 == 0)
    	{
    		// Rotation function
            	RotWord(&temp);
    
    		// Substitution (S-box)
    		for(j = 0; j < 4; j++)
    			temp.bytes[j] = s_box[(temp.bytes[j] >> 4) & 0x0F][temp.bytes[j] & 0x0F];
    
    		// Round Constant
    		temp.bytes[0] = temp.bytes[0] ^ round_constants[(i/4)-1];  // bit wise xor and applicable for one byte
    	}
    	// Xor of two words
    	KeyWords[i] = xorWords(KeyWords[i-4], &temp, KeyWords[i]);
    	i++;
    }

    //KeyDisplayFunction(KeyWords);
    return KeyWords;
}

//////////////////////////////// Round Functions ///////////////////////////////

// Function gives a * 0x02
// if (a >> 7) & 1 = 1 i.e. msb is 1 then reduction happened o/w just left shift
unsigned char xtime(unsigned char a) 
{
    return (a << 1) ^ (((a >> 7) & 1) * 0x1b);
}

// Display function which prints the state matrix
void StateDisplayFunction(unsigned char state[4][4]) 
{
    int j, i;
    for (i = 0; i < 4; i++) 
    {
        for (j = 0; j < 4; j++)
            printf(" 0x%02X  ", state[i][j]);
        printf("\n");
    }
}

// Function for Byte Multiplication
unsigned char ByteMultiply(unsigned char a, unsigned char b) 
{
    unsigned char result = 0x00, xtemp = a;
    for (int i = 0; i < 8; i++) 
    {
        // checks if i-th bit is 1 or 0
        if ((b >> i) & 1) 
        {
            result ^= xtemp;
        }
        xtemp = xtime(xtemp);
    }
    return result;
}

// Function for ShiftRows operation
void ShiftRows(unsigned char state[4][4]) 
{
    unsigned char temp;
    for (int i = 1; i < 4; i++) 
    {
        for (int j = 0; j < i; j++) 
        {
            temp = state[i][0];
            for (int k = 0; k < 3; k++) 
            {
                state[i][k] = state[i][k + 1];
            }
            state[i][3] = temp;
        }
    }
}

// Function for Inverse ShiftRows operation
void InvShiftRows(unsigned char state[4][4]) 
{
    unsigned char temp;
    for (int i = 1; i < 4; i++) 
    {
        for (int j = 0; j < i; j++) 
        {
            temp = state[i][3];
            for (int k = 3; k > 0; k--) 
            {
                state[i][k] = state[i][k - 1];
            }
            state[i][0] = temp;
        }
    }
}

// Function for MixColumns operation
void MixColumns(unsigned char state[4][4]) 
{
    unsigned char temp_state[4][4] = {0}; // Temporary state to hold the result

    for (int j = 0; j < 4; j++) 
    {
        for (int i = 0; i < 4; i++) 
        {
            temp_state[i][j] = 
                ByteMultiply(mix_columns_matrix[i][0], state[0][j]) ^
                ByteMultiply(mix_columns_matrix[i][1], state[1][j]) ^
                ByteMultiply(mix_columns_matrix[i][2], state[2][j]) ^
                ByteMultiply(mix_columns_matrix[i][3], state[3][j]);
        }
    }

    // Copy the result back to the original state
    for (int i = 0; i < 4; i++) 
    {
        for (int j = 0; j < 4; j++) 
        {
            state[i][j] = temp_state[i][j];
        }
    }
}

// Function for Inverse MixColumns operation
void InvMixColumns(unsigned char state[4][4]) 
{
    unsigned char temp_state[4][4] = {0}; // Temporary state to hold the result

    for (int j = 0; j < 4; j++) 
    {
        for (int i = 0; i < 4; i++) 
        {
            temp_state[i][j] = 
                ByteMultiply(inv_mix_columns_matrix[i][0], state[0][j]) ^
                ByteMultiply(inv_mix_columns_matrix[i][1], state[1][j]) ^
                ByteMultiply(inv_mix_columns_matrix[i][2], state[2][j]) ^
                ByteMultiply(inv_mix_columns_matrix[i][3], state[3][j]);
        }
    }

    // Copy the result back to the original state
    for (int i = 0; i < 4; i++) 
    {
        for (int j = 0; j < 4; j++) 
        {
            state[i][j] = temp_state[i][j];
        }
    }
}


// function for S-Box operation
void SBox(unsigned char state[4][4])
{
    int i, j;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++) 
        {
            state[i][j] = s_box[(state[i][j] >> 4) & 0x0F][state[i][j] & 0x0F];
        }
    }
}

// function for Inverse S-Box operation
void InvSBox(unsigned char state[4][4])
{
    int i, j;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++) 
        {
            state[i][j] = inv_sbox[(state[i][j] >> 4) & 0x0F][state[i][j] & 0x0F];
        }
    }
}

////////////////////////////////////////// Encryption Function ////////////////////////////
// AES encryption function, takes input plain text, cipher text(only space variable for storing cipher text)
// and set of all keywords generated from key generation algorithm
void Encryption(unsigned char msg[4][4], unsigned char cipher[4][4], Word * KeyWords[])
{
    unsigned char state[4][4];
    int  i, j, round;
    
    // Copy the result back to the original state
    for (i = 0; i < 4; i++) 
    {
        for (j = 0; j < 4; j++) 
        {
            state[i][j] = msg[i][j];
        }
    }
    // Add Round Key
    for (i = 0; i < 4; i++) 
    {
        for (j = 0; j < 4; j++) 
        {
            state[i][j] = state[i][j] ^ KeyWords[j]->bytes[i];
        }
    }

    for(round = 1; round < 10; round++)
    {
        // Substitution (S-box)
        SBox(state);

        // ShiftRows
        ShiftRows(state);
        
        // MixColumns
        MixColumns(state);

        // Add Round Key
        for (i = 0; i < 4; i++) 
        {
            for (j = 0; j < 4; j++) 
            {
                state[i][j] = state[i][j] ^ KeyWords[4*round + j]->bytes[i];
            }
        }
    }

    // last round(10th)
    SBox(state);
    ShiftRows(state);
    // Add Round Key
    for (i = 0; i < 4; i++) 
    {
        for (j = 0; j < 4; j++) 
        {
            state[i][j] = state[i][j] ^ KeyWords[40 + j]->bytes[i];
        }
    }

    // Copy the final result back to the cipher text space
    for (i = 0; i < 4; i++) 
    {
        for (j = 0; j < 4; j++) 
        {
            cipher[i][j] = state[i][j];
        }
    }
}

///////////////////////////////////////////////// Decryption Function /////////////////////////////
// Decryption function
void Decryption(unsigned char cipher[4][4], unsigned char msg[4][4], Word * KeyWords[])
{
    unsigned char state[4][4];
    int  i, j, round = 9;
    
    // Copy the result back to the original state
    for (i = 0; i < 4; i++) 
    {
        for (j = 0; j < 4; j++) 
        {
            state[i][j] = cipher[i][j];
        }
    }
    // Add Round Key
    for (i = 0; i < 4; i++) 
        {
            for (j = 0; j < 4; j++) 
            {
                state[i][j] = state[i][j] ^ KeyWords[40 + j]->bytes[i];
            }
        }
    
    for(round = 9; round > 0; round--)
    {
        // Inverse ShiftRows
        InvShiftRows(state);

		// Inverse Substitution (S-box)
        InvSBox(state);

        // Add Round Key
        for (i = 0; i < 4; i++) 
        {
            for (j = 0; j < 4; j++) 
            {
                state[i][j] = state[i][j] ^ KeyWords[4*round + j]->bytes[i];
            }
        }
        // Inverse Mixcolumn
        InvMixColumns(state);
    }

    // last round(10th)
    InvShiftRows(state);
    InvSBox(state);

    // Add Round Key
    for (i = 0; i < 4; i++) 
    {
        for (j = 0; j < 4; j++) 
        {
            state[i][j] = state[i][j] ^ KeyWords[j]->bytes[i];
        }
    }

    // Copy the final result back to the cipher text space
    for (i = 0; i < 4; i++) 
    {
        for (j = 0; j < 4; j++) 
        {
            msg[i][j] = state[i][j];
        }
    }
}