#include <stdio.h>
#include <stdlib.h>
#include "AES_128.h"
#include <string.h>

// Decryption using ECB mode
void ECBDecryption(FILE * filePointer, Word * KeyWords[])
{
	// Buffer to store the read data
	unsigned char buffer[16], state[4][4], msg[4][4]= {
        {0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00}, 
        {0x00, 0x00, 0x00, 0x00}, 
        {0x00, 0x00, 0x00, 0x00}};
    int i, j;
    
	// "output.txt" file is opened in read mode
	filePointer = fopen("output_ecb.txt", "r");
	// error checking in file opening
	if (filePointer == NULL)
	{
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }
    
    // "output1.txt" file is opened in write mode
    FILE * OutfilePointer = fopen("output1_ecb.txt","w");
    if (OutfilePointer == NULL)
	{
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }
    
	while (fread(buffer, 1, 16, filePointer) > 0)
	{
        // creating state matrix from 1D array buffer
		for (i = 0; i < 4; ++i)
		{
            for (j = 0; j < 4; ++j)
            {
                state[i][j] =  buffer[i * 4 + j];
            }
        }
        
        Decryption(state, msg, KeyWords);

        // output file print
		for (i = 0; i < 4; ++i)
		{
            for (j = 0; j < 4; ++j)
                fprintf(OutfilePointer,"%c",msg[i][j]);
        }  

        // each time fread coping to buffer, we need to initialize
		memset(buffer, '\0', sizeof(buffer)); 
	}
    // closing file pointers
	fclose(filePointer);
    fclose(OutfilePointer);
}


int main()
{
    ///////////////////////////////////// Key Generation part /////////////////////////

    Word * KeyWords[44]; // Array of 44 pointers to Word structures, stores all the key words
    int i, j;

    // Memory allocation to each word
    for (i = 0; i < 44; i++)
    {
        KeyWords[i] = (Word*)malloc(sizeof(Word));
        if (KeyWords[i] == NULL)
        {
            printf("Error 1: memory allocation failed.");
            return 1; // indicate error
        }
    }

    // User input in hex for master key
    unsigned char sample_values[4][4] = {
        {0x00, 0x01, 0x02, 0x03},
        {0x04, 0x05, 0x06, 0x07},
        {0x08, 0x09, 0x0a, 0x0b},
        {0x0c, 0x0d, 0x0e, 0x0f}};
    
    // keys are allocating to KeyWords's bytes
    for (j = 0; j < 4; j++)
    {
        //printf("Enter 4 bytes in hex for KeyWords %d: ", j);
        for (i = 0; i < 4; i++)
            //scanf("%hhx", &KeyWords[j]->bytes[i]);  // each 'KeyWords' is a word and 'bytes' is its component
            KeyWords[j]->bytes[i] = sample_values[j][i];
    } 
    
    // all keywords are stored in "KeyWords", which are generated from 'KeyExpansionFunction'
    KeyExpansionFunction(KeyWords);

    //////////////////////////////////////////// Decryption part /////////////////////////////

    // File pointer
	FILE* filePointer;
    ECBDecryption(filePointer, KeyWords);

    //Free allocated memory
     for (i = 0; i < 5; i++)
     {
	 	free(KeyWords[i]);
     }

    return 0;
}
