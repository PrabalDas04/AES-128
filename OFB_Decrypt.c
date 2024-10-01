#include <stdio.h>
#include <stdlib.h>
#include "AES_128.h"
#include <string.h>

// Decryption using OFB mode
void OFBDecryption(FILE * filePointer, Word * KeyWords[])
{
	unsigned char buffer[16], state[4][4], msg[4][4]= {
        {0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00}, 
        {0x00, 0x00, 0x00, 0x00}, 
        {0x00, 0x00, 0x00, 0x00}};
    int i, j, count;
    
	// "output_ofb.txt" file is opened in read mode which contains cipher text
	filePointer = fopen("output_ofb.txt", "r");
	// error checking in file opening
	if (filePointer == NULL)
	{
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }
    
    // "output1_ofb.txt" file is opened in write mode, which will contain plain text
    FILE * OutfilePointer = fopen("output1_ofb.txt","w");
    // error checking in file opening
	if (OutfilePointer == NULL)
	{
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }
    
    char temp[16];
    // temp is storing the IV from filePointer
    fread(temp, 1, 16, filePointer);
	
	while ((count = fread(buffer, 1, 16, filePointer)) == 16)
	{
        
        // creating state matrix from 1D array buffer
		for (i = 0; i < 4; ++i)
		{
            for (j = 0; j < 4; ++j)
            {
                state[i][j] =  temp[i * 4 + j];
            }
        }
        
        Encryption(state, msg, KeyWords);
        
        int index = 0;
        for (i = 0; i < 4; ++i)
		{
            for (j = 0; j < 4; ++j)
            {
                temp[index] = msg[i][j];
                fprintf(OutfilePointer,"%c",temp[index] ^ buffer[index]);
                index++;
            }  
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
    OFBDecryption(filePointer, KeyWords);

    //Free allocated memory
    for (i = 0; i < 5; i++)
    {
		free(KeyWords[i]);
    }

    return 0;
}



