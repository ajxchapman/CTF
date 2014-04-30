/*
Copyright (c) 2014 Alex J Chapman (dev at noxr.net)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifdef _BENCHMARK
#include <time.h>
#endif
#if defined(_DEBUG) || defined(_BENCHMARK)
#include <stdio.h>
#endif

#define B64LOOKUP(lookup, val) case lookup: c = val; break
#define INVALID 0x42

#define S_POINT1 0
#define S_POINT2 1
#define S_COMMA 2
#define S_MINUS1 3
#define S_MINUS2 4
#define S_SPACE 5

#define NSPACES 11
#define NCOMMAS 12

#define COORD 3

#define BYTE unsigned char
#define WORD unsigned short

inline void d_puts(char* p, int l);
void decrypt(char* argv);

/*
void decrypt(char* argv)
*/
void decrypt(char* argv)
{
    /*
    Security Note: There are classic buffer overflows on the cbuf, spaces and commas byte arrays
    but for the sake of speed we are skipping the required checks!
    Exploiting these issues is left as an exercise for the reader.
    */
    
    //Arrays to store the calculated key and base64 decoded / decrypted data
    BYTE cbuf[1024];
    BYTE* cbuf_ = cbuf;
    BYTE key[17];
    BYTE* key_;
    
    //Length of the base64 decoded data stream
    WORD len = 0;
    
    //Flag to store the completness of the calculated key
    WORD complete = 0;
    
    //Flag to store the initial state of the state machine
    BYTE state = S_MINUS1;
    
    //Arrays for recording the location of spaces and commas
    //Spaces[COORD] initialised to 0 as this is used as a check during the algorithm
    int spaces[NSPACES];
    int* spaces_ = spaces;
    spaces[COORD] = 0;
    
    int commas[NCOMMAS];
    int* commas_ = commas;
    
    //Counters
    BYTE j;
    BYTE k = 0;
    
    //Byte to store the previous XOR BYTE to undo the chained XORing
    BYTE previous = 0;
 
    //Bytes used in base64 decoding
    BYTE c = 0;
    BYTE p;
    
    while (1)
    {
        //Lookup base64 character
        //During testing a switch based lookup appeared to be marginally quicker than a memory based lookup table
        switch(*argv++)
        {
            B64LOOKUP('A', 0x00);
            B64LOOKUP('B', 0x01);
            B64LOOKUP('C', 0x02);
            B64LOOKUP('D', 0x03);
            B64LOOKUP('E', 0x04);
            B64LOOKUP('F', 0x05);
            B64LOOKUP('G', 0x06);
            B64LOOKUP('H', 0x07);
            B64LOOKUP('I', 0x08);
            B64LOOKUP('J', 0x09);
            B64LOOKUP('K', 0x0a);
            B64LOOKUP('L', 0x0b);
            B64LOOKUP('M', 0x0c);
            B64LOOKUP('N', 0x0d);
            B64LOOKUP('O', 0x0e);
            B64LOOKUP('P', 0x0f);
            B64LOOKUP('Q', 0x10);
            B64LOOKUP('R', 0x11);
            B64LOOKUP('S', 0x12);
            B64LOOKUP('T', 0x13);
            B64LOOKUP('U', 0x14);
            B64LOOKUP('V', 0x15);
            B64LOOKUP('W', 0x16);
            B64LOOKUP('X', 0x17);
            B64LOOKUP('Y', 0x18);
            B64LOOKUP('Z', 0x19);
            B64LOOKUP('a', 0x1a);
            B64LOOKUP('b', 0x1b);
            B64LOOKUP('c', 0x1c);
            B64LOOKUP('d', 0x1d);
            B64LOOKUP('e', 0x1e);
            B64LOOKUP('f', 0x1f);
            B64LOOKUP('g', 0x20);
            B64LOOKUP('h', 0x21);
            B64LOOKUP('i', 0x22);
            B64LOOKUP('j', 0x23);
            B64LOOKUP('k', 0x24);
            B64LOOKUP('l', 0x25);
            B64LOOKUP('m', 0x26);
            B64LOOKUP('n', 0x27);
            B64LOOKUP('o', 0x28);
            B64LOOKUP('p', 0x29);
            B64LOOKUP('q', 0x2a);
            B64LOOKUP('r', 0x2b);
            B64LOOKUP('s', 0x2c);
            B64LOOKUP('t', 0x2d);
            B64LOOKUP('u', 0x2e);
            B64LOOKUP('v', 0x2f);
            B64LOOKUP('w', 0x30);
            B64LOOKUP('x', 0x31);
            B64LOOKUP('y', 0x32);
            B64LOOKUP('z', 0x33);
            B64LOOKUP('0', 0x34);
            B64LOOKUP('1', 0x35);
            B64LOOKUP('2', 0x36);
            B64LOOKUP('3', 0x37);
            B64LOOKUP('4', 0x38);
            B64LOOKUP('5', 0x39);
            B64LOOKUP('6', 0x3a);
            B64LOOKUP('7', 0x3b);
            B64LOOKUP('8', 0x3c);
            B64LOOKUP('9', 0x3d);
            B64LOOKUP('+', 0x3e);
            B64LOOKUP('/', 0x3f);
            default:
                goto CONT;
        }
        
        //Decode base64 character
        BYTE cbyte;
        switch (k)
        {
            case 0:
                p = c;
                k++;
                continue;
            case 1:
                cbyte = (BYTE)(p << 2) | (BYTE)(c >> 4);
                p = c;
                k++;
                break;
            case 2:
                cbyte = (BYTE)(p << 4) | (BYTE)(c >> 2);
                p = c;
                k++;
                break;
            default:
                cbyte = (BYTE)(p << 6) | c;
                k = 0;
        }
 
#ifdef _DEBUG
        fprintf(stderr, "{ 0x%02x }\n", cbyte);
#endif
        BYTE ki = len % 16;
        WORD kib = 1 << ki;
        
        //Undo the chained XOR encoding and store the byte
        BYTE xbyte = cbyte ^ previous;
        *cbuf_ = xbyte;

        //If we have calculated the entire key but don't have the location of the 4th space yet
        if (complete == 65535)
        {
            if (spaces[COORD] == 0)
            {
                key_ = key + ki;
                if (*cbuf_ ^ *key_ == 0x20)
                {
                    *(spaces_++) = len;
                    
                    if (spaces[COORD] != 0)
                        goto FIN;
                }
            }
            else
            {
                //Shouldn't be able to get here due to gotos in state machine
                goto FIN;
            }
        }
        else
        {
            //Mask to identify punctuation characters
            //When the mask is applied all punctuation characters will be less than 0x30
            BYTE bxmask = xbyte ^ 0b00110000;
            if (xbyte & 0b01000000)
                bxmask = xbyte ^ 0b01100000;
            
            //State machine to identify correct punctuation characters from masked bytes
            switch (state)
            {
                case S_POINT1:
                    if (bxmask < 0x30)
                    {
                        if (!(complete & kib))
                        {
                            BYTE ikey = xbyte ^ 0x2e; //"."
                            key_ = key + ki;
                            *key_ = ikey;
                            complete |= kib;
#ifdef _DEBUG
                            fprintf(stderr, "0x%02x = 0x%02x\n", ki, *key_);
#endif
                            
                            //If we have everything we need exit the analysis loop
                            if (complete == 65535 && spaces[COORD] != 0)
                                goto FIN;
                        }
                        state = S_COMMA;
                    }
                    break;
                case S_POINT2:
                    if (bxmask < 0x30)
                    {
                        if (!(complete & kib))
                        {
                            BYTE ikey = xbyte ^ 0x2e; //"."
                            key_ = key + ki;
                            *key_ = ikey;
                            complete |= kib;
#ifdef _DEBUG
                            fprintf(stderr, "0x%02x = 0x%02x\n", ki, *key_);
#endif

                            //If we have everything we need exit the analysis loop
                            if (complete == 65535 && spaces[COORD] != 0)
                                goto FIN;
                        }
                        state = S_SPACE;
                    }
                    break;
                case S_COMMA:
                    if (bxmask < 0x30)
                    {
                        *(commas_++) = len;
                        if (!(complete & kib))
                        {
                            BYTE ikey = xbyte ^ 0x2c; //","
                            key_ = key + ki;
                            *key_ = ikey;
                            complete |= kib;
#ifdef _DEBUG
                            fprintf(stderr, "0x%02x = 0x%02x\n", ki, *key_);
#endif

                            //If we have everything we need exit the analysis loop
                            if (complete == 65535 && spaces[COORD] != 0)
                                goto FIN;
                        }
                        state = S_MINUS2;
                    }
                    break;
                case S_MINUS1:
                    if (bxmask < 0x30)
                    {
                        if (!(complete & kib))
                        {
                            BYTE ikey = xbyte ^ 0x2d; //"-"
                            key_ = key + ki;
                            *key_ = ikey;
                            complete |= kib;
#ifdef _DEBUG
                            fprintf(stderr, "0x%02x = 0x%02x\n", ki, *key_);
#endif

                            //If we have everything we need exit the analysis loop
                            if (complete == 65535 && spaces[COORD] != 0)
                                goto FIN;
                        }
                    }
                    state = S_POINT1;
                    break;
                case S_MINUS2:
                    if (bxmask < 0x30)
                    {
                        if (!(complete & kib))
                        {
                            BYTE ikey = xbyte ^ 0x2d; //"-"
                            key_ = key + ki;
                            *key_ = ikey;
                            complete |= kib;
#ifdef _DEBUG
                            fprintf(stderr, "0x%02x = 0x%02x\n", ki, *key_);
#endif

                            //If we have everything we need exit the analysis loop
                            if (complete == 65535 && spaces[COORD] != 0)
                                goto FIN;
                        }
                    }
                    state = S_POINT2;
                    break;
                case S_SPACE:
                    if (bxmask < 0x30)
                    {
                        *(spaces_++) = len;
                        if (!(complete & kib))
                        {
                            BYTE ikey = xbyte ^ 0x20; //" "
                            key_ = key + ki;
                            *key_ = ikey;
                            complete |= kib;
#ifdef _DEBUG
                            fprintf(stderr, "0x%02x = 0x%02x\n", ki, *key_);
#endif

                            //If we have everything we need exit the analysis loop
                            if (complete == 65535 && spaces[COORD] != 0)
                                goto FIN;
                        }
                        state = S_MINUS1;
                    }
                    break;
            }
        }
        previous = cbyte;
        cbuf_++;
        len++;
    }
CONT:
    
    //If we do not have the complete key, use some prior knowledge to guess the missing values
#ifdef _DEBUG
    fprintf(stderr, "%d.", complete);
#endif
    //"Dastardly enemy spies are broadcasting geolocation coordinates of our key UK sites back to their base."
    //Step 1: Assume the first character or anything after a space is a number 5
    //UK latitude 5x.xxxxxx 99.9% of the time
    //Step 2: Assume anything after a comma is a positive number
    //UK positive longitude 0.xxxxxx ~80% of the time
    //Can't be negative because state machine would have identified the minus character and associated key value
    //Step 3: Guess
    
    //Step 1
    //Score increase confirmed for UK coordinates
    if (!(complete & 1))
    {
        key[0] = cbuf[0] ^ 0x35;
        complete |= 1;
        
        if(complete == 65535)
            goto FIN;
    }

    //Step 1
    //Score increase confirmed for UK coordinates
    spaces_ = spaces;
    for (j = 0; j < NSPACES; j++)
    {
        int ki = (*spaces_ + 1) % 16;
        int kib = (1 << ki);
        if (!(complete & kib))
        {
#ifdef _DEBUG
            fprintf(stderr, "0x%02x[0x%02x]*", ki, *spaces_);
#endif
            key[ki] = cbuf[*spaces_ + 1] ^ 0x35;
            complete |= kib;

            if(complete == 65535)
                goto FIN;
        }
        spaces_++;
    }    

    //Step 2
    //Score increase confirmed for UK coordinates
    commas_ = commas;
    for (j = 0; j < NCOMMAS; j++)
    {
        int ki = (*commas_ + 1) % 16;
        int kib = (1 << ki);
        if (!(complete & kib))
        {
#ifdef _DEBUG
            fprintf(stderr, "0x%02x[0x%02x]#", ki, *commas_);
#endif
            key[ki] = cbuf[*commas_ + 1] ^ 0x30;
            complete |= kib;

            if(complete == 65535)
                goto FIN;
        }
        commas_++;
    }
    
    //Step 3
    
    for (j = 0; j < 16; j++)
    {
        if (!(complete & (1 << j)))
        {
            cbuf_ = cbuf + j;
            if (*cbuf_ & 0b01000000)
                key[j] = 'd';
            else
                key[j] = '5';
            
        }
    }
    
FIN:
#ifdef _DEBUG
    key[16] = 0;
    fprintf(stderr, "\nKey: %s\n", key);
#endif
    
    //Only decrypt the required COORD coordinate bytes instead of the entire message
    for (j = spaces[COORD - 1]; j < spaces[COORD]; j++)
        cbuf[j] = key[j % 16] ^ cbuf[j];
    cbuf[spaces[COORD]] = '\n';

    char* result = cbuf + spaces[COORD - 1] + 1;
    int resultl = spaces[COORD] - spaces[COORD - 1];
    
    d_puts(result, resultl);

#ifdef _DEBUG
    cbuf[spaces[COORD]] = 0;
    fprintf(stderr, "Result: %s\n", result);
#endif
}

/*
inline void d_puts(char* p, int l)
*/
#if defined(_DEBUG) || defined(_BENCHMARK)
inline void d_puts(char* p, int l)
{

    int i;
    for (i = 0; i < l; i++)
        putchar(p[i]);
}
#else
inline void d_puts(char* p, int l)
{
    //ARM puts implementation
    asm volatile(
        "mov r7, #4\n"
        "mov r0, #1\n"
        "mov r2, %[l]\n"
        "mov r1, %[p]\n"
        "swi 0\n"
        : 
        : [l] "r" (l), [p] "r" (p)
        : "r0", "r1", "r2", "r7"
    );
}
#endif

/*
struct timespec diff(struct timespec start, struct timespec end)
*/
#ifdef _BENCHMARK
struct timespec diff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec) < 0)
    {
		temp.tv_sec = end.tv_sec - start.tv_sec - 1;
		temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
	}
    else
    {
		temp.tv_sec = end.tv_sec - start.tv_sec;
		temp.tv_nsec = end.tv_nsec - start.tv_nsec;
	}
	
    return temp;
}
#endif

/*
int main(int argc, char *argv[])
*/
#ifdef _BENCHMARK
int main(int argc, char *argv[])
{

    int i;
    struct timespec time1;
    struct timespec time2;
    
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time1);
	for (i = 0; i < 1000000; i++)
    {
        decrypt(argv[1]);
    }
    
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time2);
	fprintf(stderr, "%lld.%.9ld\n", (long long)diff(time1,time2).tv_sec, diff(time1,time2).tv_nsec);
    return 0;
}
#else
#ifdef _DEBUG
int main(int argc, char *argv[])
{
    fprintf(stderr, "%s\n", argv[1]);
    decrypt(argv[1]);
    return 0;
}
#else
__attribute__ ((naked)) void _start()
{
    int argc;
    char **argv;
    
    //ARM code to store the argc and argv
    asm volatile(
        "ldr %0, [sp], #4\n"
        "mov %1, sp\n"
        : "=r" (argc), "=r" (argv)
    );
    
    decrypt(argv[1]);
    
    //ARM exit implementation
    asm volatile(
        "mov r7, #1\n"
        "swi 0\n"
        : 
        :
        : "r7"
    );
}
#endif
#endif

/*
Code should be compiled without linking the stdlib for a *much* more efficient load time.
*/
//gcc -s -nostdlib -o decrypt decrypt.c
