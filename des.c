#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// InitialPermutation
int InitialPermutationTable[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

// FinalPermutation
int FinalPermutationTable[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};

// Parity
int ParityDropTable[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

// KeyCompression
int KeyCompressionTable[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

// 라운드별 좌측 이동 횟수
int ShiftTable[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

uint64_t permute(uint64_t input, const int *table, int size)
{
    uint64_t output = 0;
    for (int i = 0; i < size; i++)
    {
        output <<= 1;
        output |= (input >> (64 - table[i])) & 1;
    }
    return output;
}

// 28비트 좌측 순환 이동
uint32_t left_rotate(uint32_t input, int shifts)
{
    return ((input << shifts) | (input >> (28 - shifts))) & 0xFFFFFFF;
}

// 라운드 키 생성
void generate_round_keys(uint64_t key, uint64_t round_keys[16])
{
    uint64_t permuted_key = permute(key, ParityDropTable, 56);
    uint32_t C = (permuted_key >> 28) & 0xFFFFFFF;
    uint32_t D = permuted_key & 0xFFFFFFF;

    for (int i = 0; i < 16; i++)
    {
        C = left_rotate(C, ShiftTable[i]);
        D = left_rotate(D, ShiftTable[i]);
        uint64_t combined = ((uint64_t)C << 28) | D;
        round_keys[i] = permute(combined, KeyCompressionTable, 48);
    }
}

// DES 암호화/복호화 함수
uint64_t des_cipher(uint64_t block, uint64_t round_keys[16], int decrypt)
{
    uint64_t permuted_block = permute(block, InitialPermutationTable, 64);
    uint32_t left = (permuted_block >> 32) & 0xFFFFFFFF;
    uint32_t right = permuted_block & 0xFFFFFFFF;

    for (int i = 0; i < 16; i++)
    {
        int key_index = decrypt ? 15 - i : i;
        uint32_t temp = right;
        right = left ^ (right ^ round_keys[key_index]);
        left = temp;
    }

    uint64_t combined = ((uint64_t)right << 32) | left;
    return permute(combined, FinalPermutationTable, 64);
}

// 파일 줄 단위 처리 (Plain Text 1)
void process_by_lines(const char *input_file, const char *enc_file, const char *dec_file, uint64_t round_keys[16])
{
    FILE *input = fopen(input_file, "r");
    FILE *enc_output = fopen(enc_file, "w");
    FILE *dec_output = fopen(dec_file, "w");

    if (!input || !enc_output || !dec_output)
    {
        perror("파일 열기 실패");
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), input))
    {
        size_t len = strlen(line);
        int has_newline = 0;

        if (line[len - 1] == '\n')
        {
            has_newline = 1;
            line[len - 1] = '\0';
            len--;
        }

        size_t offset = 0;
        while (offset < len)
        {
            uint64_t block = 0;
            size_t chunk_size = (len - offset > 8) ? 8 : len - offset;
            memcpy(&block, &line[offset], chunk_size);

            uint64_t encrypted = des_cipher(block, round_keys, 0);
            fprintf(enc_output, "%016llx\n", encrypted);

            uint64_t decrypted = des_cipher(encrypted, round_keys, 1);
            char decrypted_text[9] = {0};
            memcpy(decrypted_text, &decrypted, chunk_size);
            fwrite(decrypted_text, 1, chunk_size, dec_output);

            offset += 8;
        }

        if (has_newline)
        {
            fprintf(dec_output, "\n");
        }
    }

    fclose(input);
    fclose(enc_output);
    fclose(dec_output);
}

// 전체 파일 처리 (Plain Text 2)
void process_entire_file(const char *input_file, const char *enc_file, const char *dec_file, uint64_t round_keys[16])
{
    FILE *input = fopen(input_file, "r");
    FILE *enc_output = fopen(enc_file, "w"); // 텍스트 모드
    FILE *dec_output = fopen(dec_file, "w"); // 텍스트 모드

    if (!input || !enc_output || !dec_output)
    {
        perror("파일 열기 실패");
        if (input)
            fclose(input);
        if (enc_output)
            fclose(enc_output);
        if (dec_output)
            fclose(dec_output);
        return;
    }

    fseek(input, 0, SEEK_END);
    size_t size = ftell(input);
    rewind(input);

    char *buffer = malloc(size);
    fread(buffer, 1, size, input);

    for (size_t i = 0; i < size; i += 8)
    {
        uint64_t block = 0;
        size_t chunk_size = (i + 8 <= size) ? 8 : size - i;
        memcpy(&block, buffer + i, chunk_size);

        // 암호화
        uint64_t encrypted = des_cipher(block, round_keys, 0);
        fprintf(enc_output, "%016llx\n", encrypted); // 암호화된 데이터 텍스트 저장

        // 복호화
        uint64_t decrypted = des_cipher(encrypted, round_keys, 1);
        char decrypted_text[9] = {0};
        memcpy(decrypted_text, &decrypted, chunk_size);
        fwrite(decrypted_text, 1, chunk_size, dec_output); // 복호화된 텍스트 저장
    }

    free(buffer);
    fclose(input);
    fclose(enc_output);
    fclose(dec_output);
}

int main()
{
    uint64_t key = 0x133457799BBCDFF1;
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    printf("Plain Text 1 처리...\n");
    process_by_lines("Plain text 1.txt", "Plain text 1 enc.txt", "Plain text 1 dec.txt", round_keys);

    printf("Plain Text 2 처리...\n");
    process_entire_file("Plain text 2.txt", "Plain text 2 enc.txt", "Plain text 2 dec.txt", round_keys);

    printf("암/복호화 완료.\n");
    return 0;
}
