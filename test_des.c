#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// 위에서 구현된 DES 함수와 데이터 정의 포함

void test_round_key_generation()
{
    uint64_t key = 0x133457799BBCDFF1;
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    printf("라운드 키 테스트:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("라운드 %d: %012llx\n", i + 1, round_keys[i]);
    }

    // 예제 키와 비교 (테스트 키로 디버깅 가능)
    assert(round_keys[0] != 0); // 라운드 키가 0이 아니어야 함
}

void test_des_encryption_decryption()
{
    uint64_t key = 0x133457799BBCDFF1;
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    uint64_t plain_text = 0x0123456789ABCDEF;
    uint64_t cipher_text = des_cipher(plain_text, round_keys, 0);     // 암호화
    uint64_t decrypted_text = des_cipher(cipher_text, round_keys, 1); // 복호화

    printf("DES 암/복호화 테스트:\n");
    printf("평문: %016llx\n", plain_text);
    printf("암호문: %016llx\n", cipher_text);
    printf("복호문: %016llx\n", decrypted_text);

    assert(plain_text == decrypted_text); // 복호화된 텍스트가 원본과 같아야 함
}

void test_plain_text_1()
{
    // 테스트용 파일 생성
    FILE *plain_text_1 = fopen("Plain text 1.txt", "w");
    fprintf(plain_text_1, "Hello, DES!\nThis is line 2.\nThird line.");
    fclose(plain_text_1);

    uint64_t key = 0x133457799BBCDFF1;
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    process_by_lines("Plain text 1.txt", "Plain text 1 enc.txt", "Plain text 1 dec.txt", round_keys);

    // 복호화 결과 검증
    FILE *dec_output = fopen("Plain text 1 dec.txt", "r");
    char line[128];

    printf("\nPlain Text 1 테스트 결과:\n");
    while (fgets(line, sizeof(line), dec_output))
    {
        printf("%s", line);
    }
    fclose(dec_output);

    // 복호화된 결과를 원본 파일과 비교
    dec_output = fopen("Plain text 1 dec.txt", "r");
    FILE *original = fopen("Plain text 1.txt", "r");

    char dec_line[128], orig_line[128];
    while (fgets(orig_line, sizeof(orig_line), original) && fgets(dec_line, sizeof(dec_line), dec_output))
    {
        assert(strcmp(orig_line, dec_line) == 0);
    }

    fclose(dec_output);
    fclose(original);
}

void test_plain_text_2()
{
    // 테스트용 파일 생성
    FILE *plain_text_2 = fopen("Plain text 2.txt", "w");
    fprintf(plain_text_2, "This is a longer text file. It contains multiple lines and will be encrypted as a single block.");
    fclose(plain_text_2);

    uint64_t key = 0x133457799BBCDFF1;
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    process_entire_file("Plain text 2.txt", "Plain text 2 enc.txt", "Plain text 2 dec.txt", round_keys);

    // 복호화 결과 검증
    FILE *dec_output = fopen("Plain text 2 dec.txt", "r");
    char buffer[1024];

    printf("\nPlain Text 2 테스트 결과:\n");
    while (fgets(buffer, sizeof(buffer), dec_output))
    {
        printf("%s", buffer);
    }
    fclose(dec_output);

    // 복호화된 결과를 원본 파일과 비교
    dec_output = fopen("Plain text 2 dec.txt", "r");
    FILE *original = fopen("Plain text 2.txt", "r");

    char dec_line[1024], orig_line[1024];
    while (fgets(orig_line, sizeof(orig_line), original) && fgets(dec_line, sizeof(dec_line), dec_output))
    {
        assert(strcmp(orig_line, dec_line) == 0);
    }

    fclose(dec_output);
    fclose(original);
}

int main()
{
    // 테스트 실행
    printf("라운드 키 생성 테스트:\n");
    test_round_key_generation();

    printf("\nDES 암/복호화 기본 테스트:\n");
    test_des_encryption_decryption();

    printf("\nPlain Text 1 암/복호화 테스트:\n");
    test_plain_text_1();

    printf("\nPlain Text 2 암/복호화 테스트:\n");
    test_plain_text_2();

    printf("\n모든 테스트 성공.\n");

    return 0;
}
