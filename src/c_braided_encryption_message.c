/*
    "C braided key offset encryption" (criptografia por deslocamento de chave trançada).
    Released to Public Domain.
*/

#include <math.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *Base64Encode(const unsigned char *in, size_t len) {
    char *out;
    size_t elen;
    size_t i, j;
    size_t v;

    if (in == NULL || len == 0) return NULL;

    elen = 4 * ((len + 2) / 3); /* 4*ceil(len/3)*/
    out = malloc(elen + 1);
    out[elen] = '\0';

    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        v = in[i];
        v = i + 1 < len ? v << 8 | in[i + 1] : v << 8;
        v = i + 2 < len ? v << 8 | in[i + 2] : v << 8;

        out[j] = b64chars[(v >> 18) & 0x3F];
        out[j + 1] = b64chars[(v >> 12) & 0x3F];
        out[j + 2] = i + 1 < len ? b64chars[(v >> 6) & 0x3F] : '=';
        out[j + 3] = i + 2 < len ? b64chars[v & 0x3F] : '=';
    }

    return out;
}

/* Decode 4 Base64 characters into up to 3 bytes*/
static size_t decode_base64(char *ostr, const uint8_t *inbuf, int *inbuf_size) {
    uint8_t out;
    size_t len = 0;

    /* Decode first byte*/
    out = (uint8_t)((inbuf[0] << 2) | (inbuf[1] >> 4));
    *ostr++ = out;
    len++;

    /* Decode second byte if valid*/
    if (*inbuf_size > 2) {
        out = (uint8_t)((inbuf[1] << 4) | (inbuf[2] >> 2));
        *ostr++ = out;
        len++;
    }

    /* Decode third byte if valid*/
    if (*inbuf_size > 3) {
        out = (uint8_t)((inbuf[2] << 6) | inbuf[3]);
        *ostr++ = out;
        len++;
    }

    *inbuf_size = 0; /* Reset buffer size*/
    return len;
}

/* Convert Base64 character to numeric value*/
static int conv_to_number(uint8_t inbyte) {
    if (inbyte >= 'A' && inbyte <= 'Z') return inbyte - 'A';
    if (inbyte >= 'a' && inbyte <= 'z') return inbyte - 'a' + 26;
    if (inbyte >= '0' && inbyte <= '9') return inbyte - '0' + 52;
    if (inbyte == '+') return 62;
    if (inbyte == '/') return 63;
    return -1; /* Invalid character*/
}

/* Base64 decode function*/
size_t b64_decode(const char *s, size_t nbytes, char **pdst) {
    if (!pdst || !s) return 0; /* Validate pointers*/

    size_t max_len = 0, bytes_left = 0;

    /* Allocate initial buffer if not provided*/
    if (!*pdst) {
        *pdst = malloc(max_len = bytes_left = 64);
        if (!*pdst) return 0;
    }

    char *dst = *pdst;
    uint8_t inbuf[4];
    int inbuf_size = 0;

    /* Iterate through input Base64 string*/
    for (size_t i = 0; i < nbytes; i++) {
        int n = conv_to_number((uint8_t)*s++);

        if (n < 0) continue; /* Ignore invalid characters*/

        inbuf[inbuf_size++] = (uint8_t)n;

        /* Decode when buffer is full*/
        if (inbuf_size == 4) {
            size_t len = decode_base64(dst, inbuf, &inbuf_size);
            dst += len;
            bytes_left -= len;
        }

        /* Reallocate buffer if needed*/
        if (max_len && (bytes_left < 8)) {
            max_len *= 2;
            size_t offset = dst - *pdst;
            bytes_left = max_len - offset;
            *pdst = realloc(*pdst, max_len);
            if (!*pdst) return 0;
            dst = *pdst + offset;
        }
    }

    /* Handle remaining buffer*/
    if (inbuf_size) {
        for (int i = inbuf_size; i < 4; i++) inbuf[i] = 0;
        dst += decode_base64(dst, inbuf, &inbuf_size);
    }

    *dst = '\0'; /* Null-terminate output string*/
    return dst - *pdst;
}

/* Wrapper for easier usage*/
unsigned char *Base64Decode(const char *in, size_t len, size_t *outlen) {
    char *decoded = NULL;
    size_t decoded_len = b64_decode(in, len, &decoded);

    if (outlen) *outlen = decoded_len;
    return (unsigned char *)decoded;
}

/* Função GetBraidOffset em C, agora corrigida conforme a lógica de Harbour*/
static int GetBraidOffset(const char *cKey, int nIndex) {
    int nKeyLen = strlen(cKey); /* Comprimento da chave*/
    char cBraid = cKey[(nIndex - 1) % nKeyLen]; /* Caractere da chave na posição (nIndex-1)%nKeyLen*/
    int nBraid = (int)cBraid; /* Valor ASCII do caractere*/
    int nMod = (int)(nBraid % nKeyLen); /* Módulo do valor ASCII com o comprimento da chave*/

    if (nMod == 0) {
        return 3; /* Offset para cruzamento à direita*/
    } else if (nMod == 1) {
        return -2; /* Offset para cruzamento à esquerda*/
    } else {
        nMod = nMod % 2; /* Modificar o módulo para garantir 0 ou 1*/
        if (nMod == 0) {
            return -1; /* Offset para cruzamento à esquerda*/
        } else {
            return 2; /* Offset para cruzamento à direita*/
        }
    }
    return 0; /* Sem alteração*/
}

/* Função para gerar a senha*/
static void GenPwd(int nLen, const char *cKSeed, char *cPass) {
    int nSeedLen = strlen(cKSeed);
    srand(time(NULL)); /* Semente para resultados diferentes*/

    for (int i = 0; i < nLen; i++) {
        cPass[i] = cKSeed[rand() % nSeedLen];
    }
    cPass[nLen] = '\0';
}

/* Função para criptografar a mensagem*/
char *EncryptMessage(const char *cMessage, char **cKey) {
    static char cEncrypted[256];
    char *cLocalKey;
    int nLen = strlen(cMessage);

    srand(time(NULL)); /* Semente para resultados diferentes*/
    int nKeyRand=rand() % 15;

    if (*cKey == NULL) {
        *cKey = malloc(nLen+nKeyRand+1);
        if (*cKey == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        GenPwd(nLen+nKeyRand, "AaBbCcD-dEeFfGg-HhIiHhK_kLlMmNn-OoPpQqRrS-sTtUuVvW_wXxYyZz0-123456_789!@#$%^&*()_+[]{}|;:,.<>?/~`0123456789", *cKey);
    }

    cLocalKey = malloc(strlen(*cKey) + 1);
    if (cLocalKey == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(*cKey);
        exit(EXIT_FAILURE);
    }
    strcpy(cLocalKey, *cKey);

    memset(cEncrypted, 0, sizeof(cEncrypted));

    for (int i = 0; i < nLen; i++) {
        int offset = GetBraidOffset(cLocalKey, i + 1); /* Calcular deslocamento usando a chave e o índice*/
        cEncrypted[i] = (cMessage[i] + offset); /* Ajustar valor para o intervalo ASCII visível*/
    }
    cEncrypted[nLen] = '\0';

    free(cLocalKey);
    return cEncrypted;
}

/* Função para descriptografar a mensagem*/
char *DecryptMessage(const char *cEncrypted, const char *cKey) {
    static char cDecrypted[256];
    int nLen;

    nLen = strlen(cEncrypted);
    memset(cDecrypted, 0, sizeof(cDecrypted));

    /* Descriptografar a mensagem*/
    for (int i = 0; i < nLen; i++) {
        int offset = GetBraidOffset(cKey, i + 1); /* Calcular o deslocamento usando a chave e o índice*/
        cDecrypted[i] = (cEncrypted[i] - offset); /* Ajustar o valor para o intervalo ASCII visível*/
    }
    cDecrypted[nLen] = '\0';

    return cDecrypted;
}

/* Função principal*/
int main(int argc, char *argv[]) {

    const char *cMessage = "Hello, World!";
    char *cKey = NULL;
    char *cEncrypted = NULL;

    if (argc == 1) {
        /* Criptografar mensagem e exibir resultados em Base64*/
        cEncrypted = EncryptMessage(cMessage, &cKey);
        if (!cEncrypted || !cKey) {
            fprintf(stderr, "Erro ao criptografar a mensagem ou gerar a chave.\n");
            return EXIT_FAILURE;
        }

        char *cEncrypted64 = Base64Encode((const unsigned char *)cEncrypted, strlen(cEncrypted));
        char *cKey64 = Base64Encode((const unsigned char *)cKey, strlen(cKey));
        if (!cEncrypted64 || !cKey64) {
            fprintf(stderr, "Erro ao codificar mensagem ou chave em Base64.\n");
            free(cKey);
            return EXIT_FAILURE;
        }

        /*
            printf("Encrypted (Base64): %s\n", cEncrypted64);
            printf("Key (Base64): %s\n", cKey64);
        */
        char *cDecrypted = DecryptMessage(cEncrypted, cKey);
        /*
            if (cDecrypted) {
                printf("Decrypted: %s\n", cDecrypted);
            } else {
                fprintf(stderr, "Erro ao descriptografar a mensagem.\n");
            }
        */
        printf("%s %s %s", cEncrypted64, cKey64, cDecrypted);

        free(cKey);
        free(cEncrypted64);
        free(cKey64);

    } else if (argc == 3) {

        /* Decodificar parâmetros e descriptografar*/
        size_t decoded_len1, decoded_len2;
        unsigned char *EncryptedDecoded64 = Base64Decode(argv[1], strlen(argv[1]), &decoded_len1);
        unsigned char *KeyDecoded64 = Base64Decode(argv[2], strlen(argv[2]), &decoded_len2);

        if (!EncryptedDecoded64 || !KeyDecoded64) {
            fprintf(stderr, "Erro ao decodificar Base64.\n");
            free(EncryptedDecoded64);
            free(KeyDecoded64);
            return EXIT_FAILURE;
        }

        char *cDecrypted = DecryptMessage((const char *)EncryptedDecoded64, (const char *)KeyDecoded64);
        if (cDecrypted) {
            printf("From Parameters:\n");
            printf("Encrypted (decoded): %s\n", EncryptedDecoded64);
            printf("Key (decoded): %s\n", KeyDecoded64);
            printf("Decrypted: %s\n", cDecrypted);
        } else {
            fprintf(stderr, "Erro ao descriptografar os parâmetros.\n");
        }

        free(EncryptedDecoded64);
        free(KeyDecoded64);
    } else {
        fprintf(stderr, "Uso incorreto. Execute sem argumentos para criptografar ou com dois argumentos (mensagem e chave em Base64) para descriptografar.\n");
        return EXIT_FAILURE;
    }

    return 0;
}
