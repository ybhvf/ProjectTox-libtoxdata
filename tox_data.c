#include "tox_data.h"

uint32_t tox_size_encrypted(Tox *tox) {
    return tox_size(tox) + 108;
}

int tox_save_encrypted(Tox *tox, uint8_t *data, uint8_t *key, uint16_t key_length) {
    /* The values used (N=14,r=8,p=1) were sourced from here: https://www.tarsnap.com/scrypt/scrypt-slides.pdf
     * Percival recommends these values for interactive logins.
     */
    uint32_t scrypt_n = 14,
             scrypt_r = 8,
             scrypt_p = 1;

    uint8_t  encrypted_key[crypto_secretbox_KEYBYTES],
             nonce[crypto_secretbox_NONCEBYTES],
             salt[24];

    uint64_t block_two_size = tox_size(tox) + 36;

    //generate encryption key
    randombytes(salt, 24);
    randombytes(nonce, 24);
    scrypt(key, key_length, salt, 24, scrypt_n, scrypt_r, scrypt_p, encrypted_key, 32);

    uint8_t block_two_plaintext[block_two_size],
            block_two_encrypted[block_two_size];

    //prepare block two

    uint8_t magic2[4] = {0x72, 0x74, 0x61, 0x73};
    memcpy(block_two_plaintext + 32, magic2, 4);

    tox_save(tox, block_two_plaintext + 32 + 4);

    memset(block_two_plaintext, 0, 32);
    if(crypto_secretbox(block_two_encrypted, block_two_plaintext, block_two_size, nonce, encrypted_key) != 0)
        return -1;

    //prepare block one

    int offset = 0;

    //magic
    uint8_t magic1[4] = {0x6c, 0x69, 0x62, 0x65};
    memcpy(data, magic1, 4);
    offset += 4;

    //scrypt values
    memcpy(data + offset, &scrypt_n, 4);
    offset += 4;
    memcpy(data + offset, &scrypt_r, 4);
    offset += 4;
    memcpy(data + offset, &scrypt_p, 4);
    offset += 4;

    //salt & nonce
    memcpy(data + offset, salt, 24);
    offset += 24;
    memcpy(data + offset, nonce, 24);
    offset += 24;

    //block two
    memcpy(data + offset, &block_two_size, 8);
    offset += 8;
    memcpy(data + offset, block_two_encrypted, block_two_size);

    //a nice gesture
    memset(block_two_plaintext, 0, block_two_size);
    memset(encrypted_key, 0, 32);

    return 0;
}

int tox_load_encrypted(Tox *tox, uint8_t *data, uint32_t length, uint8_t *key, uint16_t key_length) {
    uint32_t scrypt_n,
             scrypt_r,
             scrypt_p;

    uint8_t  encrypted_key[crypto_secretbox_KEYBYTES],
             nonce[crypto_secretbox_NONCEBYTES],
             salt[24];

    uint64_t block_two_length;

    int offset = 0;

    if(length < 72)
        return -1;

    //check magic
    char magic[4];
    memcpy(magic, data, 4);
    if(memcmp(magic,&"libe",4) != 0)
        return -1;
    offset += 4;

    //scrypt vars
    memcpy(&scrypt_n, data + offset, 4);
    offset += 4;
    memcpy(&scrypt_r, data + offset, 4);
    offset += 4;
    memcpy(&scrypt_p, data + offset, 4);
    offset += 4;

    //salt & nonce
    memcpy(salt, data + offset, 24);
    offset += 24;
    memcpy(nonce, data + offset, 24);
    offset += 24;

    //block two
    memcpy(&block_two_length, data + offset, 8);
    offset += 8;

    if(length < block_two_length + 72)
        return -1;

    uint8_t block_two_encrypted[block_two_length],
            block_two_plaintext[block_two_length];

    memcpy(block_two_encrypted, data + offset, block_two_length);

    //derive key from file
    scrypt(key, key_length, salt, 24, scrypt_n, scrypt_r, scrypt_p, encrypted_key, 32);

    //decrypt block
    if(crypto_secretbox_open(block_two_plaintext, block_two_encrypted, block_two_length, nonce, encrypted_key) != 0)
        return -1;

    //check magic
    memcpy(magic, block_two_plaintext + 32, 4);
    if(memcmp(magic, &"rtas",4) != 0)
        return -1;

    tox_load(tox, block_two_plaintext + 36, block_two_length - 36);

    //a nice gesture
    memset(block_two_plaintext, 0, block_two_length);
    memset(encrypted_key, 0, 32);

    return 0;
}
