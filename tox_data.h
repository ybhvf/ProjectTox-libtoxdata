#ifndef TOX_DATA_H
#define TOX_DATA_H

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <tox.h>
#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <scrypt-jane.h>

/* Buffer Save Format
 * ==============
 *
 * bytes    name        type        purpose
 * ----------------------------------------
 * -- block one [unencrypted] --
 * 4        magic       uint8       magic, 6c:69:62:65 "libe"
 * 12       scryptvars  uint32      N,r,p variables for scrypt - in this order
 * 24       salt        uint8       the salt for scrypt
 * 24       nonce       uint8       the nonce for nacl
 * 8        blocklen    uint64      the length of the encrypted block
 * -- block two [encrypted] --
 * 32       0           uint8       crypto_secretbox_ZEROBYTES
 * 4        magic       uint8       magic, 72:74:61:73 "rtas"
 * varies   profile     uint8       the messenger data - this goes to tox_load()
 */

/* ------------- SIMPLE-USE FUNCTIONS ------------- */
/* return the size of data to pass to messenger_save_encrypted(...)
 */
uint32_t tox_size_encrypted(Tox *tox);

/* Save the messenger, encrypting the data with key of length key_length
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tox_save_encrypted(Tox *tox, uint8_t *data, uint8_t *key, uint16_t key_length);

/* Load the messenger from data of size length encrypted with key of key_length.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tox_load_encrypted(Tox *tox, uint8_t *data, uint32_t length, uint8_t *key, uint16_t key_length);

#ifdef __cplusplus
}
#endif

#endif
