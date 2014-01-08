#include <stdio.h>
#include <string.h>
#include <time.h>

#include <tox.h>
#include <sodium.h>
#include <scrypt-jane.h>

/* Profile Save Format
 * ==============
 *
 * bytes    name        type        purpose
 * ----------------------------------------
 * -- block one [unencrypted] --
 * 4        magic       uint8       magic,6c:69:62:65 "libe"
 * 8        saved       uint64      timestamp of when the profile was last used
 * 2        namelen     uint16      length of name
 * varies   name        uint8       name of profile, UTF-8 preferrably
 * 12       scryptvars  uint32      N,r,p variables for scrypt - in this order
 * 24       salt        uint8       the salt for scrypt
 * 24       nonce       uint8       the nonce for nacl
 * 8        blocklen    uint64      the length of the encrypted block
 * -- block two [encrypted] --
 * 32       0           uint8       crypto_secretbox_ZEROBYTES
 * 4        magic       uint8       magic,72:74:61:73 "rtas"
 * varies   profile     uint8       the messenger data - this goes to tox_load()
 */

typedef struct tox_data {
    char *file_path;
    int locked;

	uint8_t encrypted_key[crypto_secretbox_KEYBYTES], //Sodium encrypt key, 32 bytes.
			nonce[crypto_secretbox_NONCEBYTES], //Sodium nonce, 24 bytes.
			salt[24]; //Scrypt salt, 24 bytes.

	/* These values were sourced from here: https://www.tarsnap.com/scrypt/scrypt-slides.pdf
	 * Percival recommends these values for interactive logins - we can always adjust them later
	 * for increased difficulty.
	 */
	uint32_t scrypt_n,
			 scrypt_r,
			 scrypt_p;

	//The profile's name and last save time.
	uint8_t *name;
	uint64_t time_saved;

	//The encrypted block's file offset and length.
	size_t block_two_offset;
	uint64_t block_two_length;

	//The unencrypted messenger data.
	uint8_t *data;
	size_t data_length;
} tox_data;

tox_data* data_init_new(char *path, uint8_t *data_name, uint8_t *password);
tox_data* data_init_load(char *path);
void data_close(tox_data *data);

int data_unlock(tox_data *data, uint8_t *password);

/* ------------- REQUIRES UNLOCKING ------------- */
int data_lock(tox_data *data);
int data_change_key(tox_data *data, uint8_t *old_password, uint8_t *new_password);
int data_write_messenger(tox_data *data, uint8_t *buffer, size_t length);
size_t data_read_messenger(tox_data*data, uint8_t **buffer);
int data_flush(tox_data *data);