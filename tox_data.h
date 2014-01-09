#include <stdio.h>
#include <string.h>
#include <time.h>

#include <tox.h>
#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <scrypt-jane.h>

/* "Profile" Save Format
 * ==============
 *
 * bytes    name        type        purpose
 * ----------------------------------------
 * -- block one [unencrypted] --
 * 4        magic       uint8       magic, 6c:69:62:65 "libe"
 * 8        saved       uint64      unix timestamp from when the profile was last used
 * 2        namelen     uint16      length of name
 * varies   name        uint8       name of profile, UTF-8 preferably
 * 12       scryptvars  uint32      N,r,p variables for scrypt - in this order
 * 24       salt        uint8       the salt for scrypt
 * 24       nonce       uint8       the nonce for nacl
 * 8        blocklen    uint64      the length of the encrypted block
 * -- block two [encrypted] --
 * 32       0           uint8       crypto_secretbox_ZEROBYTES
 * 4        magic       uint8       magic, 72:74:61:73 "rtas"
 * varies   profile     uint8       the messenger data - this goes to tox_load()
 */

typedef struct tox_data {
	//the file path for the given profile
	char *file_path;
	//indicates whether the profile is locked
	int locked;

	uint8_t encrypted_key[crypto_secretbox_KEYBYTES], //Sodium encrypt key, 32 bytes.
			nonce[crypto_secretbox_NONCEBYTES], //Sodium nonce, 24 bytes.
			salt[24]; //Scrypt salt, 24 bytes.

	/* The values used (N=12,r=8,p=1) were sourced from here: https://www.tarsnap.com/scrypt/scrypt-slides.pdf
	 * Percival recommends larger (N=14) values for interactive logins - I've lessened them slightly to make
	 * decryption acceptable on slower machines. One can always specify harder values.
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

/* NOTE - all string function parameters must be nul-teminated (path, password, et cetera) */

/* Creates and returns a new tox_data with the given path, internal name, and password
 * The returned tox_data is both unlocked and not yet saved to disk.
 * The caller is responsible for calling data_close() on the given tox_data when done.
 *
 * returns tox_data on success, NULL otherwise
 */
tox_data* data_init_new(char *path, uint8_t *data_name, uint8_t *password);

/* Loads a tox_data from the given path
 * The returned tox_data is locked until data_unlock() is called.
 * The caller is responsible for calling data_close() on the given tox_data when done.
 *
 * returns tox_data on success, NULL otherwise
 */
tox_data* data_init_load(char *path);

/* Safely frees a given tox_data */
void data_close(tox_data *data);

/* Unlocks the given tox_data
 * 
 * returns	0 if success
 *			-1 if the password is wrong
 *			-2 if the file is malformed
 */
int data_unlock(tox_data *data, uint8_t *password);

/* ------------- REQUIRES UNLOCKING ------------- */

/* Locks the given tox_data
 * 
 * returns	0 if success
 *			-1 if the file is locked
 */
int data_lock(tox_data *data);

/* Changes the password for the given tox_data
 * 
 * returns	0 if success
 *			-1 if the file is locked
 *			-2 if the old password is wrong
 */
int data_change_key(tox_data *data, uint8_t *old_password, uint8_t *new_password);

/* Writes the given messenger to the given tox_data
 * This function also calls data_flush().
 * 
 * returns	0 if success
 *			-1 if the file is locked
 */
int data_write_messenger(tox_data *data, uint8_t *buffer, size_t length);

/* Copies the messenger from the given tox_data
 * 
 * returns	the size of the tox messenger if success
 *			-1 if the file is locked
 */
size_t data_read_messenger(tox_data *data, uint8_t **buffer);

/* Writes the given tox_data to the disk
 * 
 * returns	0 if success
 *			-1 if the file is locked
 *			-2 if encryption error
 *			-3 if FILE error
 */
int data_flush(tox_data *data);

#ifdef __cplusplus
}
#endif
