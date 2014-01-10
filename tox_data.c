#include "tox_data.h"

void _gen_key(tox_data *data, uint8_t *password, uint8_t *key) {
	scrypt(password, strlen((char*)password), data->salt, 24, data->scrypt_n, data->scrypt_r, data->scrypt_p, key, 32);
}

void _gen_key_new(tox_data *data, uint8_t *password) {
	randombytes(data->salt, 24);
	randombytes(data->nonce, 24);
	_gen_key(data, password, data->encrypted_key);
}

void _data_init(tox_data *data) {
	data->file_path = NULL;
	data->locked = 1;

	data->scrypt_n = 12;
	data->scrypt_r = 8;
	data->scrypt_p = 1;

	data->name = NULL;
	data->_data = NULL;
}

tox_data* data_init_new(char *path, uint8_t *username, uint8_t *password) {
	tox_data *data = (tox_data*)malloc(sizeof(tox_data));
	_data_init(data);

	size_t str_size = strlen(path) + 1;
	data->file_path = (char*)malloc(str_size);
	strncpy(data->file_path, path, str_size);

	str_size = strlen((char*)username) + 1;
	data->name = (uint8_t*)malloc(str_size);
	strncpy((char*)data->name, (char*)username, str_size);

	_gen_key_new(data, password);
	memset(password, 0, strlen((char*)password) + 1);
	data->locked = 0;

	return data;
}

tox_data* data_init_load(char *path) {
	tox_data *data = (tox_data*)malloc(sizeof(tox_data));
	_data_init(data);

	size_t str_size = strlen(path) + 1;
	data->file_path = (char*)malloc(str_size);
	strncpy(data->file_path, path, str_size);

	FILE *file = fopen(path, "r");
	if(file == NULL)
		return NULL;

	//check magic
	char magic[4];
	fread(magic, 1, 4, file);
	if(memcmp(magic,&"libe",4) != 0)
		return NULL;

	//read time last saved
	fread(&data->time_saved, 8, 1, file);

	//read name
	uint16_t name_length;
	fread(&name_length, 2, 1, file);
	data->name = (uint8_t*)malloc(name_length);
	fread(data->name, 1, name_length, file);
	//check for nul-terminated name string
	if(data->name[name_length - 1] != '\0') {
		data->name = realloc(data->name, name_length + 1);
		data->name[name_length] = '\0';
	}

	//scrypt vars
	fread(&data->scrypt_n, 4, 1, file);
	fread(&data->scrypt_r, 4, 1, file);
	fread(&data->scrypt_p, 4, 1, file);

	//salt & nonce
	fread(data->salt, 1, 24, file);
	fread(data->nonce, 1, 24, file);

	//block two
	fread(&data->_block_two_length, 8, 1, file);
	data->_block_two_offset = ftell(file);

	fclose(file);
	return data;
}

void data_close(tox_data *data) {
	free(data->file_path);
	free(data->name);
	free(data->_data);
	free(data);
}

int data_unlock(tox_data *data, uint8_t *password) {
	if(!data->locked)
		return 0;

	//load encrypted block
	FILE *file = fopen(data->file_path, "r");

	uint8_t block_two_encrypted[data->_block_two_length],
			block_two_plaintext[data->_block_two_length];

	fseek(file, data->_block_two_offset, 0);
	fread(block_two_encrypted, 1, data->_block_two_length, file);

	fclose(file);

	//derive key from file
	_gen_key(data, password, data->encrypted_key);

	//decrypt block
	if(crypto_secretbox_open(block_two_plaintext, block_two_encrypted, data->_block_two_length, data->nonce, data->encrypted_key) != 0)
		return -1;

	//check magic
	char magic[4];
	memcpy(magic, block_two_plaintext + 32, 4);
	if(memcmp(magic, &"rtas",4) != 0)
		return -2;

	//load for future use
	if(data->_data != NULL)
		free(data->_data);
	data->_data_length = data->_block_two_length - 36;
	data->_data = (uint8_t*)malloc(data->_data_length);
	memcpy(data->_data, block_two_plaintext + 36, data->_data_length);

	/* Generate a new key for future saving.
	 * This somewhat more secure than keeping the user password around in plaintext in
	 * the ram (keeping in mind, of course, that it's already game-over if the client is
	 * compromised). Still though - it's the thought that counts.
	 */
	_gen_key_new(data, password);

	memset(block_two_plaintext, 0, data->_block_two_length);

	data->locked = 0;

	return 0;
}

/* ------------- REQUIRES UNLOCKING ------------- */
int data_lock(tox_data *data) {
	if(data->locked)
		return -1;

	data_flush(data);

	memset(data->_data, 0, data->_data_length);
	memset(data->encrypted_key, 0, 32);

	data->locked = 1;
	return 0;
}

int data_change_key(tox_data *data, uint8_t *old_password, uint8_t *new_password) {
	if(data->locked)
		if(data_unlock(data, old_password) != 0)
			return -1;

	uint8_t key[32];
	_gen_key(data, old_password, key);

	/* Check to see if keys match.
	 * Although there's no cryptographic need to do so, it ensures that whomever's using
	 * the profile should have access.
	 */
	if(strcmp((const char*)key, (const char*)data->encrypted_key) != 0)
		return -2;

	_gen_key_new(data, new_password);
	return 0;
}

int data_write_messenger(tox_data *data, uint8_t *buffer, size_t length) {
	if(data->locked)
		return -1;

	if(data->_data != NULL)
		free(data->_data);

	data->_data_length = length;
	data->_data = (uint8_t*)malloc(length);
	memcpy(data->_data, buffer, length);
	data_flush(data);

	return 0;
}

size_t data_messenger_size(tox_data *data) {
	if(data->locked)
		return -1;

	return data->_data_length;
}

int data_read_messenger(tox_data *data, uint8_t *buffer) {
	if(data->locked)
		return -1;

	memcpy(buffer, data->_data, data->_data_length);
	return 0;
}

int data_flush(tox_data *data) {
	if(data->locked)
		return -1;

	/* Create block two */
	uint64_t block_two_size = data->_data_length + 36;
	uint8_t block_two_plaintext[block_two_size], block_two_encrypted[block_two_size];
	uint8_t magic2[4] = {0x72, 0x74, 0x61, 0x73};

	memcpy(block_two_plaintext + 32, magic2, 4);
	memcpy(block_two_plaintext + 32 + 4, data->_data, data->_data_length);

	//required zerobytes
	memset(block_two_plaintext, 0, 32);

	/* Encrypt block two */
	if(crypto_secretbox(block_two_encrypted, block_two_plaintext, block_two_size, data->nonce, data->encrypted_key) != 0)
		return -2;
	memset(block_two_plaintext, 0, block_two_size);

	FILE *file = fopen(data->file_path, "w+");

	/* Compose entire file */
	//determine file size & create buffer
	uint16_t name_length = strlen((char*)data->name);

	//magic
	uint8_t magic1[4] = {0x6c, 0x69, 0x62, 0x65};
	fwrite(magic1, 1, 4, file);

	//time
	data->time_saved = time(NULL);
	fwrite(&data->time_saved, 8, 1, file);

	//profile name
	fwrite(&name_length, 2, 1, file);
	fwrite(data->name, 1, name_length, file);

	//scrypt values
	fwrite(&data->scrypt_n, 4, 1, file);
	fwrite(&data->scrypt_r, 4, 1, file);
	fwrite(&data->scrypt_p, 4, 1, file);

	//salt & nonce
	fwrite(data->salt, 1, 24, file);
	fwrite(data->nonce, 1, 24, file);

	//block two
	fwrite(&block_two_size, 8, 1, file);
	fwrite(block_two_encrypted, 1, block_two_size, file);

	if(fclose(file) != 0)
		return -3;
	return 0;
}