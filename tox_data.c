#include "tox_data.h"

void _gen_key(tox_data *data, uint8_t *password, uint8_t *key) {
	scrypt(password, strlen(password), data->salt, 24, data->scrypt_n, data->scrypt_r, data->scrypt_p, key, 32);
}

int _gen_key_new(tox_data *data, uint8_t *password) {
	randombytes(data->salt, 24);
	randombytes(data->nonce, 24);
	_gen_key(data, password, data->encrypted_key);
}

void _data_init(tox_data *tox) {
	data->file_path = NULL;
	data->locked = true;

	data->scrypt_n = 15;
	data->scrypt_r = 8;
	data->scrypt_p = 1;

	data->name = NULL;
	data->data = NULL;
}

tox_data* data_init_new(uint8_t *path, uint8_t *username, uint8_t *password) {
	tox_data *data = (tox_data*)malloc(sizeof tox_data);
	_data_init(data);

	file_path = (uint8_t*)malloc(strlen(path));
	strcpy(file_path, path);

	data->name = (uint8_t*)malloc(strlen(username));
	strcpy(data->name, username);

	_gen_key_new(data, password);
	memset(password, 0, strlen(password));

	return data;
}

tox_data* data_init_load(uint8_t *path) {
	tox_data *data = (tox_data*)malloc(sizeof tox_data);
	_data_init(data);

	file_path = (uint8_t*)malloc(strlen(path));
	strcpy(file_path, path);

	File *file = fopen(path, "r");
	if(file == NULL)
		return file;

	//check magic
	char magic[4];
	fgets(magic, 4, file);
	if(memcmp(magic,&"libe",4) != 0)
		return NULL;

	//read time last saved
	fread(&data->time_saved, 8, 1, file);

	//read name
	uint16_t name_length;
	fread(&name_length, 2, 1, file);
	data->name = (uint8_t*)malloc(name_length);
	fread(data->name, 1, name_length, file)
	//check for nul-terminated name string
	if(data->name[name_length - 1] != nul) {
		realloc(data->name, name_length + 1);
		data->name[name_length] = nul;
	}

	//scrypt vars
	fread(&data->scrypt_n, 4, 1, file);
	fread(&data->scrypt_r, 4, 1, file);
	fread(&data->scrypt_p, 4, 1, file);

	//salt & nonce
	fread(data->salt, 1, 24, file);
	fread(data->nonce, 1, 24, file);

	//block two
	fread(&data->block_two_length, 8, 1);
	data->block_two_offset = ftell(file);

	fclose(file);
	return data;
}

void data_close(tox_data *data) {
	free(data->file_path);
	free(data->name);
	free(data->data);
	free(data);
}

int data_unlock(tox_data *data, uint8_t *password) {
	if(!data->locked)
		return -1;

	//load encrypted block
	File *file = fopen(data->file_path, "r");

	uint8_t block_two_encrypted[data->block_two_length],
			block_two_plaintext[data->block_two_length];

	fseek(data->block_two_offset, file);
	fread(block_two_encrypted, 1, data->block_two_length);

	fclose(file);

	//derive key from file
	_gen_key(data, password, data->encrypted_key);

	//decrypt block
	if(crypto_secretbox_open(block_two_plaintext, block_two_encrypted, block_two_length, data->nonce, data->encrypted_key) != 0)
		return -1;

	//check magic
	char magic[4];
	memcpy(magic, block_two_plaintext + 32, 4);
	if(memcmp(magic, &"rtas",4) != 0)
		return -1;

	//load for future use
	if(data->data != nullptr)
		free(data->data);
	data->data_length = block_two_length - 36;
	data->data = (uint8_t*)malloc(data->data_length);
	memcpy(data->data, block_two_plaintext + 36, data->data_length);

	//check against loaded scrypt values being too small
	if(data->scrypt_n < 15)
		data->scrypt_n = 15;
	if(data->scrypt_r < 8)
		data->scrypt_r = 8;

	/* Generate a new key for future saving.
	 * This somewhat more secure than keeping the user password around in plaintext in
	 * the ram (keeping in mind, of course, that it's already game-over if the client is
	 * compromised). Still though - it's the thought that counts.
	 */
	_gen_key_new(data, password);

	memset(block_two_plaintext, 0, block_two_length);

	data->locked = false;

	return 0;
}

/* ------------- REQUIRES UNLOCKING ------------- */
int data_lock(tox_data *data) {
	if(data->locked)
		return -1;

	data_flush(data);

	memset(data->data, 0, data->data_length);
	memset(data->encrypted_key, 0, 32);

	data->locked = true;
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
	 * the profile should have access to it, rather than having stumbled upon an unlocked
	 * computer.
	 */
	if(strcmp((const char*)key, (const char*)data->encrypted_key) != 0)
		return -1;

	_gen_key_new(data, new_password);
	return 0;
}

int data_write_messenger(tox_data *data, uint8_t *buffer, size_t length) {
	if(data->locked)
		return -1;

	if(data->data != NULL)
		free(data->data);

	data->data_length = length;
	data->data = (uint8_t*)malloc(length);
	memcpy(data->data, buffer, length);
	data_flush(data);

	return 0;
}

size_t data_read_messenger(tox_data *data, uint8_t **buffer) {
	if(data->locked)
		return -1;

	*buffer = (uint8_t*)malloc(data->data_length);
	memcpy(*buffer, data->data, data->data_length);
	return data->data_length;
}

int data_flush(tox_data *data) {
	if(data->locked)
		return -1;

	/* Create block two */
	size_t block_two_size = data->data_length + 36, total_length;
	uint8_t block_two_plaintext[block_two_size], block_two_encrypted[block_two_size];
	uint8_t magic2[4] = {0x72, 0x74, 0x61, 0x73};

	memcpy(block_two_plaintext + 32, magic2, 4);
	memcpy(block_two_plaintext + 32 + 4, data->data, data->data_length);

	//required zerobytes
	memset(block_two_plaintext, 0, 32);

	/* Encrypt block two */
	if(crypto_secretbox(block_two_encrypted, block_two_plaintext, block_two_size, data->nonce, data->encrypted_key) != 0)
		return -1;
	memset(block_two_plaintext, 0, block_two_size);

	File *file = fopen(data->file_path, "w+");

	/* Compose entire file */
	//determine file size & create buffer
	uint16_t name_length = strlen(data->name);
	totalLength = blockTwoSize + name_length + 82;
	uint8_t buffer[total_length];

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

	fclose(file);
	return 0;
}