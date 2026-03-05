#ifndef HASH_H
#define HASH_H

#include "common.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

/* Fonctions */
int  hash_sha256_file(const char *filepath, char *output_hash);
int  hash_sha256_string(const char *input, char *output_hash);
int  hash_compare(const char *hash1, const char *hash2);
void hash_print(const char *filepath, const char *hash);

#endif
