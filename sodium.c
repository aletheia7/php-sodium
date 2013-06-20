/* {{{ LGPL License 
php-sodium License

Copyright 2013 Erik Haller. All rights reserved.

This file is part of php-sodium.

    php-sodium is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    php-sodium is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with php-sodium.  If not, see <http://www.gnu.org/licenses/>
}}} */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_sodium.h"
#include "sodium.h"
#include "Zend/zend_exceptions.h"

static int le_crypto;

zend_class_entry *php_sodium_crypto_entry;
static zend_object_handlers php_sodium_crypto_object_handlers;

zend_class_entry *php_sodium_nonce_entry;
static zend_object_handlers php_sodium_nonce_object_handlers;

zend_class_entry *php_sodium_public_key_entry;
static zend_object_handlers php_sodium_public_key_object_handlers;

zend_class_entry *php_sodium_secret_key_entry;
static zend_object_handlers php_sodium_secret_key_object_handlers;

zend_class_entry *php_sodium_crypto_exception_entry;

typedef struct _php_sodium_nonce_data {
	struct timeval	ts;
	unsigned char rand[8];
	unsigned long long counter; 
} php_sodium_nonce_data;

typedef struct _php_sodium_nonce {
	zend_object std;
	unsigned char *last;
	unsigned char *current;
	php_sodium_nonce_data *data;
} php_sodium_nonce;

typedef struct _php_sodium_key {
	zend_object std;
	unsigned char *public;
	unsigned char *secret;
} php_sodium_key;

static int php_sodium_little_endian;

/* {{{ void lltos(long long v, sizeof(v), s, direction) 
	Converts a long long to string s lltos is a ptr set to lltos_big or llto_little for corrent endian behavior
*/
static void (*lltos)(void *v, size_t vsize, unsigned char *s, int direction);
/* }}} */

/* {{{ lltos_big */
static void lltos_big(void *v, size_t vsize, unsigned char *s, int direction) {

	unsigned char *p = (unsigned char *) v;
	int i = 0; 
	int max = vsize - 1;

	for (; i <= max ; i++) {

		if (direction) {
			s[i] = p[i];
		}
		else {
			p[i] = s[i];
		}
	}
}
/* }}} */

/* {{{ lltos_little */
static void lltos_little(void *v, size_t vsize, unsigned char *s, int direction) {

	unsigned char *p = (unsigned char *) v;
	int i = 0; 
	int max = vsize - 1;

	for (; i <= max ; i++) {

		if (direction) {
			s[max - i] = p[i];
		}
		else {
			p[i] = s[max - i];
		}
	}
}
/* }}} */

/* {{{ php_sodium_hex */
static char *php_sodium_hex(const unsigned char *old, const size_t oldlen) {

	static char hexconvtab[] = "0123456789abcdef";
	register unsigned char *result = NULL;
	size_t i, j;
	int result_len = (oldlen * 2);
	result = (unsigned char *) safe_emalloc(result_len + 1, sizeof(unsigned char), 1);
	*(result + result_len) = 0;
	
	for (i = j = 0; i < oldlen; i++) {
		result[j++] = hexconvtab[old[i] >> 4];
		result[j++] = hexconvtab[old[i] & 15];
	}

	return (char *)result;
}
/* }}} */

/* {{{ php_hex2bin(const unsignec char *old, const size_t oldlen, size_t *newlen) 
	(from php 5.4 string.c)
*/
static char *php_hex2bin(const unsigned char *old, const size_t oldlen, size_t *newlen) {

    size_t target_length = oldlen >> 1;
    register unsigned char *str = (unsigned char *)safe_emalloc(target_length, sizeof(char), 1);
    size_t i, j;
    for (i = j = 0; i < target_length; i++) {
        char c = old[j++];
        if (c >= '0' && c <= '9') {
            str[i] = (c - '0') << 4;
        } else if (c >= 'a' && c <= 'f') {
            str[i] = (c - 'a' + 10) << 4;
        } else if (c >= 'A' && c <= 'F') {
            str[i] = (c - 'A' + 10) << 4;
        } else {
            efree(str);
            return NULL;
        }
        c = old[j++];
        if (c >= '0' && c <= '9') {
            str[i] |= c - '0';
        } else if (c >= 'a' && c <= 'f') {
            str[i] |= c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            str[i] |= c - 'A' + 10;
        } else {
            efree(str);
            return NULL;
        }
    }
    str[target_length] = '\0';

    if (newlen)
        *newlen = target_length;

    return (char *)str;
}
/* }}} */

/* {{{
	Used for testing endian
	reverse_num((unsigned char *) &a, (unsigned char *) &t, sizeof(a));
void reverse_num(unsigned char *in, unsigned char *out, size_t size) {

	int i;

	for(i = 0; i < size; i++) {

		out[i] = in[size - i - 1];
	}
}
 }}} */

/* {{{ static void php_sodium_nonce_free_object_storage(void *object TSRMLS_DC) */
static void php_sodium_nonce_free_object_storage(void *object TSRMLS_DC) {

	php_sodium_nonce *intern = (php_sodium_nonce *) object;

	if (! intern) {
		return;
	}

	if (intern->last) {

		efree(intern->last);
	}

	if (intern->current) {

		efree(intern->current);
	}

	if (intern->data) {

		efree(intern->data);
	}

	zend_object_std_dtor(&intern->std TSRMLS_CC);
	efree(intern);
}
/* }}} */

/* {{{ zend_object_value php_sodium_nonce_ctor(zend_class_entry *class_type TSRMLS_DC) */
static zend_object_value php_sodium_nonce_ctor(zend_class_entry *class_type TSRMLS_DC) {

	zend_object_value zov;
	php_sodium_nonce *intern;

	intern = (php_sodium_nonce *) emalloc(sizeof(*intern));
	memset(&intern->std, 0, sizeof(zend_object));
	zend_object_std_init(&intern->std, class_type TSRMLS_CC);
	object_properties_init(&intern->std, class_type);
	intern->last = NULL;
	intern->current = NULL;
	intern->data = NULL;

	zov.handle = zend_objects_store_put(
		  intern 
		, NULL
		, (zend_objects_free_object_storage_t) php_sodium_nonce_free_object_storage 
		, NULL TSRMLS_CC
	); 
	zov.handlers = (zend_object_handlers *) &php_sodium_nonce_object_handlers;
	return zov;
}
/* }}} */

/* {{{ static void php_sodium_key_free_object_storage(void *object TSRMLS_DC) */
static void php_sodium_key_free_object_storage(void *object TSRMLS_DC) {

	php_sodium_key *intern = (php_sodium_key *) object;

	if (! intern) {
		return;
	}

	if (intern->public) {
		efree(intern->public);
	}

	if (intern->secret) {
		efree(intern->secret);
	}

	zend_object_std_dtor(&intern->std TSRMLS_CC);
	efree(intern);
}
/* }}} */

/* {{{ zend_object_value php_sodium_key_ctor(zend_class_entry *class_type TSRMLS_DC) */
static zend_object_value php_sodium_key_ctor(zend_class_entry *class_type TSRMLS_DC) {

	zend_object_value zov;
	php_sodium_key *intern;

	intern = (php_sodium_key *) emalloc(sizeof(*intern));
	memset(&intern->std, 0, sizeof(zend_object));
	zend_object_std_init(&intern->std, class_type TSRMLS_CC);
	object_properties_init(&intern->std, class_type);
	intern->public = NULL;
	intern->secret = NULL;

	zov.handle = zend_objects_store_put(
		  intern 
		, NULL
		, (zend_objects_free_object_storage_t) php_sodium_key_free_object_storage 
		, NULL TSRMLS_CC
	); 
	zov.handlers = (zend_object_handlers *) &php_sodium_public_key_object_handlers;
	return zov;
}
/* }}} */

/* {{{ proto crypto crypto::__construct() 
	ctor */
PHP_METHOD(crypto, __construct)
{
}
/* }}} */

/* {{{ proto crypto crypto::__destruct() 
	dtor
*/
PHP_METHOD(crypto, __destruct) { }
/* }}} */

/* {{{ proto mixed crypto::keypair() 
	Generates a new secret_key 
*/
PHP_METHOD(crypto, keypair)
{
	object_init_ex(return_value, php_sodium_secret_key_entry);
	php_sodium_key *key = (php_sodium_key *) zend_object_store_get_object(return_value TSRMLS_CC);
	key->public = safe_emalloc(crypto_box_PUBLICKEYBYTES, sizeof(unsigned char), 1);
	key->secret = safe_emalloc(crypto_box_SECRETKEYBYTES, sizeof(unsigned char), 1);

	int rc = crypto_box_keypair(key->public, key->secret);
	
	if (rc != 0) {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_KEYPAIR_FAILED TSRMLS_CC, "crypto_box_keypair failed: %d", rc);
		return;
	}

	zend_update_property_stringl(php_sodium_secret_key_entry, return_value, "pbin", strlen("pbin"), key->public, crypto_box_PUBLICKEYBYTES TSRMLS_CC);
	zend_update_property_stringl(php_sodium_secret_key_entry, return_value, "sbin", strlen("sbin"), key->secret, crypto_box_SECRETKEYBYTES TSRMLS_CC);
}
/* }}} */

/* {{{ proto string crytpo::box(string $plain_text, nonce $nonce, public_key $receiver, secret_key $sender) 
	Encrypts $plain_text with $nonce and keys
*/
PHP_METHOD(crypto, box)
{
	unsigned char *c, *m, *plain_text;
	zval *zn, *zpk, *zsk;  
	int plain_text_len;
	php_sodium_nonce *nonce;
	php_sodium_key *public_key;
	php_sodium_key *secret_key;

	PHP_SODIUM_ERROR_HANDLING_INIT()
	PHP_SODIUM_ERROR_HANDLING_THROW()

	int rc = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sOOO", &plain_text, &plain_text_len, &zn, php_sodium_nonce_entry, &zpk, php_sodium_public_key_entry, &zsk, php_sodium_secret_key_entry);

	PHP_SODIUM_ERROR_HANDLING_RESTORE()

	if (rc == FAILURE) {

		return;
	}

	nonce = (php_sodium_nonce *) zend_object_store_get_object(zn TSRMLS_CC);

	if (! nonce->current) {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_NONCE TSRMLS_CC, "nonce is missing a current value. Call nonce::next() or nonce::set_nonce()");
		return;
	}

	public_key = (php_sodium_key *) zend_object_store_get_object(zpk TSRMLS_CC);

	if (! public_key->public) {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_LOAD_PUBLICKEY TSRMLS_CC, "public_key is missing a key. Call public_key::load()");
		return;
	}

	secret_key = (php_sodium_key *) zend_object_store_get_object(zsk TSRMLS_CC);

	if (! secret_key->secret) {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_LOAD_SECRETKEY TSRMLS_CC, "secret_key is missing a key. Call secret_key::load()");
		return;
	}

	int m_len = crypto_box_ZEROBYTES + plain_text_len;
	m = safe_emalloc(m_len, sizeof(unsigned char), 1);
	memset(m, 0, crypto_box_ZEROBYTES); 
	memcpy(m + crypto_box_ZEROBYTES, plain_text, plain_text_len);

	c = safe_emalloc(m_len + 1, sizeof(unsigned char), 1);
	rc = crypto_box(c, m, m_len, nonce->current, public_key->public, secret_key->secret);
	efree(m);

	if(rc == 0) {

		*(c + m_len) = 0;
		RETVAL_STRINGL(c + crypto_box_BOXZEROBYTES, m_len - crypto_box_BOXZEROBYTES, 1);
	}
	else {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BOX_FAILED TSRMLS_CC, "crypto_box failed: %d", rc);
		return;
	}

	efree(c);
}
/* }}} */

/* {{{ proto string crytpo::box_open(string $encrypted_text, nonce $nonce, public_key $sender, secret_key $receiver) 
	Decrypts $encrypted_text with $nonce and keys
*/
PHP_METHOD(crypto, box_open)
{
	unsigned char *m, *c, *encrypted_text;
	zval *zn, *zpk, *zsk;
	int encrypted_text_len;
	php_sodium_nonce *nonce;
	php_sodium_key *public_key;
	php_sodium_key *secret_key;

	PHP_SODIUM_ERROR_HANDLING_INIT()
	PHP_SODIUM_ERROR_HANDLING_THROW()

	int rc = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sOOO", &encrypted_text, &encrypted_text_len, &zn, php_sodium_nonce_entry, &zpk, php_sodium_public_key_entry, &zsk, php_sodium_secret_key_entry);

	PHP_SODIUM_ERROR_HANDLING_RESTORE()

	if (rc == FAILURE) {

		return;
	}

	if (encrypted_text_len <= crypto_box_BOXZEROBYTES) {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_NONCE TSRMLS_CC, "Encrypted text must be at least %d bytes. Actual length is %d bytes", crypto_box_BOXZEROBYTES + 1, encrypted_text_len);	
		return;
	}

	nonce = (php_sodium_nonce *) zend_object_store_get_object(zn TSRMLS_CC);

	if (! nonce->current) {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_NONCE TSRMLS_CC, "nonce is missing a current value. Call nonce::next() or nonce::set_nonce()");
		return;
	}

	public_key = (php_sodium_key *) zend_object_store_get_object(zpk TSRMLS_CC);

	if (! public_key->public) {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_LOAD_PUBLICKEY TSRMLS_CC, "public_key is missing a key. Call public_key::load()");
		return;
	}

	secret_key = (php_sodium_key *) zend_object_store_get_object(zsk TSRMLS_CC);

	if (! secret_key->secret) {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_LOAD_SECRETKEY TSRMLS_CC, "secret_key is missing a key. Call secret_key::load()");
		return;
	}

	int c_len = encrypted_text_len - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES; 
	c = safe_emalloc(c_len, sizeof(unsigned char), 1);
	memset(c, 0, crypto_box_BOXZEROBYTES); 
	memcpy(c + crypto_box_BOXZEROBYTES, encrypted_text, encrypted_text_len);

	m = safe_emalloc(c_len + 1, sizeof(unsigned char), 1);
	rc = crypto_box(m, c, c_len, nonce->current, public_key->public, secret_key->secret);
	efree(c);

	if(rc == 0) {

		*(m + c_len) = 0;
		RETVAL_STRINGL(crypto_box_ZEROBYTES + m, encrypted_text_len - crypto_box_BOXZEROBYTES, 1);
	}
	else {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BOX_OPEN_FAILED TSRMLS_CC, "crypto_box_open failed: %d", rc);
		return;
	}

	efree(m);
}
/* }}} */

/* {{{ proto string random_bytes(int $length) 
	Returns a length of random bytes */
PHP_METHOD(crypto, random_bytes)
{
	long length;
	unsigned char *b;

	PHP_SODIUM_ERROR_HANDLING_INIT()
	PHP_SODIUM_ERROR_HANDLING_THROW()

	int rc = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &length);

	PHP_SODIUM_ERROR_HANDLING_RESTORE()

	if (rc == FAILURE) {
		return;
	}

	b = safe_emalloc(length + 1, sizeof(unsigned char), 1);

	randombytes(b, length);
	*(b + length) = 0;
	RETURN_STRINGL(b, length, 0);
}
/* }}} */

/* {{{ proto nonce nonce::__construct() 
	ctor */
PHP_METHOD(nonce, __construct)
{
}
/* }}} */

/* {{{ proto nonce::__destruct() 
	dtor */
PHP_METHOD(nonce, __destruct)
{
}
/* }}} */

/* {{{ proto nonce nonce::next() */
PHP_METHOD(nonce, next)
{
	php_sodium_nonce *nonce = PHP_SODIUM_NONCE;

	if (! nonce->current) {

		nonce->current = safe_emalloc(crypto_box_NONCEBYTES, sizeof(unsigned char), 1);
	}

	if (nonce->data) {

		nonce->data->counter++;
	}
	else {

		nonce->data = safe_emalloc(1, sizeof(php_sodium_nonce_data), 1);
		randombytes(nonce->data->rand, sizeof(nonce->data->rand));
		memcpy(nonce->current + 8, nonce->data->rand, 8);
		nonce->data->counter = 0;
	}

	lltos(&nonce->data->counter, 8, (nonce->current + 16), 1);

	/* If counter wraparound occurs, get new time() */
	if (nonce->data->counter == 0) { 

		gettimeofday(&nonce->data->ts, NULL);
		lltos(&nonce->data->ts.tv_sec, 4, nonce->current, 1);
		lltos(&nonce->data->ts.tv_usec, 4, nonce->current + 4, 1);
	}

	zend_update_property_stringl(php_sodium_nonce_entry, getThis(), "current", strlen("current"), nonce->current, crypto_box_NONCEBYTES TSRMLS_CC);
	RETURN_ZVAL(getThis(), 1, 0);
}
/* }}} */

/* {{{ proto mixed nonce::set_nonce(string $new_nonce [, bool $affirm_greater = true]) 
	  $affirm_greater => if current_nonce < new_nonce, set last_nonce, current_nonce and return nonce object, or return false on current_nonce >= new_nonce
	! $affirm_greater => set last_nonce = current_nonce, current = new_once, return nonce object
*/
PHP_METHOD(nonce, set_nonce)
{
	unsigned char *new_nonce;
	int new_nonce_len;
	zend_bool affirm_greater = 1;
	unsigned char *hex;
	int rc;

	PHP_SODIUM_ERROR_HANDLING_INIT()
	PHP_SODIUM_ERROR_HANDLING_THROW()

	rc = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|b", &new_nonce, &new_nonce_len, &affirm_greater);

	PHP_SODIUM_ERROR_HANDLING_RESTORE()

	if (rc == FAILURE) {

		return;
	}

	if (new_nonce_len != crypto_box_NONCEBYTES) {

		zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_NONCE TSRMLS_CC, "Bad nonce. nonce length must be %d bytes. Actual length is %d bytes.", crypto_box_NONCEBYTES, new_nonce_len);
		return;
	}

	php_sodium_nonce *nonce = PHP_SODIUM_NONCE;

	if (affirm_greater) {

		if (nonce->last) {

			/* Compare struct timeval */
			rc = memcmp(nonce->current, new_nonce, 16; 

			if (rc == -1) {
				
				zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_NONCE TSRMLS_CC, "Bad nonce. First 8 bytes of nonce < current: %d", rc);
				return;
			}
			else if (rc == 0) {
				/* Compare counter */
				rc = memcmp(nonce->current + 16, new_nonce + 16, 8); 

				if (rc < 1) {

					zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_NONCE TSRMLS_CC, "Bad nonce. new nonce less than current nonce: %d", rc);
					return;
				}
			}
		}
	}

	nonce->last = nonce->current;
	nonce->current = estrndup(new_nonce, new_nonce_len);
	zend_update_property_stringl(php_sodium_nonce_entry, getThis(), "current", strlen("current"), nonce->current, crypto_box_NONCEBYTES TSRMLS_CC);
	RETURN_ZVAL(getThis(), 1, 0);
}
/* }}} */

/* {{{ proto public_key::__construct() 
	ctor
*/
PHP_METHOD(public_key, __construct) {}
/* }}} */

/* {{{ proto public_key::__destruct() 
	dtor
*/
PHP_METHOD(public_key, __destruct) {}
/* }}} */

/* {{{ proto mixed public_key::load(string $public_key [, bool $from_hex = true]) 
*/
PHP_METHOD(public_key, load)
{
	unsigned char *public_key;
	int public_key_len;
	zend_bool from_hex = 1;
	unsigned char *public_key_bin;
	int public_key_bin_len;

	PHP_SODIUM_ERROR_HANDLING_INIT()
	PHP_SODIUM_ERROR_HANDLING_THROW()

	int rc = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|b", &public_key, &public_key_len, &from_hex);

	PHP_SODIUM_ERROR_HANDLING_RESTORE()

	if (rc == FAILURE) {

		return;
	}

	php_sodium_key *key = PHP_SODIUM_KEY;

	if (from_hex) {

		if (public_key_len != (crypto_box_PUBLICKEYBYTES * 2)) {

			zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_PUBLICKEY TSRMLS_CC, "Bad public key. Incorrect key length for hex: %d vs %d", public_key_len, (crypto_box_PUBLICKEYBYTES * 2));
			return;
		}

		if (key->public) {

			public_key_bin = php_hex2bin(public_key, crypto_box_PUBLICKEYBYTES * 2, &public_key_bin_len);
			memcpy(key->public, public_key_bin, crypto_box_PUBLICKEYBYTES);
			efree(public_key_bin);
		}
		else {

			key->public = php_hex2bin(public_key, crypto_box_PUBLICKEYBYTES * 2, &public_key_bin_len);
		}
	}
	else {

		if (public_key_len != crypto_box_PUBLICKEYBYTES) {

			zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_PUBLICKEY TSRMLS_CC, "Bad public key. Incorrect key length: %d vs %d", public_key_len, crypto_box_PUBLICKEYBYTES);
			return;
		}
	
		if (key->public) {
				
			memcpy(key->public, public_key, crypto_box_PUBLICKEYBYTES);
		}
		else {

			key->public = estrndup(public_key, public_key_len); 
		}
	}

	RETURN_ZVAL(getThis(), 1, 0);
}
/* }}} */

/* {{{ proto secret_key::__construct() 
	ctor
*/
PHP_METHOD(secret_key, __construct) {}
/* }}} */

/* {{{ proto secret_key::__destruct() 
	dtor
*/
PHP_METHOD(secret_key, __destruct) {}
/* }}} */

/* {{{ proto mixed secret_key::load(string $public_key, string $secret_key [, bool $from_hex = true]) 
*/
PHP_METHOD(secret_key, load)
{
	unsigned char *public_key;
	int public_key_len;
	unsigned char *secret_key;
	int secret_key_len;
	zend_bool from_hex = 1;

	unsigned char *public_key_bin;
	int public_key_bin_len;
	unsigned char *secret_key_bin;
	int secret_key_bin_len;

	PHP_SODIUM_ERROR_HANDLING_INIT()
	PHP_SODIUM_ERROR_HANDLING_THROW()

	int rc = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|b", &public_key, &public_key_len, &secret_key, &secret_key_len, &from_hex);

	PHP_SODIUM_ERROR_HANDLING_RESTORE()

	if (rc == FAILURE) {

		return;
	}

	php_sodium_key *key = PHP_SODIUM_KEY;

	if (from_hex) {

		if (public_key_len != (crypto_box_PUBLICKEYBYTES * 2)) {

			zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_PUBLICKEY TSRMLS_CC, "Bad public key. Incorrect key length for hex: %d vs %d", public_key_len, (crypto_box_PUBLICKEYBYTES * 2));
			return;
		}

		if (secret_key_len != (crypto_box_SECRETKEYBYTES * 2)) {

			zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_SECRETKEY TSRMLS_CC, "Bad secret key. Incorrect key length for hex: %d vs %d", secret_key_len, (crypto_box_SECRETKEYBYTES * 2));
			return;
		}
	
		public_key_bin = php_hex2bin(public_key, crypto_box_PUBLICKEYBYTES * 2, &public_key_bin_len); 

		if (key->public) {
		
			memcpy(key->public, public_key_bin, crypto_box_PUBLICKEYBYTES);
			efree(public_key_bin);
		}
		else {

			key->public = public_key_bin; 
		}

		secret_key_bin = php_hex2bin(secret_key, crypto_box_SECRETKEYBYTES * 2, &secret_key_bin_len); 

		if (key->secret) {

			memcpy(key->secret, secret_key_bin, crypto_box_SECRETKEYBYTES);
			efree(secret_key_bin);
		}
		else {

			key->secret = secret_key_bin; 
		}
	}
	else {
		
		if (public_key_len != crypto_box_PUBLICKEYBYTES) {

			zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_PUBLICKEY TSRMLS_CC, "Bad public key. Incorrect key length for hex: %d vs %d", public_key_len, crypto_box_PUBLICKEYBYTES);
			return;
		}

		if (secret_key_len != crypto_box_SECRETKEYBYTES) {

			zend_throw_exception_ex(php_sodium_crypto_exception_entry, PHP_SODIUM_E_BAD_SECRETKEY TSRMLS_CC, "Bad secret key. Incorrect key length for hex: %d vs %d", secret_key_len, crypto_box_SECRETKEYBYTES);
			return;
		}

		if (key->public) {

			memcpy(key->public, public_key, crypto_box_PUBLICKEYBYTES);
		}
		else {

			key->public = estrndup(public_key, crypto_box_PUBLICKEYBYTES);
		}

		if (key->secret) {

			memcpy(key->secret, secret_key, crypto_box_SECRETKEYBYTES);
		}
		else {

			key->secret = estrndup(secret_key, secret_key_len);
		}
	}
	zend_update_property_stringl(php_sodium_secret_key_entry, getThis(), "pbin", strlen("pbin"), key->public, crypto_box_PUBLICKEYBYTES TSRMLS_CC);
	zend_update_property_stringl(php_sodium_secret_key_entry, getThis(), "sbin", strlen("sbin"), key->secret, crypto_box_SECRETKEYBYTES TSRMLS_CC);
	RETURN_ZVAL(getThis(), 1, 0);
}
/* }}} */

/* {{{ ZEND_BEGIN_ARG_INFO */
ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto__construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto__destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto_keypair, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto_box, 0, 0, 4)
	ZEND_ARG_INFO(0, plain_text)
	ZEND_ARG_INFO(0, nonce)
	ZEND_ARG_INFO(0, receiver)
	ZEND_ARG_INFO(0, sender)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto_box_open, 0, 0, 4)
	ZEND_ARG_INFO(0, encrypted_text)
	ZEND_ARG_INFO(0, nonce)
	ZEND_ARG_INFO(0, sender)
	ZEND_ARG_INFO(0, recever)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto_random_bytes, 0, 0, 1)
	ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_nonce__construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_nonce__destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_nonce_next, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_nonce_set_nonce, 0, 0, 1)
	ZEND_ARG_INFO(0, nonce)
	ZEND_ARG_INFO(0, affirm_greater)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_public_key__construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_public_key__destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_public_key_load, 0, 0, 1)
	ZEND_ARG_INFO(0, public_key)
	ZEND_ARG_INFO(0, from_hex)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_secret_key__construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_secret_key__destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_secret_key_load, 0, 0, 2)
	ZEND_ARG_INFO(0, public_key)
	ZEND_ARG_INFO(0, secret_key)
	ZEND_ARG_INFO(0, from_hex)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ php_sodium_crypto_class_methods[] */
static zend_function_entry php_sodium_crypto_class_methods[] = {
	PHP_ME(crypto, __construct, ai_sodium_crypto__construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
	PHP_ME(crypto, __destruct, ai_sodium_crypto__destruct, ZEND_ACC_PUBLIC|ZEND_ACC_DTOR)
	PHP_ME(crypto, keypair, ai_sodium_crypto_keypair, ZEND_ACC_PUBLIC)
	PHP_ME(crypto, box, ai_sodium_crypto_box, ZEND_ACC_PUBLIC)
	PHP_ME(crypto, box_open, ai_sodium_crypto_box_open, ZEND_ACC_PUBLIC)
	PHP_ME(crypto, random_bytes, ai_sodium_crypto_random_bytes, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ php_sodium_nonce_class_methods[] */
static zend_function_entry php_sodium_nonce_class_methods[] = {
	PHP_ME(nonce, __construct, ai_sodium_nonce__construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
	PHP_ME(nonce, __destruct, ai_sodium_nonce__destruct, ZEND_ACC_PUBLIC|ZEND_ACC_DTOR)	
	PHP_ME(nonce, next, ai_sodium_nonce_next, ZEND_ACC_PUBLIC)
	PHP_ME(nonce, set_nonce, ai_sodium_nonce_set_nonce, ZEND_ACC_PUBLIC)
};
/* }}} */

/* {{{ php_sodium_public_key_methods[] */
static zend_function_entry php_sodium_public_key_class_methods[] = {
	PHP_ME(public_key, __construct, ai_sodium_public_key__construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
	PHP_ME(public_key, load, ai_sodium_public_key_load, ZEND_ACC_PUBLIC)
	PHP_ME(public_key, __destruct, ai_sodium_public_key__destruct, ZEND_ACC_PUBLIC|ZEND_ACC_DTOR)	
};
/* }}} */

/* {{{ php_sodium_secret_key_methods[] */
static zend_function_entry php_sodium_secret_key_class_methods[] = {
	PHP_ME(secret_key, __construct, ai_sodium_secret_key__construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
	PHP_ME(secret_key, load, ai_sodium_secret_key_load, ZEND_ACC_PUBLIC)
	PHP_ME(secret_key, __destruct, ai_sodium_secret_key__destruct, ZEND_ACC_PUBLIC|ZEND_ACC_DTOR)	
};
/* }}} */

/* {{{ sodium_module_entry 
*/
zend_module_entry sodium_module_entry = {

	STANDARD_MODULE_HEADER,
	"sodium",
	NULL,
	PHP_MINIT(sodium),
	PHP_MSHUTDOWN(sodium),
	NULL,
	NULL,
	PHP_MINFO(sodium),
	PHP_SODIUM_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

/* {{{ PHP_MINIT_FUNCTION 
 */
PHP_MINIT_FUNCTION(sodium)
{
	int i  = 1;
	char *p = (char *)&i;
	php_sodium_little_endian = ( (p[0] == 1) ? 1 : 0 );
	lltos = (php_sodium_little_endian == 1 ? lltos_little: lltos_big);

	zend_class_entry ce_sodium_crypto;
	INIT_NS_CLASS_ENTRY(ce_sodium_crypto, PHP_SODIUM_NS, "crypto", php_sodium_crypto_class_methods);
	memcpy(&php_sodium_crypto_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_sodium_crypto_entry = zend_register_internal_class(&ce_sodium_crypto TSRMLS_CC);

	zend_class_entry ce_sodium_nonce;
	INIT_NS_CLASS_ENTRY(ce_sodium_nonce, PHP_SODIUM_NS, "nonce", php_sodium_nonce_class_methods);
	ce_sodium_nonce.create_object = php_sodium_nonce_ctor;
	memcpy(&php_sodium_nonce_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_sodium_nonce_entry = zend_register_internal_class(&ce_sodium_nonce TSRMLS_CC);
	zend_declare_property_null(php_sodium_nonce_entry, "current", strlen("current"), ZEND_ACC_PUBLIC TSRMLS_CC);

	zend_class_entry ce_sodium_public_key;
	INIT_NS_CLASS_ENTRY(ce_sodium_public_key, PHP_SODIUM_NS, "public_key", php_sodium_public_key_class_methods);
	ce_sodium_public_key.create_object = php_sodium_key_ctor;
	memcpy(&php_sodium_public_key_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_sodium_public_key_entry = zend_register_internal_class(&ce_sodium_public_key TSRMLS_CC);
	zend_declare_property_null(php_sodium_public_key_entry, "pbin", strlen("pbin"), ZEND_ACC_PUBLIC TSRMLS_CC);

	zend_class_entry ce_sodium_secret_key;
	INIT_NS_CLASS_ENTRY(ce_sodium_secret_key, PHP_SODIUM_NS, "secret_key", php_sodium_secret_key_class_methods);
	ce_sodium_secret_key.create_object = php_sodium_key_ctor;
	memcpy(&php_sodium_secret_key_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_sodium_secret_key_entry = zend_register_internal_class(&ce_sodium_secret_key TSRMLS_CC);
	zend_declare_property_null(php_sodium_secret_key_entry, "pbin", strlen("pbin"), ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(php_sodium_secret_key_entry, "sbin", strlen("sbin"), ZEND_ACC_PUBLIC TSRMLS_CC);

	zend_class_entry ce_sodium_crypto_exception;
	INIT_NS_CLASS_ENTRY(ce_sodium_crypto_exception, PHP_SODIUM_NS, "crypto_exception", NULL);
	php_sodium_crypto_exception_entry = zend_register_internal_class_ex(&ce_sodium_crypto_exception, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
	zend_declare_class_constant_long(php_sodium_crypto_exception_entry, "BAD_NONCE", strlen("BAD_NONCE"), PHP_SODIUM_E_BAD_NONCE TSRMLS_CC);
	zend_declare_class_constant_long(php_sodium_crypto_exception_entry, "LOAD_PUBLICKEY", strlen("LOAD_PUBLICKEY"), PHP_SODIUM_E_LOAD_PUBLICKEY TSRMLS_CC);
	zend_declare_class_constant_long(php_sodium_crypto_exception_entry, "LOAD_SECRETKEY", strlen("LOAD_SECRETKEY"), PHP_SODIUM_E_LOAD_SECRETKEY TSRMLS_CC);
	zend_declare_class_constant_long(php_sodium_crypto_exception_entry, "BAD_PUBLICKEY", strlen("BAD_PUBLICKEY"), PHP_SODIUM_E_BAD_PUBLICKEY TSRMLS_CC);
	zend_declare_class_constant_long(php_sodium_crypto_exception_entry, "BAD_SECRETKEY", strlen("BAD_SECRETKEY"), PHP_SODIUM_E_BAD_SECRETKEY TSRMLS_CC);
	zend_declare_class_constant_long(php_sodium_crypto_exception_entry, "KEYPAIR_FAILED", strlen("KEYPAIR_FAILED"), PHP_SODIUM_E_KEYPAIR_FAILED TSRMLS_CC);
	zend_declare_class_constant_long(php_sodium_crypto_exception_entry, "BOX_FAILED", strlen("BOX_FAILED"), PHP_SODIUM_E_BOX_FAILED TSRMLS_CC);
	zend_declare_class_constant_long(php_sodium_crypto_exception_entry, "BOX_OPEN_FAILED", strlen("BOX_OPEN_FAILED"), PHP_SODIUM_E_BOX_OPEN_FAILED TSRMLS_CC);

	php_printf("key is %d\n", crypto_box_PUBLICKEYBYTES);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION 
 */
PHP_MSHUTDOWN_FUNCTION(sodium)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION 
 */
PHP_MINFO_FUNCTION(sodium)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "sodium support", "enabled");
	php_info_print_table_header(2, "sodium extension version", PHP_SODIUM_VERSION);
	php_info_print_table_header(2, "sodium library version", sodium_version_string());
	php_info_print_table_header(2, "randombytes implementation name", randombytes_implementation_name());
	php_info_print_table_header(2, "endian", (php_sodium_little_endian == 1 ? "little endian" : "big endian"));
	php_info_print_table_end();
}
/* }}} */

#ifdef COMPILE_DL_SODIUM
ZEND_GET_MODULE(sodium)
#endif
/*
vim: fdm=marker
*/
