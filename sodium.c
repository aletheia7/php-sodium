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

static int le_crypto;

zend_class_entry *php_sodium_crypto_entry;
static zend_object_handlers php_sodium_crypto_object_handlers;

zend_class_entry *php_sodium_nonce_entry;
static zend_object_handlers php_sodium_nonce_object_handlers;

typedef struct _php_sodium_nonce {
	zend_object std;
	unsigned char *last;
	unsigned char *current;
} php_sodium_nonce;

typedef struct _php_sodium_nonce_data {
	struct timeval	ts;
	unsigned char rand[8];
	long long counter; 
} php_sodium_nonce_data;

/* {{{ php_bin2hex */
static char hexconvtab[] = "0123456789abcdef";

static char *php_bin2hex(const unsigned char *old, const size_t oldlen, size_t *newlen)
{
	register unsigned char *result = NULL;
	size_t i, j;

	result = (unsigned char *) safe_emalloc(oldlen, 2 * sizeof(char), 1);
	
	for (i = j = 0; i < oldlen; i++) {
		result[j++] = hexconvtab[old[i] >> 4];
		result[j++] = hexconvtab[old[i] & 15];
	}
	result[j] = '\0';

	if (newlen) 
		*newlen = oldlen * 2 * sizeof(char);

	return (char *)result;
}
/* }}} */

#define PHP_SODIUM_NONCE (php_sodium_nonce *) zend_object_store_get_object(getThis() TSRMLS_CC);

/* {{{ static void php_sodium_nonce_free_object_storage(void *object TSRMLS_DC) { */
static void php_sodium_nonce_free_object_storage(void *object TSRMLS_DC) {

	php_sodium_nonce *intern = (php_sodium_nonce *) object;

	if(! intern) {
		return;
	}

	if(intern->last) {
		efree(intern->last);
		intern->last = NULL;
	}

	if(intern->current) {
		efree(intern->current);
		intern->current = NULL;
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

/* {{{ php_sodium_nonce_destroy(php_sodium_nonce *intern */
static void php_sodium_nonce_destroy(php_sodium_nonce *internal) {

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

/* {{{ proto void crypto::keypair(string &$public_key, string &$secret_key) 
	Generates a new $public_key and $secret_key
*/
PHP_METHOD(crypto, keypair)
{
	zval *pk;
	zval *sk;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &pk, &sk) == FAILURE) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed parsing parms");
		RETURN_FALSE;
	}

	zval_dtor(pk);
	zval_dtor(sk);
	unsigned char *pkout = safe_emalloc(crypto_box_PUBLICKEYBYTES + 1, sizeof(unsigned char), 1);
	unsigned char *skout = safe_emalloc(crypto_box_SECRETKEYBYTES + 1, sizeof(unsigned char), 1);
	int rc = crypto_box_keypair(pkout, skout);
	
	if(rc != 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "crypto_box_keypair failed: %d", rc);
		RETURN_FALSE;
	}

	*(pkout + crypto_box_PUBLICKEYBYTES) = 0x0;
	*(skout + crypto_box_SECRETKEYBYTES) = 0x0;

	ZVAL_STRINGL(pk, pkout, crypto_box_PUBLICKEYBYTES, 0);
	ZVAL_STRINGL(sk, skout, crypto_box_SECRETKEYBYTES, 0);
}
/* }}} */

/* {{{ proto string crytpo::box(string $plain_text, string $nonce, string $receiver_public_key, string $sender_secret_key) 
	Encrypts $plain_text with $nonce and keys
*/
PHP_METHOD(crypto, box)
{
	unsigned char *c, *m, *plain_text, *n, *pk, *sk;  
	int plain_text_len, n_len, pk_len, sk_len; 

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss", &plain_text, &plain_text_len, &n, &n_len, &pk, &pk_len, &sk, &sk_len) == FAILURE) {
		RETURN_FALSE;
	}

	if(n_len != crypto_box_NONCEBYTES) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Nonce length must be %d bytes. Actual length is %d bytes", crypto_box_NONCEBYTES, n_len);	
		RETURN_FALSE;
	}

	if(pk_len != crypto_box_PUBLICKEYBYTES) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "$receiver_public_key length must be %d bytes. Actual length is %d bytes", crypto_box_PUBLICKEYBYTES, pk_len);	
		RETURN_FALSE;
	}

	if(sk_len != crypto_box_SECRETKEYBYTES) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "$send_secret_key length must be %d bytes. Actual length is %d bytes", crypto_box_SECRETKEYBYTES, sk_len);	
		RETURN_FALSE;
	}

	int m_len = crypto_box_ZEROBYTES + plain_text_len;
	m = safe_emalloc(m_len, sizeof(unsigned char), 1);
	memset(m, 0x0, crypto_box_ZEROBYTES); 
	memcpy(m + crypto_box_ZEROBYTES, plain_text, plain_text_len);

	c = safe_emalloc(m_len + 1, sizeof(unsigned char), 1);
	int rc = crypto_box(c, m, m_len, n, pk, sk);
	efree(m);

	if(rc == 0) {
		*(c + m_len) = 0x0;
		RETVAL_STRINGL(c + crypto_box_BOXZEROBYTES, m_len - crypto_box_BOXZEROBYTES, 1);
	}
	else {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "crypto_box failed: %d", rc);
		RETVAL_FALSE;
	}

	efree(c);
}
/* }}} */

/* {{{ proto string crytpo::box(string $encrypted_text, string $nonce, string $send_public_key, string $receiver_secret_key) 
	Decrypts $encrypted_text with $nonce and keys
*/
PHP_METHOD(crypto, box_open)
{
	unsigned char *m, *c, *encrypted_text, *n, *pk, *sk;  
	int encrypted_text_len, n_len, pk_len, sk_len; 

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss", &encrypted_text, &encrypted_text_len, &n, &n_len, &pk, &pk_len, &sk, &sk_len) == FAILURE) {
		RETURN_FALSE;
	}

	if(encrypted_text_len <= crypto_box_BOXZEROBYTES) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Encrypted text must be at least %d bytes. Actual length is %d bytes", crypto_box_BOXZEROBYTES + 1, encrypted_text_len);	
		RETURN_FALSE;
	}

	if(n_len != crypto_box_NONCEBYTES) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Nonce length must be %d bytes. Actual length is %d bytes", crypto_box_NONCEBYTES, n_len);	
		RETURN_FALSE;
	}

	if(pk_len != crypto_box_PUBLICKEYBYTES) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "$receiver_public_key length must be %d bytes. Actual length is %d bytes", crypto_box_PUBLICKEYBYTES, pk_len);	
		RETURN_FALSE;
	}

	if(sk_len != crypto_box_SECRETKEYBYTES) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "$send_secret_key length must be %d bytes. Actual length is %d bytes", crypto_box_SECRETKEYBYTES, sk_len);	
		RETURN_FALSE;
	}

	int c_len = encrypted_text_len - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES; 
	c = safe_emalloc(c_len, sizeof(unsigned char), 1);
	memset(c, 0x0, crypto_box_BOXZEROBYTES); 
	memcpy(c + crypto_box_BOXZEROBYTES, encrypted_text, encrypted_text_len);

	m = safe_emalloc(c_len + 1, sizeof(unsigned char), 1);
	int rc = crypto_box(m, c, c_len, n, pk, sk);
	efree(c);

	if(rc == 0) {
		*(m + c_len) = 0x0;
		RETVAL_STRINGL(crypto_box_ZEROBYTES + m, encrypted_text_len - crypto_box_BOXZEROBYTES, 1);
	}
	else {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "crypto_box_open failed: %d", rc);
		RETVAL_FALSE;
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

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &length) == FAILURE) {
		RETURN_FALSE;
	}

	b = safe_emalloc(length + 1, sizeof(unsigned char), 1);

	randombytes(b, length);
	*(b + length) = 0x0;
	RETURN_STRINGL(b, length, 0);
}
/* }}} */

/* {{{ proto nonce nonce::__construct() 
	ctor */
PHP_METHOD(nonce, __construct)
{
	php_sodium_nonce *intern = PHP_SODIUM_NONCE;
	unsigned char b[8];
	php_sodium_nonce_data *d;

	intern->current = safe_emalloc(1, sizeof(php_sodium_nonce_data), 0);
	memset(intern->current, 0, sizeof(php_sodium_nonce_data));
	d = (php_sodium_nonce_data *) intern->current;
	gettimeofday(&d->ts, NULL);
	//randombytes(d->rand, sizeof(d->rand));
	d->counter = 0xffffffff; 

	size_t newlen;
	unsigned char *hex = php_bin2hex(intern->current, sizeof(php_sodium_nonce_data), &newlen);
	php_printf("current: %d %s %d size: %d\n", newlen, hex, __LINE__, sizeof(php_sodium_nonce_data));
	efree(hex);
}
/* }}} */

/* {{{ proto nonce::__destruct() 
	dtor */
PHP_METHOD(nonce, __destruct)
{
}
/* }}} */

/* {{{ proto nonce nonce::increment() 
	Increment nonce by 1 */
PHP_METHOD(nonce, increment)
{
	php_sodium_nonce *nonce = PHP_SODIUM_NONCE;
}
/* }}} */

/* {{{ proto mixed nonce::set_nonce(string $new_nonce]) 
	  $affirm_greater => if current_nonce < new_nonce, set last_nonce, current_nonce and return nonce object, or return false on current_nonce >= new_nonce
	! $affirm_greater => set last_nonce = current_nonce, current = new_once, return nonce object
*/
PHP_METHOD(nonce, set_nonce)
{

	//if(memcmp() < 0)
}
/* }}} */

/* {{{ ZEND_BEGIN_ARG_INFO */
ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto__construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto__destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto_keypair, 0, 0, 2)
	ZEND_ARG_INFO(1, public_key)
	ZEND_ARG_INFO(1, secret_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto_box, 0, 0, 4)
	ZEND_ARG_INFO(0, plain_text)
	ZEND_ARG_INFO(0, nonce)
	ZEND_ARG_INFO(0, public_key)
	ZEND_ARG_INFO(0, secret_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto_box_open, 0, 0, 4)
	ZEND_ARG_INFO(0, encrypted_text)
	ZEND_ARG_INFO(0, nonce)
	ZEND_ARG_INFO(0, public_key)
	ZEND_ARG_INFO(0, secret_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_crypto_random_bytes, 0, 0, 1)
	ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_nonce__construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_nonce__destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_nonce_increment, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_sodium_nonce_set_nonce, 0, 0, 1)
	ZEND_ARG_INFO(0, nonce)
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

/* {{{ php_sodium_nonce_class_methods[] */
static zend_function_entry php_sodium_nonce_class_methods[] = {
	PHP_ME(nonce, __construct, ai_sodium_nonce__construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
	PHP_ME(nonce, __destruct, ai_sodium_nonce__destruct, ZEND_ACC_PUBLIC|ZEND_ACC_DTOR)	
	PHP_ME(nonce, increment, ai_sodium_nonce_increment, ZEND_ACC_PUBLIC)
	PHP_ME(nonce, set_nonce, ai_sodium_nonce_set_nonce, ZEND_ACC_PUBLIC)
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
	zend_class_entry ce_sodium_crypto;
	INIT_NS_CLASS_ENTRY(ce_sodium_crypto, PHP_SODIUM_NS, "crypto", php_sodium_crypto_class_methods);
	memcpy(&php_sodium_crypto_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_sodium_crypto_entry = zend_register_internal_class(&ce_sodium_crypto TSRMLS_CC);

	zend_class_entry ce_sodium_nonce;
	INIT_NS_CLASS_ENTRY(ce_sodium_nonce, PHP_SODIUM_NS, "nonce", php_sodium_nonce_class_methods);
	ce_sodium_nonce.create_object = php_sodium_nonce_ctor;
	memcpy(&php_sodium_nonce_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_sodium_nonce_entry = zend_register_internal_class(&ce_sodium_nonce TSRMLS_CC);
	/*zend_declare_property_null(php_sodium_nonce_entry, "last", strlen("last"), ZEND_ACC_PROTECTED TSRMLS_CC);
	zend_declare_property_null(php_sodium_nonce_entry, "current", strlen("current"), ZEND_ACC_PROTECTED TSRMLS_CC);*/

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
	php_info_print_table_end();
}
/* }}} */

#ifdef COMPILE_DL_SODIUM
ZEND_GET_MODULE(sodium)
#endif
/*
vim: fdm=marker
*/
