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

zend_class_entry *php_crypto_entry;
static zend_object_handlers crypto_object_handlers;

/* {{{ proto crypto crypto::__construct() 
	ctor
*/
PHP_METHOD(crypto, __construct) { }
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
	Returns a length of random bytes
*/
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

ZEND_BEGIN_ARG_INFO_EX(ai_crypto__construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_crypto_keypair, 0, 0, 2)
	ZEND_ARG_INFO(1, public_key)
	ZEND_ARG_INFO(1, secret_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_crypto_box, 0, 0, 4)
	ZEND_ARG_INFO(0, plain_text)
	ZEND_ARG_INFO(0, nonce)
	ZEND_ARG_INFO(0, public_key)
	ZEND_ARG_INFO(0, secret_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_crypto_box_open, 0, 0, 4)
	ZEND_ARG_INFO(0, encrypted_text)
	ZEND_ARG_INFO(0, nonce)
	ZEND_ARG_INFO(0, public_key)
	ZEND_ARG_INFO(0, secret_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_crypto_random_bytes, 0, 0, 1)
	ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

/* {{{ php_crypto_class_methods[] 
*/
static zend_function_entry php_crypto_class_methods[] = {
	PHP_ME(crypto, __construct, ai_crypto__construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
	PHP_ME(crypto, keypair, ai_crypto_keypair, ZEND_ACC_PUBLIC)
	PHP_ME(crypto, box, ai_crypto_box, ZEND_ACC_PUBLIC)
	PHP_ME(crypto, box_open, ai_crypto_box_open, ZEND_ACC_PUBLIC)
	PHP_ME(crypto, random_bytes, ai_crypto_random_bytes, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
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
	zend_class_entry ce_crypto;
	INIT_NS_CLASS_ENTRY(ce_crypto, PHP_SODIUM_NS, "crypto", php_crypto_class_methods);
	memcpy(&crypto_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_crypto_entry = zend_register_internal_class(&ce_crypto TSRMLS_CC);

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
