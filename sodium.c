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

static int le_sodium;

PHP_FUNCTION(sodium_crypto_box_keypair)
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

		php_error_docref(NULL TSRMLS_CC, E_WARNING, "rc failed with %d", rc);
		RETURN_FALSE;
	}

	*(pkout + crypto_box_PUBLICKEYBYTES) = 0x0;
	*(skout + crypto_box_SECRETKEYBYTES) = 0x0;

	php_printf("rc: %d %d\n", rc, __LINE__);

	ZVAL_STRINGL(pk, pkout, crypto_box_PUBLICKEYBYTES, 0);
	ZVAL_STRINGL(sk, skout, crypto_box_SECRETKEYBYTES, 0);
}

ZEND_BEGIN_ARG_INFO_EX(ai_change_s, 0, 0, 2)
	ZEND_ARG_INFO(1, public_key)
	ZEND_ARG_INFO(1, secret_key)
ZEND_END_ARG_INFO()

/* {{{ sodium_functions[] */
const zend_function_entry sodium_functions[] = {
	PHP_FE(sodium_crypto_box_keypair, ai_change_s)
	PHP_FE_END
};
/* }}} */

/* {{{ sodium_module_entry 
*/
zend_module_entry sodium_module_entry = {

	STANDARD_MODULE_HEADER,
	"sodium",
	sodium_functions,
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
	/* If you have INI entries, uncomment these lines 
	REGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(sodium)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(sodium)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "sodium support", "enabled");
	php_info_print_table_header(2, "sodium extension version", PHP_SODIUM_VERSION);
	php_info_print_table_header(2, "sodium library version", sodium_version_string());
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

#ifdef COMPILE_DL_SODIUM
ZEND_GET_MODULE(sodium)
#endif
/*
vim: fdm=marker
*/
