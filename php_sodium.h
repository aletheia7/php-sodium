/* {{{ LGPL License

php-sodium License

Copyright 2013 Erik Haller <Erik dot Haller at gmail dot com>. All rights reserved.

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

#ifndef PHP_SODIUM_H
#define PHP_SODIUM_H

#define PHP_SODIUM_VERSION "1.0.0"
#define PHP_SODIUM_EXTNAME "sodium"
#define PHP_SODIUM_NS "sodium"

extern zend_module_entry sodium_module_entry;

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(sodium);
PHP_MSHUTDOWN_FUNCTION(sodium);
PHP_MINFO_FUNCTION(sodium);

#define PHP_SODIUM_NONCE (php_sodium_nonce *) zend_object_store_get_object(getThis() TSRMLS_CC);

#define PHP_SODIUM_KEY (php_sodium_key *) zend_object_store_get_object(getThis() TSRMLS_CC);


#define PHP_SODIUM_E_GENERAL (1<<0L)
#define PHP_SODIUM_E_BAD_NONCE (1<<1L)
#define PHP_SODIUM_E_LOAD_PUBLICKEY (1<<2L)
#define PHP_SODIUM_E_LOAD_SECRETKEY (1<<3L)
#define PHP_SODIUM_E_BAD_PUBLICKEY (1<<4L)
#define PHP_SODIUM_E_BAD_SECRETKEY (1<<5L)
#define PHP_SODIUM_E_KEYPAIR_FAILED (1<<6L)
#define PHP_SODIUM_E_BOX_FAILED (1<<7L)
#define PHP_SODIUM_E_BOX_OPEN_FAILED (1<<8L)
#define PHP_SODIUM_E_BEFORENM_FAILED (1<<9L)
#define PHP_SODIUM_E_AFTERNM_BOX_FAILED (1<<10L)
#define PHP_SODIUM_E_AFTERNM_BOX_OPEN_FAILED (1<<11L)
#define PHP_SODIUM_E_LOAD_PRECOMPKEY (1<<12L)

#define PHP_SODIUM_ERROR_HANDLING_INIT() zend_error_handling error_handling;

#define PHP_SODIUM_ERROR_HANDLING_THROW() zend_replace_error_handling(EH_THROW, php_sodium_crypto_exception_entry, &error_handling TSRMLS_CC);

#define PHP_SODIUM_ERROR_HANDLING_RESTORE() zend_restore_error_handling(&error_handling TSRMLS_CC);

/* PHP 5.4 */
#if PHP_VERSION_ID < 50399
# define object_properties_init(zo, class_type) { \
			zval *tmp; \
			zend_hash_copy((*zo).properties, \
							&class_type->default_properties, \
							(copy_ctor_func_t) zval_add_ref, \
							(void *) &tmp, \
							sizeof(zval *)); \
		 }
#endif

#endif /* PHP_SODIUM_H */
/*
vim: fdm=marker
*/
