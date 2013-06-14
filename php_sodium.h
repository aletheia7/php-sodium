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
