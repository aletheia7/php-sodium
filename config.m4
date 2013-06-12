dnl $Id$
dnl config.m4 for extension php-sodium

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(php-sodium, for php-sodium support,
dnl Make sure that the comment is aligned:
dnl [  --with-php-sodium             Include php-sodium support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(php-sodium, whether to enable php-sodium support,
dnl Make sure that the comment is aligned:
dnl [  --enable-php-sodium           Enable php-sodium support])

if test "$PHP_PHP-SODIUM" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-php-sodium -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/php-sodium.h"  # you most likely want to change this
  dnl if test -r $PHP_PHP-SODIUM/$SEARCH_FOR; then # path given as parameter
  dnl   PHP-SODIUM_DIR=$PHP_PHP-SODIUM
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for php-sodium files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       PHP-SODIUM_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$PHP-SODIUM_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the php-sodium distribution])
  dnl fi

  dnl # --with-php-sodium -> add include path
  dnl PHP_ADD_INCLUDE($PHP-SODIUM_DIR/include)

  dnl # --with-php-sodium -> check for lib and symbol presence
  dnl LIBNAME=php-sodium # you may want to change this
  dnl LIBSYMBOL=php-sodium # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $PHP-SODIUM_DIR/lib, PHP-SODIUM_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_PHP-SODIUMLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong php-sodium lib version or lib not found])
  dnl ],[
  dnl   -L$PHP-SODIUM_DIR/lib -lm
  dnl ])
  dnl
  dnl PHP_SUBST(PHP-SODIUM_SHARED_LIBADD)

  PHP_NEW_EXTENSION(php-sodium, php-sodium.c, $ext_shared)
fi
