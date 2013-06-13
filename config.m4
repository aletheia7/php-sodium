PHP_ARG_WITH(sodium, for sodium support,
[  --with-sodium             Include sodium support])

PHP_ARG_ENABLE(sodium, whether to enable sodium support,
[  --enable-sodium           Enable sodium support])

if test "$PHP_SODIUM" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-sodium -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/sodium.h"  # you most likely want to change this
  dnl if test -r $PHP_SODIUM/$SEARCH_FOR; then # path given as parameter
  dnl   SODIUM_DIR=$PHP_SODIUM
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for sodium files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       SODIUM_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$SODIUM_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the sodium distribution])
  dnl fi

  dnl # --with-sodium -> add include path
  dnl PHP_ADD_INCLUDE($SODIUM_DIR/include)

  dnl # --with-sodium -> check for lib and symbol presence
  dnl LIBNAME=sodium # you may want to change this
  dnl LIBSYMBOL=sodium # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $SODIUM_DIR/lib, SODIUM_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_SODIUMLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong sodium lib version or lib not found])
  dnl ],[
  dnl   -L$SODIUM_DIR/lib -lm
  dnl ])
  dnl
  dnl PHP_SUBST(SODIUM_SHARED_LIBADD)

  PHP_NEW_EXTENSION(sodium, sodium.c, $ext_shared)
fi
