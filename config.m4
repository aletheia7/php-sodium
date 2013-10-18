PHP_ARG_WITH(sodium, for sodium support,
[  --with-sodium             Include sodium support])

PHP_ARG_ENABLE(sodium, whether to enable sodium support,
[  --enable-sodium           Enable sodium support])

if test "$PHP_SODIUM" != "no"; then
  dnl Write more examples of tests here...

  # --with-sodium -> check with-path
  SEARCH_PATH="/usr/local /usr"     # you might want to change this
  SEARCH_FOR="/include/sodium.h"  # you most likely want to change this
  if test -r $PHP_SODIUM/$SEARCH_FOR; then # path given as parameter
    SODIUM_DIR=$PHP_SODIUM
  else # search default path list
    AC_MSG_CHECKING([for sodium files in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        SODIUM_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi
  dnl
  if test -z "$SODIUM_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please reinstall the sodium distribution])
  fi

  dnl # --with-sodium -> add include path
  PHP_ADD_INCLUDE($SODIUM_DIR/include)

  dnl # --with-sodium -> check for lib and symbol presence

 dnl   PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
 dnl   [
 dnl     PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $SODIUM_DIR/lib, SODIUM_SHARED_LIBADD)
 dnl     AC_DEFINE(HAVE_SODIUMLIB,1,[ ])
 dnl   ],[
 dnl     AC_MSG_ERROR([wrong sodium lib version or lib not found])
 dnl   ],[
 dnl     -L$SODIUM_DIR/lib -lm
 dnl   ])
    PHP_SODIUM_PREFIX=`$PKG_CONFIG libsodium --variable=prefix`
    PHP_SODIUM_LIBS=`$PKG_CONFIG libsodium --libs`
    PHP_SODIUM_INCS=`$PKG_CONFIG libsodium --cflags`
    PHP_EVAL_LIBLINE($PHP_SODIUM_LIBS, SODIUM_SHARED_LIBADD)
    PHP_EVAL_INCLINE($PHP_SODIUM_INCS)
  PHP_SUBST(SODIUM_SHARED_LIBADD)

  PHP_NEW_EXTENSION(sodium, sodium.c, $ext_shared)
fi
