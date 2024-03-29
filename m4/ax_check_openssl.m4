# SPDX-License-Identifier: FSFAP
#
# ===========================================================================
#     https://www.gnu.org/software/autoconf-archive/ax_check_openssl.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CHECK_OPENSSL([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for OpenSSL in a number of default spots, or in a user-selected
#   spot (via --with-openssl).  Sets
#
#     OPENSSL_CFLAGS to the include directives required
#     OPENSSL_LIBS to the -l directives required
#     OPENSSL_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets OPENSSL_CFLAGS such that source files should use the
#   openssl/ directory in include directives:
#
#     #include <openssl/hmac.h>
#
# LICENSE
#
#   Copyright (c) 2009,2010 Zmanda Inc. <http://www.zmanda.com/>
#   Copyright (c) 2009,2010 Dustin J. Mitchell <dustin@zmanda.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 11

AU_ALIAS([CHECK_SSL], [AX_CHECK_OPENSSL])
AC_DEFUN([AX_CHECK_OPENSSL], [
    found=false
    AC_PROG_SED
    AC_ARG_WITH([openssl],
        [AS_HELP_STRING([--with-openssl=DIR],
            [root of the OpenSSL directory])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-openssl value])
              ;;
            *) ssldirs="$withval"
              ;;
            esac
        ], [
            # if ssldirs is set, do not try to use pkg-config to locate openssl
            if test x"$ssldirs" = x""; then
                # if pkg-config is installed and openssl has installed a .pc file,
                # then use that information and don't search ssldirs
                AC_CHECK_TOOL([PKG_CONFIG], [pkg-config])
                if test x"$PKG_CONFIG" != x""; then
                    OPENSSL_LDFLAGS=`$PKG_CONFIG openssl --libs-only-L 2>/dev/null`
                    if test $? = 0; then
                        OPENSSL_LIBS=`$PKG_CONFIG openssl --libs-only-l 2>/dev/null`
                        OPENSSL_CFLAGS=`$PKG_CONFIG openssl --cflags-only-I 2>/dev/null`
                        OPENSSL_VERSION=`$PKG_CONFIG openssl --modversion 2>/dev/null`
                        found=true
                    fi
                fi
                # no such luck; use some default ssldirs
                if ! $found; then
                    ssldirs="/usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr"
                fi
            fi
        ]
        )


    # note that we #include <openssl/foo.h>, so the OpenSSL headers have to be in
    # an 'openssl' subdirectory

    if ! $found; then
        OPENSSL_CFLAGS=
        for ssldir in $ssldirs; do
            AC_MSG_CHECKING([for include/openssl/ssl.h in $ssldir])
            if test -f "$ssldir/include/openssl/ssl.h"; then
                OPENSSL_CFLAGS="-I$ssldir/include"
                OPENSSL_LDFLAGS="-L$ssldir/lib"
                OPENSSL_LIBS="-lssl -lcrypto"
                OPENSSL_VERSION=`$SED -ne 's/.*OPENSSL_VERSION_STR[^"]*"\([^"]*\)".*/\1/p;' $ssldir/include/openssl/opensslv.h`
                if test -z "$OPENSSL_VERSION"; then
                  OPENSSL_VERSION=`$SED -ne 's/.*OPENSSL_VERSION_TEXT[^"]*"\([^"]*\)".*/\1/p;' $ssldir/include/openssl/opensslv.h`
                fi
                found=true
                AC_MSG_RESULT([yes])
                break
            else
                AC_MSG_RESULT([no])
            fi
        done

        # if the file wasn't found, well, go ahead and try the link anyway -- maybe
        # it will just work!
    fi

    # try the preprocessor and linker with our new flags,
    # being careful not to pollute the global LIBS, LDFLAGS, and CPPFLAGS

    AC_MSG_CHECKING([whether compiling and linking against OpenSSL works])
        "OPENSSL_LIBS=$OPENSSL_LIBS; OPENSSL_CFLAGS=$OPENSSL_CFLAGS" >&AS_MESSAGE_LOG_FD

    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
    LIBS="$OPENSSL_LIBS $LIBS"
    CPPFLAGS="$OPENSSL_CFLAGS $CPPFLAGS"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([#include <openssl/ssl.h>], [SSL_new(NULL)])],
        [
            AC_MSG_RESULT([yes])
            $1
        ], [
            AC_MSG_RESULT([no])
            $2
        ])
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"

    AC_SUBST([OPENSSL_CFLAGS])
    AC_SUBST([OPENSSL_LIBS])
    AC_SUBST([OPENSSL_LDFLAGS])
    AC_SUBST([OPENSSL_VERSION])
])
