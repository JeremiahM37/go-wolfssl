#!/bin/bash

# Usage: ./generateOptions.sh [<wolfssl-prefix-or-source-root>]
#
# If the argument is an installed wolfSSL prefix (containing
# include/wolfssl/options.h), options.go is generated and all cgo-bearing
# files are repointed at that prefix. If the argument is a wolfSSL source
# root (containing wolfssl/options.h), only options.go is generated.
# With no argument, defaults to ../wolfssl as a source root and /usr/local.

OPTIONS_H="../wolfssl/wolfssl/options.h"
PREFIX=""

if [ ! -z "$1" ]; then
    WOLFSSL_PATH="$1"
    echo "Path to wolfSSL was supplied."

    if [ -f "$WOLFSSL_PATH/include/wolfssl/options.h" ]; then
        OPTIONS_H="$WOLFSSL_PATH/include/wolfssl/options.h"
        PREFIX="$WOLFSSL_PATH"
    elif [ -f "$WOLFSSL_PATH/wolfssl/options.h" ]; then
        OPTIONS_H="$WOLFSSL_PATH/wolfssl/options.h"
    else
        echo "Couldn't find options.h, please supply the correct path to wolfSSL."
        exit 99
    fi
else
    echo "No path given, defaulting to ../wolfssl path."
    if [ ! -d ../wolfssl ];then
        echo "Couldn't find wolfSSL in default path, please supply the correct path to wolfSSL."
        exit 99
    fi
fi

rm -f options.go
echo "package wolfSSL" >> options.go
echo ""                >> options.go
echo "// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl" >> options.go
echo "// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm"                >> options.go
sed 's/^/\/\/ /' $OPTIONS_H                                           >> options.go
echo "options.go generated."

# When the supplied path is an installed wolfSSL prefix, repoint cgo
# directives in every cgo-bearing file at $PREFIX. Skipped for source-tree
# layouts (no <src>/lib to point -L at).
if [ ! -z "$PREFIX" ]; then
    sed -i.bak \
        -e "s|-I/usr/include -I/usr/include/wolfssl|-I$PREFIX/include -I$PREFIX/include/wolfssl|" \
        -e "s| -I/usr/local/include -I/usr/local/include/wolfssl||" \
        -e "s|-L/usr/local/lib|-L$PREFIX/lib|" \
        options.go aes.go wolfx509/certgen_wolfcrypt.go wolftls/conn.go \
        && rm options.go.bak aes.go.bak wolfx509/certgen_wolfcrypt.go.bak wolftls/conn.go.bak
    echo "cgo paths pointed at $PREFIX."
fi

exit 0
