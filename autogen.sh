#!/bin/sh
autoreconf --force --install
ret=$?
if [ $ret -ne 0 ]; then
	echo "autoreconf: failed with return code: $ret"
	exit $ret
fi
echo "To build run:"
echo "./configure && make"
exit 0
