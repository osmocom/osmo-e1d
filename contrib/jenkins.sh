#!/bin/sh
# jenkins build helper script for osmo-e1d.  This is how we build on jenkins.osmocom.org
#

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi


set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

osmo-clean-workspace.sh

mkdir "$deps" || true

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"
export PATH="$inst/bin:$PATH"

osmo-build-dep.sh libosmocore "" --disable-doxygen

# Additional configure options and depends
CONFIG=""
if [ "$WITH_MANUALS" = "1" ]; then
	 CONFIG="--enable-manuals"
fi

set +x
echo
echo
echo
echo " =============================== osmo-e1d ==============================="
echo
set -x

cd "$base"
autoreconf --install --force
./configure --enable-sanitize --enable-werror $CONFIG
$MAKE $PARALLEL_MAKE
$MAKE check || cat-testlogs.sh
# Do distcheck with --disable options as workaround, because it doesn't build
# the usermanual pdf / doxygen html files for some reason and then fails at
# "make install" because it doesn't exist. Spent a lot of time on debugging it,
# not worth fixing now.
DISTCHECK_CONFIGURE_FLAGS="$CONFIG --disable-manuals --disable-doxygen" \
	$MAKE distcheck || cat-testlogs.sh

if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
	make -C "$base/doc/manuals" publish
fi

$MAKE maintainer-clean
osmo-clean-workspace.sh
