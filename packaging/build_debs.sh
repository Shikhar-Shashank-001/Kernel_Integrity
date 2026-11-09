#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# build_debs.sh - build kim-dkms_<v>_all.deb and kim-daemon_<v>_amd64.deb
# into packaging/dist/. No root needed (dpkg-deb --root-owner-group).
#
#   kim-dkms    /usr/src/kim-<v>/ (module source + Kbuild + dkms.conf);
#               postinst runs dkms add/build/install, Depends: dkms
#   kim-daemon  /usr/sbin/kimd (kd_daemon), kim.service, /etc/kim/kimd.conf
#               (conffile, monitor-only), README; enables + starts the service
#
# Both preinst scripts refuse anything but Ubuntu 26.04 on Intel 12th gen+
# (KIM_ALLOW_UNSUPPORTED=1 to override the OS/model check).
#
# Usage (from File_Extractor/files/packaging):  ./build_debs.sh
# Env: VERSION (1.0.0)  MAINT (Maintainer field; default "Shikhar Shashank")
set -euo pipefail
umask 022

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/.." && pwd)
VERSION=${VERSION:-1.0.0}
MAINT=${MAINT:-"Shikhar Shashank"}
BUILD=$HERE/build
DIST=$HERE/dist

subst() { sed -e "s|@VERSION@|$VERSION|g" -e "s|@MAINT@|$MAINT|g" "$1"; }
script() { subst "$1" > "$2"; chmod 0755 "$2"; }
finish() {   # $1 = staged package root
	local root=$1
	find "$root" -type d -exec chmod 0755 {} +
	find "$root" -type f ! -perm -u+x -exec chmod 0644 {} +
	(cd "$root" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' | sort -z |
		xargs -0 -r md5sum) > "$root/DEBIAN/md5sums"
	echo "Installed-Size: $(du -sk --exclude=DEBIAN "$root" | cut -f1)" >> "$root/DEBIAN/control"
	dpkg-deb --root-owner-group -Zxz --build "$root" "$DIST" >/dev/null
}

echo "== building user space"
make -C "$TOP/module2_dispatcher" kd_daemon >/dev/null
rm -rf "$BUILD"
mkdir -p "$BUILD" "$DIST"
rm -f "$DIST"/kim-*_"$VERSION"_*.deb

# ------------------------------------------------------------------ kim-dkms
R=$BUILD/kim-dkms
SRC=$R/usr/src/kim-$VERSION
install -d "$R/DEBIAN" "$SRC" "$R/usr/share/doc/kim-dkms"
install -m 0644 "$TOP/kernel_extractor.c" "$TOP/kim_uapi.h" "$HERE/kim-dkms/Kbuild" "$SRC/"
subst "$HERE/kim-dkms/dkms.conf" > "$SRC/dkms.conf"
subst "$HERE/common/copyright" > "$R/usr/share/doc/kim-dkms/copyright"
script "$HERE/common/preinst" "$R/DEBIAN/preinst"
script "$HERE/kim-dkms/postinst" "$R/DEBIAN/postinst"
script "$HERE/kim-dkms/prerm" "$R/DEBIAN/prerm"
cat > "$R/DEBIAN/control" <<EOF
Package: kim-dkms
Version: $VERSION
Architecture: all
Maintainer: $MAINT
Depends: dkms (>= 3), kmod
Recommends: linux-headers-generic, mokutil
Section: kernel
Priority: optional
Description: kernel integrity monitor - kernel module (DKMS)
 kernel_extractor exports kernel text, the syscall tables and loaded module
 text/rodata to the kim daemon through a read-only shared ring and a read-only,
 never-executable window on kernel text. DKMS rebuilds and signs it for every
 kernel. Ubuntu 26.04 LTS on Intel Core 12th gen (Alder Lake) and newer only.
EOF
finish "$R"

# ------------------------------------------------------------------ kim-daemon
R=$BUILD/kim-daemon
install -d "$R/DEBIAN" "$R/usr/sbin" "$R/usr/lib/systemd/system" "$R/etc/kim" "$R/usr/share/doc/kim-daemon"
install -m 0755 -s "$TOP/module2_dispatcher/kd_daemon" "$R/usr/sbin/kimd"
install -m 0644 "$HERE/kim-daemon/kim.service" "$R/usr/lib/systemd/system/kim.service"
install -m 0644 "$HERE/kim-daemon/kimd.conf" "$R/etc/kim/kimd.conf"
subst "$HERE/kim-daemon/README" > "$R/usr/share/doc/kim-daemon/README"
subst "$HERE/common/copyright" > "$R/usr/share/doc/kim-daemon/copyright"
script "$HERE/common/preinst" "$R/DEBIAN/preinst"
script "$HERE/kim-daemon/postinst" "$R/DEBIAN/postinst"
script "$HERE/kim-daemon/prerm" "$R/DEBIAN/prerm"
script "$HERE/kim-daemon/postrm" "$R/DEBIAN/postrm"
echo /etc/kim/kimd.conf > "$R/DEBIAN/conffiles"
libc=$(dpkg-query -W -f='${Version}' libc6 | cut -d- -f1)
cat > "$R/DEBIAN/control" <<EOF
Package: kim-daemon
Version: $VERSION
Architecture: amd64
Maintainer: $MAINT
Depends: libc6 (>= $libc), kim-dkms (= $VERSION), kmod, systemd
Recommends: auditd
Section: admin
Priority: optional
Description: kernel integrity monitor - verification daemon
 kimd learns a baseline of the running kernel at start-up and then verifies
 every scan (AES-256-GCM-SIV tags computed with VAES on the P-cores, one kernel
 thread pinned to its own core). Legitimate runtime patching is decoded and
 reported as low severity; unexplained code changes, writable kernel text and
 syscall-table changes are critical. Alerts go to the journal, syslog and
 auditd. Monitor-only by default; enforcement (lockdown, modules_disabled) is
 opt-in in /etc/kim/kimd.conf. Ubuntu 26.04 LTS, Intel Core 12th gen and newer.
EOF
finish "$R"

echo "== built"
for d in "$DIST"/kim-*_"$VERSION"_*.deb; do
	printf '%s  (%s)\n' "$(basename "$d")" "$(du -h "$d" | cut -f1)"
done
