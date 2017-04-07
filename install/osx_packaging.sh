#!/usr/bin/env bash

if [ $# -lt 33 ]; then
echo "USAGE: $0 <root_dir> <script_dir>"
fi
package_file=$1
SCRIPT_DIR=$2
package_name=${package_file/.tar.gz}
echo $# ${package_file} ${SCRIPT_DIR}
tar -zvxf ${package_file}
pkgbuild --root ${package_name} --scripts ${SCRIPT_DIR} --identifier com.typtop.cornell.edu ${package_name}.pkg
