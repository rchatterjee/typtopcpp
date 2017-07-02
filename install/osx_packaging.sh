#!/usr/bin/env bash
set -e
set -x

if [ $# -lt 2 ]; then
    echo "Num args: $#"
    echo "USAGE: $0 <package.tar.gz> <script_dir>"
    exit
fi

package_file=$1
SCRIPT_DIR=$2
package_name=${package_file/.tar.gz}
echo $# ${package_file} ${SCRIPT_DIR}
tar -zvxf ${package_file}

pkgbuild --root ${package_name} --scripts ${SCRIPT_DIR} \
         --identifier com.typtop.cornell.edu \
         --sign "Developer ID Installer" \
         ${package_name}-tmp.pkg

productbuild --distribution ./distribution.plist \
             --resources . \
             --sign "Developer ID Installer" \
             --package-path ${package_name}-tmp.pkg ${package_name}.pkg

rm -rf ${package_file} ${package_name}-tmp.pkg ${package_name}
