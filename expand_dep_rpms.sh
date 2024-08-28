#!/bin/sh

###############################################################
# DO NOT REMOVE
# This script file is used as part of the build process
# This script extracts RPM dependencies
###############################################################

echo "Expand deps called"
cd ../target/deps
#cp /root/.m2/repository/com/ericsson/nms/litp/ERIClitpcore_CXP9030418/1.2.37-SNAPSHOT/ERIClitpcore_CXP9030418-1.2.37-SNAPSHOT.rpm .
#rm -f ERIClitpcore_CXP9030418-1.1.32.rpm
echo "cd to target deps dir"
for i in *rpm ; do rpm2cpio $i | cpio -idmv ; done

cd ../../ERIC*/
exit

