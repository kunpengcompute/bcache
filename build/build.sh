#! /bin/sh

BCACHE_PATH=../drivers/md/bcache/
KERNEL_HEAD_PATH=/lib/modules/$(uname -r)/build/
OUTPUT_PATH=../output

if [ x$1 == x"clean" ]; then
	cd ${BCACHE_PATH};\
	make -C ${KERNEL_HEAD_PATH} M=$(pwd) clean;\
	cd -
	rm -rf ${OUTPUT_PATH}
	exit 0
fi

rm -rf ${OUTPUT_PATH}
mkdir -p ${OUTPUT_PATH}

cd ${BCACHE_PATH};\
make -C ${KERNEL_HEAD_PATH} M=$(pwd) clean;\
make -C ${KERNEL_HEAD_PATH} M=$(pwd) -j;\
cd -;

cp ${BCACHE_PATH}/bcache.ko ${OUTPUT_PATH}
