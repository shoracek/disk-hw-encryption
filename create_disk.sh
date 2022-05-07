set -xe

umount ./mounted_image || true

dd if=/dev/zero of=./image bs=1M count=128
mkfs.ext4 ./image
mount -o loop ./image ./mounted_image -o inlinecrypt
tune2fs -O encrypt "/dev/loop0"

mkdir mounted_image/{enc,nonenc}
