ovmffw := env("OVMFFW", "/usr/share/OVMF/OVMF_CODE.fd")
pwd := env("PWD")

[group('Listing')]
default:
  just --list

[group('setup')]
setup-grub:
    mkdir -p ./modules/grub/install
    cd ./modules/grub && ./bootstrap && ./configure --with-platform=efi

[group('setup')]
build-grub:
    cd ./modules/grub && make -j`nproc` && make install DESTDIR=`pwd`/install

[group('setup')]
install-grub:
    mkdir -p ./artifacts/hda/efi/boot/
    ./modules/grub/install/usr/local/bin/grub-mkimage \
        -c ./configs/early-grub.cfg \
        -d ./modules/grub/install/usr/local/lib/grub/x86_64-efi \
        -o ./artifacts/hda/efi/boot/bootx64.efi \
        -O x86_64-efi \
        -p "" \
        `cat configs/grub_mod.lst | xargs echo`

[group('run')]
run:
    qemu-system-x86_64 \
        -cpu qemu64 \
        -smbios type=0,uefi=on \
        -bios {{ovmffw}} \
        -hda fat:rw:`pwd`/artifacts/hda \
        -enable-kvm \
        -device e1000,netdev=net0,mac=4c:45:42:45:02:02 \
        -netdev user,id=net0,net=192.168.76.0/24,dhcpstart=192.168.76.9,dns=192.168.76.1 \
        -gdb tcp::1234 \
        -m 4096M \
        -nographic \
        -no-reboot \
        -d int

[group('run')]
debug offset:
    cd ./modules/grub/grub-core/ && \
        gdb -ex 'set pagination off' \
        -ex "source ./gdb_grub" \
        -ex "dynamic_load_symbols {{offset}}" \
        -ex "source {{pwd}}/scripts/grub-gdb.gdbs"
