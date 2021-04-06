#!/bin/bash -e

sudo docker build -t uos-shim-review .

id=$(sudo docker create deepin-shim-review)
sudo docker cp $id:/build/shimx64.efi .
sudo docker rm -v $id

sha256sum -c shimx64.efi.sha256sum

echo "To remove the container image used for this build: sudo docker image rm deepin-shim-review"

