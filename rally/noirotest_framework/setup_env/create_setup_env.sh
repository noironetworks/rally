#!/bin/bash

source /home/noiro/overcloudrc

echo "Uploading images required for testing..."
openstack image create --container-format bare --disk-format raw --file openwrt_image.img --public OpenWRTImg1

echo "Creating flavors required for testing..."
openstack flavor create --ram 512 --disk 1 --vcpus 1 --public --id tiny1 tiny1
openstack flavor create --ram 1024 --disk 5 --vcpus 1 --public --id small1 small1

echo "Generating json file from testconfig.yaml ..."
python gen_args_file.py /home/noiro/noirotest/testcases/testconfig.yaml

r1=$(openstack image list | grep 'OpenWRTImg1' | cut -d '|' -f2)
r2=$(openstack flavor list | grep 'tiny1' | cut -d '|' -f2)

sed -i -e "s/img/$r1/g" args.json
sed -i -e "s/flv/$r2/g" args.json

echo "Please copy the generated args.json file into the testing directory"
