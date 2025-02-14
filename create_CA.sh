#/bin/bash
CANAME=myproxyRootCA
# optional
if [ ! -d $CANAME ];then 
  mkdir $CANAME
fi
cd $CANAME
# generate key w/o passphrase
#openssl genrsa -out $CANAME.key 4096
openssl ecparam -name secp256r1 -genkey -noout -out  $CANAME.key

# create certificate, 1826 days = 5 years
openssl req -x509 -new -nodes -key $CANAME.key -sha256 -days 1826 -out $CANAME.crt -subj "/CN=$CANAME/C=NN/ST=SomeState/L=SomeLocation/O=myproxy" -addext "subjectAltName=DNS:*"


