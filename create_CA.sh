#/bin/bash
CANAME=myproxyRootCA
# optional
mkdir $CANAME
cd $CANAME
# generate aes encrypted private key 
#openssl genrsa -aes256 -out $CANAME.key 4096

# generate key w/o passphrase
openssl genrsa -out $CANAME.key 4096

# create certificate, 1826 days = 5 years
openssl req -x509 -new -nodes -key $CANAME.key -sha256 -days 1826 -out $CANAME.crt -subj "/CN=$CANAME/C=NN/ST=SomeState/L=SomeLocation/O=myproxy"


