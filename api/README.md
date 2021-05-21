# Cyences-API
Cyences API built by CrossRealms International.


### Prerequisites
- Platform
  - Linux, Windows not supported by uvloop
- Python3.7 should be installed.
  - Python3 alternative install on Ubuntu
  - Reference - https://linuxize.com/post/how-to-install-python-3-7-on-ubuntu-18-04/
- Python3.7 dev tools
  - `sudo apt install libpq-dev python3-dev`



### Install python dependency
```
make install
```


### How to run main file directly
* For dev environment.
```
make dev-run
```


## How to run the API server on HTTPS

- You will need cert-private key and certificate.pem file to configure the application on HTTPS. Make sure that private key is not encrypted with the password, gunicorn doesn't support it.

### To generate the self-signed certificate and private-key
Run below command in your terminal and enter necessary details, this will generate 2 files named key.pem and cert.pem in the current directory.
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Copy the key.pem and cert.pem files to the api code directory. If you have CA signed certs than rename the files to key.pem and cert.pem and put them with the api code.

Run below command to start the API server on https,

```
make prod-https
```

This will start the server on https.

### If you have CA-cert file,
Copy the ca cert file to the api directory and rename it to the ca-cert.pem. Make sure to have key.pem and cert.pem as well.

Run below command to start the API server,

```
make prod-https-ca
```


### How to find background process and kill it?
```
ps -aux | grep "gunicorn main:app"
```
* In the second column you should be able to see the PID of the process.
```
kill -9 <pid>
```
* The above command will kill the process.

