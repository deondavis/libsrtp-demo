# Compilation cmds

**sender**

 `gcc  -I/usr/local/include/srtp2 -I/home/deon/srtp_demo/libsrtp-2.4.2/crypto/include -I/home/deon/srtp_demo/libsrtp-2.4.2/include -L/usr/local/lib simple_srtp_server.c rtp.c util.c -o sender -lsrtp2` 

**receiver**

`gcc  -I/usr/local/include/srtp2 -I/home/deon/srtp_demo/libsrtp-2.4.2/crypto/include -I/home/deon/srtp_demo/libsrtp-2.4.2/include -L/usr/local/lib simple_srtp_client.c rtp.c util.c -o receiver -lsrtp2`
