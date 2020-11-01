#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include "base64.h"
#include <string>
#include <sys/types.h>
#include <winsock.h>
#include <iostream>
#include <openssl/crypto.h>
#include <windows.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

std::string Read(SSL* ssl, std::string file, std::string project, std::string token)
{
    int err = 0;
    std::string request = "POST /2/files/download HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\nHost: content.dropboxapi.com\r\nAuthorization: Bearer " + token + "\r\nDropbox-API-Arg: {\"path\": \"/" + project + "/" + file + "\"}\r\nContent-Type: text/plain\r\n\r\n";
    err = SSL_write(ssl, request.c_str(), strlen(request.c_str())); CHK_SSL(err);

    char* output = new char[1500000]; char length[31] = ""; char buff[4096] = {};
    int contentLength = 0; int i = 0; int counter = 0;
    memset(output, NULL, sizeof(output));
    do
    {
        err = SSL_read(ssl, buff, sizeof(buff) - 1); CHK_SSL(err);
        if (output[0] == 0)
        {
            std::string test(buff);
            size_t first = test.find("Content-Length: ") + 16;
            size_t last = test.find("\r\nCache-Control");
            std::string lgth = test.substr(first, last - first);

            std::string::size_type sz;
            contentLength = std::stoi(lgth, &sz);
            //printf("[*] CONTENT LENGTH: %d\n", contentLength);
        }
        for (i = 0; i < err; i++)
        {
            output[counter + i] = buff[i];
            //printf("%c", output[counter + i]);
        }
        counter = counter + err;
    } while (err > 0 && counter < contentLength);

    std::string otp(output);
    std::string lptm = otp.substr(otp.find("\r\n\r\n") + 4, contentLength);
    
    return lptm;
}

SSL* connect()
{
    int sd = 0;
    SSL_CTX* ctx;
    int err = 0;
    struct sockaddr_in sa; SSL* ssl;
    char buff[2048] = {};
    SSL_METHOD* meth;
    WORD wVersionRequested;
    WSADATA wsaData;
    SSLeay_add_ssl_algorithms();
    meth = (SSL_METHOD*)TLSv1_2_client_method();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(meth); CHK_NULL(ctx);

    CHK_SSL(err);

    wVersionRequested = MAKEWORD(1, 1);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        printf("///Error in WSAStartup //%d\n", err);
        exit(1);

    }

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("162.125.5.14");
    sa.sin_port = htons(443);

    err = connect(sd, (struct sockaddr*) & sa,
        sizeof(sa)); CHK_ERR(err, "connection");

    ssl = SSL_new(ctx); CHK_NULL(ssl);
    SSL_set_fd(ssl, sd);
    err = SSL_connect(ssl); CHK_SSL(err);

    //printf("[*] SSL connection using %s\n", SSL_get_cipher(ssl));
    
    return ssl;
}