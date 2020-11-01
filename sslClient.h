#ifndef _SSL_CLIENT_
#define _SSL_CLIENT_

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

std::string Read(SSL* ssl, std::string file, std::string project, std::string token);
SSL* connect();

#endif // !_SSL_CLIENT_
