#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <time.h>

#pragma warning(disable:4996)
#define PSK_KEY "Key"
#define PSK_IDENTITY "Ide"
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"ws2_32.lib")

struct ssl_st {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;
    /* SSLv3 */
    const SSL_METHOD* method;
};

const struct ssl_method_st
{
    int version;
    unsigned int flags;
    unsigned int mask;
    int(__fastcall* ssl_new)(ssl_st*);
    int(__fastcall* ssl_clear)(ssl_st*);
    void(__fastcall* ssl_free)(ssl_st*);
    int(__fastcall* ssl_accept)(ssl_st*);
    int(__fastcall* ssl_connect)(ssl_st*);
    int(__fastcall* ssl_read)(ssl_st*, void*, unsigned __int64, unsigned __int64*);
    int(__fastcall* ssl_peek)(ssl_st*, void*, unsigned __int64, unsigned __int64*);
    int(__fastcall* ssl_write)(ssl_st*, const void*, unsigned __int64, unsigned __int64*);
    int(__fastcall* ssl_shutdown)(ssl_st*);
    int(__fastcall* ssl_renegotiate)(ssl_st*);
    int(__fastcall* ssl_renegotiate_check)(ssl_st*, int);
    int(__fastcall* ssl_read_bytes)(ssl_st*, int, int*, unsigned __int8*, unsigned __int64, int, unsigned __int64*);
    int(__fastcall* ssl_write_bytes)(ssl_st*, int, const void*, unsigned __int64, unsigned __int64*);
    int(__fastcall* ssl_dispatch_alert)(ssl_st*);
};


int generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
    /* Generate a cookie */
    int i;

    /* Seed the random number generator */
    srand(time(NULL));

    /* Generate a random cookie */
    for (i = 0; i < 16; i++)
        cookie[i] = rand() % 256;

    /* Print the cookie */
    printf("Cookie: ");
    for (i = 0; i < 16; i++)
        printf("%02X", cookie[i]);
    printf("\n");
    *cookie_len = 16;
    return 1;
}

int verify_cookie(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len)
{
    /* Verify the cookie */
    /* ... */

    return 1;
}

static unsigned int psk_server_cb(SSL* ssl, const char* identity,
    unsigned char* psk, unsigned int max_psk_len)
{
    if (strcmp(identity, PSK_IDENTITY) != 0)
    {
        printf("Unknown PSK identity\n");
        return 0;
    }

    if (strlen(PSK_KEY) > max_psk_len)
    {
        printf("PSK key is too long\n");
        return 0;
    }

    memcpy(psk, PSK_KEY, strlen(PSK_KEY)+1);
    return strlen(PSK_KEY);
}

void print_memory(const void* mem, size_t len) {
    const unsigned char* p = (const unsigned char*)mem;
    for (size_t i = 0; i < len; i += 16) {
        printf("%08zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", p[i + j]);
            }
            else {
                printf("   ");
            }
        }
        printf(" ");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%c", isprint(p[i + j]) ? p[i + j] : '.');
            }
        }
        printf("\n");
    }
}

//void message_cb(int write_p, int version,
//    int content_type, const void* buf,
//    size_t len, SSL* ssl, void* arg) {
//    printf("-------------dump memory------------------\n");
//    print_memory(buf, len);
//    printf("-------------dump done====================\n");
//}

int g_need_change = 0;
long send_callback(BIO* bio, int cmd, const char* argp, int argi,
    long argl, long ret) {
    if (cmd == BIO_CB_WRITE) {
        if (g_need_change) {
            char* data = (char*)argp;
            *data = 21;// NX_SECURE_TLS_ALERT
        }
    }
    return ret;
}


int main(int argc, char** argv)
{
    SSL_CTX* ctx;
    SSL* ssl;
    BIO* bio;
    int ret;

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    int iResult;
    WSADATA wsaData;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

    /* Create a new DTLS context */
    ctx = SSL_CTX_new(DTLSv1_2_server_method());
    if (ctx == NULL)
    {
        printf("Error creating DTLS context\n");
        return -1;
    }

    /* Set the PSK callback */
    SSL_CTX_set_psk_server_callback(ctx, psk_server_cb);

    //SSL_CTX_set_msg_callback(ctx, message_cb);

    /* Set the cipher list to include only PSK-AES128-CCM8 */
    if (SSL_CTX_set_cipher_list(ctx, "PSK-AES128-CCM8") != 1)
    {
        printf("Error setting cipher list\n");
        return -1;
    }

    /* Create a new socket */
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        printf("Error creating socket\n");
        return -1;
    }

    /* Bind the socket to the specified port */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5784);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        printf("Error binding socket, %d\n", GetLastError());
        WSACleanup();
        return -1;
    }

    /* Create a new DTLS connection */
    bio = BIO_new_dgram(sock, BIO_NOCLOSE);
    if (bio == NULL)
    {
        printf("Error creating DTLS connection\n");
        WSACleanup();
        return -1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("Error creating DTLS connection\n");
        WSACleanup();
        return -1;
    }

    SSL_set_bio(ssl, bio, bio);

    /* Set the DTLS cookie generation and verification callbacks */
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    //BIO_set_callback(bio, send_callback);


    /* Wait for a DTLS client to connect */
    struct sockaddr_storage client_addr = { 0 };
    printf("Waiting for DTLS client to connect...\n");
    do {
        ret = DTLSv1_listen(ssl, (BIO_ADDR *) & client_addr);
        if (ret == -1) {
            printf("Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
    } while (ret <= 0);

    /* Perform the DTLS handshake */
    printf("Performing DTLS handshake...\n");
    if (SSL_accept(ssl) <= 0)
    {
        printf("Error performing DTLS handshake\n");
        WSACleanup();
        return -1;
    }

    printf("DTLS handshake complete\n");

    /* Communicate with the DTLS client */
    /* ... */
    SSL_write(ssl, data, data_length);
    //ssl->method->ssl_write_bytes(ssl, SSL3_RT_ALERT, data, data_length, &written);

    /* Clean up */
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
