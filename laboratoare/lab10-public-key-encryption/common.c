#include "common.h"

#include <getopt.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/param_build.h>
#include <sys/socket.h>

#define DEFAULT_SERVER_IP   "127.0.0.1"
#define DEFAULT_SERVER_PORT 1337
#define DEFAULT_DH_FILENAME "dhparam.pem"

#define INIT_DEFAULT_SERVER_CONFIGS()                                       \
(server_config_t){                                                          \
    .ip = DEFAULT_SERVER_IP,                                                \
    .port = DEFAULT_SERVER_PORT,                                            \
    .dh_filename = DEFAULT_DH_FILENAME,                                     \
}

static EVP_PKEY *bn_to_evp_pkey(const BIGNUM *dh_pub_key, EVP_PKEY *key_pair) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    BIGNUM* p_bn = NULL;
    BIGNUM* g_bn = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;

    /* Read the parameters p and g. When creating the new EVP_PKEY, we need
     * to keep those parameters alongside the new public key. Otherwise,
     * the exchange fails silently at EVP_PKEY_derive_set_peer().
     */
    if (!EVP_PKEY_get_bn_param(key_pair, OSSL_PKEY_PARAM_FFC_P, &p_bn)
        || !EVP_PKEY_get_bn_param(key_pair, OSSL_PKEY_PARAM_FFC_G, &g_bn)) {
        print_openssl_err("Failed reading params");
        goto cleanup;
    }

    /* Create a new EVP_PKEY_CTX structure for key generation, based on existing
     * DH key pair. 
     */
    if (!(kctx = EVP_PKEY_CTX_new_from_pkey(NULL, key_pair, NULL))) {
        print_openssl_err("Error creating EVP_PKEY_CTX");
        goto cleanup;
    }

    /* Parameters builder. For details, check
     * https://www.openssl.org/docs/man3.1/man3/EVP_PKEY_fromdata.html 
     */
    if (!(param_bld = OSSL_PARAM_BLD_new())
        || !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PUB_KEY, dh_pub_key)
        || !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p_bn)
        || !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g_bn)) {
        print_openssl_err("Error creating OSSL params builder");
        goto cleanup;
    }
    if (!(params = OSSL_PARAM_BLD_to_param(param_bld))) {
        print_openssl_err("Error OSSL_PARAM_BLD_to_param");
        goto cleanup;        
    }
    if (EVP_PKEY_fromdata_init(kctx) <= 0
        || EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY , params) <= 0) {
        print_openssl_err("Eeero creaing EVP context ");
        goto cleanup;
    }

cleanup:
    if (g_bn)
        BN_free(g_bn);
    if (p_bn)
        BN_free(p_bn);
    if (params)
        OSSL_PARAM_free(params);
    if (param_bld)
        OSSL_PARAM_BLD_free(param_bld);
    if (kctx)
        EVP_PKEY_CTX_free(kctx);
    return pkey;
}

static int derive_shared_secret(EVP_PKEY *key_pair, EVP_PKEY *peer_key, 
                                unsigned char **secret, size_t *secret_len) {
    /* Perform the Diffie-Hellman key derivation. The code should closely follow
     * the example from the manual (variable names are a bit different):
     * https://www.openssl.org/docs/man3.2/man3/EVP_PKEY_derive.html
     */
    EVP_PKEY_CTX *ctx;

    /* TODO: Create a new EVP_PKEY_CTX structure for key derivation.
     * Check EVP_PKEY_CTX_new() for arguments:
     * https://www.openssl.org/docs/man3.2/man3/EVP_PKEY_CTX_new.html
     * For engine argument use NULL.
     */
    if (!(ctx = EVP_PKEY_CTX_new(key_pair, NULL))) {
        print_openssl_err("Error creating EVP_PKEY_CTX");
        goto error_ctx;
    }

    /* TODO: Initialize the context for key derivation */
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        print_openssl_err("Error initializing key derivation");
        goto error;
    }

    /* TODO: Set the peer public key */
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        print_openssl_err("Error setting peer public key");
        goto error;
    }

    /* TODO: Get the size of the shared secret in secret_len */
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
        print_openssl_err("Error determining shared secret size");
        goto error;
    }

    /* TODO: Allocate memory for the shared secret */
    if (!(*secret = OPENSSL_malloc(*secret_len))) {
        print_openssl_err("Error allocating memory for shared secret");
        goto error;
    }

    /* TODO: Derive the shared secret */
    if (EVP_PKEY_derive(ctx, *secret, secret_len) <= 0) {
        print_openssl_err("Error deriving shared secret");
        goto error_derive;
    }

    EVP_PKEY_CTX_free(ctx);

    return 0;
error_derive:
    OPENSSL_free(*secret);
error:
    EVP_PKEY_CTX_free(ctx);
error_ctx:
    *secret_len = 0;
    *secret = NULL;
    return -1;
}

server_config_t parse_args(int argc, char* argv[]) {
    server_config_t config = INIT_DEFAULT_SERVER_CONFIGS();
    int opt = 0;

    /* get arg params */
    while ((opt = getopt(argc, argv, "i:p:")) != -1) {
        switch (opt) {
        case 'i':
            config.ip = optarg;
            break;
        case 'p':
            config.port = atoi(optarg);
            break;
        case 'f':
            config.dh_filename = optarg;
            break;
        default:
            fprintf(stderr, "Usage %s [-i IP] [-p PORT] [-f FILENAME]\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    return config;
}

void receive_all(int sockfd, unsigned char *buffer, int length) {
    int bytes_received = 0;
    int rc;

    while (bytes_received < length) {
        rc = recv(sockfd, buffer + bytes_received, length - bytes_received, 0);
        CHECK(rc >= 0, "recv failed");
        bytes_received += rc;
    }
}

void print_buf_hex(const unsigned char *buffer, size_t buflen) {
    int i;

    for(i = 0; i < buflen; i++)
        printf("%02X", buffer[i]);
    printf("\n");
}

int evp_pkey_to_bin(EVP_PKEY *key_pair, unsigned char *buffer) {
    BIGNUM* pkey_bn = NULL;
    int key_size;

    /* Get the public key from EVP_PKEY */
    if (!EVP_PKEY_get_bn_param(key_pair, OSSL_PKEY_PARAM_PUB_KEY, &pkey_bn)) {
        print_openssl_err("EVP_PKEY_get_bn_param 1");
        return -1;
    }

    /* Get key size in bytes */
    key_size = BN_num_bytes(pkey_bn);
    log("The public key has %d bytes\n", key_size);
    CHECK(KEY_LEN == key_size, "DH PUB KEY LEN");

    /* Put key in the buffer */
    BN_bn2bin(pkey_bn, buffer);

    BN_free(pkey_bn);
    return 0;
}

EVP_PKEY *generate_dh_key_pair(const char *filename) {
    BIO *bio;
    OSSL_DECODER_CTX *dctx;
    EVP_PKEY_CTX *kctx;
    EVP_PKEY *dparams = NULL;
    EVP_PKEY *keypair = NULL;

    /* Create a new OSSL_DECODER_CTX structure. For details, check:
     * https://www.openssl.org/docs/man3.1/man3/OSSL_DECODER_CTX_new_for_pkey.html
     * https://www.openssl.org/docs/man3.1/man7/EVP_PKEY-DH.html
     * https://www.openssl.org/docs/man3.1/man3/EVP_PKEY_fromdata.html
     */
    if (!(dctx = OSSL_DECODER_CTX_new_for_pkey(&dparams,
                                               "PEM", "DH PARAMETERS", "DH",
                                               EVP_PKEY_KEY_PARAMETERS,
                                               NULL, NULL))) {
        print_openssl_err("Error creating OSSL_DECODER_CTX");
        goto err_decoder_create;
    }

    /* Open the pem file containing the DH parameters */
    if (!(bio = BIO_new_file(filename, "r"))) {
        print_openssl_err("Error opening file %s", filename);
        goto error_bio_create;
    }

    /* Read the pem file and decode it into an EVP_PKEY object */
    if (OSSL_DECODER_from_bio(dctx, bio) <= 0) {
        print_openssl_err("Error decoding pem file");
        goto err_bio_decode;
    }

    /* Create a new EVP_PKEY_CTX structure for key generation */
    if (!(kctx = EVP_PKEY_CTX_new_from_pkey(NULL, dparams, NULL))) {
        print_openssl_err("Error creating EVP_PKEY_CTX");
        goto err_evp_key_ctx;
    }

    /* Initialize the key generation */
    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        print_openssl_err("Error initializing key generation");
        goto err_keygen;
    }

    /* Generate the key pair */
    if (EVP_PKEY_keygen(kctx, &keypair) <= 0) {
        print_openssl_err("Error generating key pair");
        goto err_keygen;
    }

err_keygen:
    EVP_PKEY_CTX_free(kctx);
err_evp_key_ctx:
err_bio_decode:
    BIO_free(bio);
error_bio_create:
    EVP_PKEY_free(dparams);
    OSSL_DECODER_CTX_free(dctx);
err_decoder_create:
    return keypair;
}

void diffie_hellman_exchange(int connect_fd, EVP_PKEY *key_pair,
                             void* buf_pubkey, size_t buf_pubkey_len) {
    unsigned char buf_peer_pubkey[KEY_LEN];
    unsigned char *secret = NULL;
    size_t secret_len;
    EVP_PKEY *peer_key = NULL;
    BIGNUM* peer_key_bn = NULL;

    /* Send the public key to the client */
    log("Sending public key...\n");
    CHECK(send(connect_fd, buf_pubkey, buf_pubkey_len, 0) >= 0, "send");

    /* Receive the client's public key */
    receive_all(connect_fd, buf_peer_pubkey, KEY_LEN);

    log("Received public key from client...\n");
    log("The received public key is: ");
    print_buf_hex(buf_peer_pubkey, KEY_LEN);

    /* Encapsulate peer's key */
    if (!(peer_key_bn = BN_bin2bn(buf_peer_pubkey, KEY_LEN, NULL))) {
        goto cleanup;
    }
    if (!(peer_key = bn_to_evp_pkey(peer_key_bn, key_pair))) {
        goto cleanup;
    }

    /* Obtain the shared secret key */
    if (derive_shared_secret(key_pair, peer_key, &secret, &secret_len)) {
        goto cleanup;
    }

    /* Print the shared secret to the standard output */
    log("Exchanged secret key has %ld bytes\n", secret_len);
    log("The exchanged secret key is: ");
    print_buf_hex(secret, secret_len);

cleanup:
    if (peer_key_bn)
        BN_free(peer_key_bn);
    if (peer_key)
        EVP_PKEY_free(peer_key);
    if (secret)
        OPENSSL_free(secret);
}
