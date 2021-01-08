#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache/cache.h"
#include "vtim.h"
#include "foreign/hydrogen.h"

#include "vcc_hydrogen_if.h"

#define HYDROGEN_CONTEXT "vmod-hydrogen"

#if VRT_MAJOR_VERSION == 7
#define WS_RES(c) WS_Reserve(c, 0)
#else
#define WS_RES(c) WS_ReserveAll(c)
#endif


int v_matchproto_(vmod_event_f)
vmod_event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
    (void)ctx;
    (void)priv;

    switch (e) {
    case VCL_EVENT_LOAD:
        if (hydro_init() != 0) {
            VRT_fail(ctx, "libhydrogen unable to hydro_init()");
        }
        break;
    case VCL_EVENT_WARM:
    case VCL_EVENT_COLD:
    case VCL_EVENT_DISCARD:
        break;
    }
    return (0);
}


/*
 * Encrypt a string, copy the encoded version to the workspace, and return that
 * back to VCL.
 */
VCL_STRING
vmod_encrypt(VRT_CTX, VCL_STRING str, VCL_STRING key)
{
    char *encoded = NULL;

    if (str == NULL) {
        VRT_fail(ctx, "encrypt(): str can not be empty");
        return (NULL);
    }

    if (key == NULL) {
        VRT_fail(ctx, "encrypt(): key must be set");
        return (NULL);
    }

    int cipherlen = hydro_secretbox_HEADERBYTES + strlen(str);

    uint8_t * ciphertext = alloca(cipherlen);
    AN(ciphertext);

    if (hydro_secretbox_encrypt(ciphertext, str, strlen(str), 0, HYDROGEN_CONTEXT, (const uint8_t *)key) != 0) {
        VRT_fail(ctx, "encryption failed");
        return (NULL);
    }

    int enclen = cipherlen * 2 + 1;   // Per the documentation.

    unsigned maxlen = WS_RES(ctx->ws);
    if (maxlen < enclen) {
        WS_Release(ctx->ws, 0);
        VRT_fail(ctx, "allocation failed");
        return(NULL);
    }

    memset(ctx->ws->f, '\0', enclen+1);
    encoded = hydro_bin2hex(ctx->ws->f, enclen, ciphertext, cipherlen);
    if (encoded == NULL) {
        WS_Release(ctx->ws, 0);
        VRT_fail(ctx, "hex encoding failed");
        return(NULL);
    }

    WS_Release(ctx->ws, enclen);
    return (encoded);
}


VCL_STRING
vmod_decrypt(VRT_CTX, VCL_STRING encoded_ciphertext, VCL_STRING key, VCL_STRING fallback)
{
    void * plaintext = NULL;
    int cipherlen;

    if (encoded_ciphertext == NULL) {
        VRT_fail(ctx, "decrypt(): ciphertext can not be empty");
        return (NULL);
    }
    if (key == NULL) {
        VRT_fail(ctx, "decrypt(): key must be set");
        return (NULL);
    }

    /* Decode the HEX encoded ciphertext to binary on the stack. */
    uint8_t * ciphertext = alloca(strlen(encoded_ciphertext));
    AN(ciphertext);

    cipherlen = hydro_hex2bin(ciphertext, strlen(encoded_ciphertext),
                                  encoded_ciphertext, strlen(encoded_ciphertext),
                                  NULL, NULL);

    if (cipherlen < 0) {
        VSLb(ctx->vsl, SLT_VCL_Log, "decrypt(): hex decoding failed");
        goto err;
    }

    /* Get some buffer space to place the decrypted string into */
    unsigned maxlen = WS_RES(ctx->ws);
    if (maxlen <= 0) {
        WS_Release(ctx->ws, 0);
        VRT_fail(ctx, "allocation failed");
        return (NULL);
    }

    unsigned ws_needed = cipherlen - hydro_secretbox_HEADERBYTES + 1;
    if (maxlen < ws_needed) {
        WS_Release(ctx->ws, 0);
        VRT_fail(ctx, "decrypt(): workspace would overflow");
        return (NULL);
    }

    plaintext = ctx->ws->f;
    memset(plaintext, '\0', ws_needed);

    if (hydro_secretbox_decrypt(plaintext, ciphertext, cipherlen, 0, HYDROGEN_CONTEXT, (const uint8_t *)key) != 0) {
        VSLb(ctx->vsl, SLT_VCL_Log, "decrypt(): decryption failed");
        goto err;
    }

    assert(strlen(plaintext) == cipherlen - hydro_secretbox_HEADERBYTES);
    WS_Release(ctx->ws, cipherlen - hydro_secretbox_HEADERBYTES);
    return (plaintext);

err:
    strcpy(plaintext, fallback);
    WS_Release(ctx->ws, strlen(plaintext));
    return (plaintext);
}
