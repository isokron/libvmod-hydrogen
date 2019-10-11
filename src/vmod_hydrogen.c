#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache/cache.h"

#include "vtim.h"
#include "vcc_hydrogen_if.h"

#include "base64.h"
#include "libhydrogen/hydrogen.h"


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
 * Encrypt a string, encode it to base64, put on workspace and return.
 *
 */




VCL_STRING
vmod_encrypt(VRT_CTX, VCL_STRING str, VCL_STRING key)
{
	(void)key;
	if (str == NULL) {
		return(NULL);
	}
	if (key == NULL) {
		VRT_fail(ctx, "key must be set");
	}

	// TODO: encrypt string

	int enclen = pg_b64_enc_len(strlen(str));
	enclen = 200; // FIXME

	char *encoded = WS_Alloc(ctx->ws, enclen+1);
	AN(encoded);
	memset(encoded, '\0', enclen+1);

	int len = pg_b64_encode(str, strlen(str), encoded, enclen);
	assert(len >= 0);
	printf("Encoded text is: \"%s\" (%i bytes in %lu sized buffer)\n", encoded, len, sizeof(encoded));
	fflush(NULL);
	return (encoded);
}

VCL_STRING
vmod_decrypt(VRT_CTX, VCL_STRING b64str, VCL_STRING key)
{
	if (b64str == NULL) {
		return(NULL);
	}
	if (key == NULL) {
		VRT_fail(ctx, "key must be set");
	}

	int declen = pg_b64_dec_len(strlen(b64str));
	declen = 100;

	char *decoded = WS_Alloc(ctx->ws, declen+1);
	AN(decoded);
	memset(decoded, '\0', declen+1);

	int len = pg_b64_decode(b64str, strlen(b64str), decoded, declen);
	assert(len >= 0);
    // extern int pg_b64_decode(const char *src, int len, char *dst, int dstlen);
	printf("Decoded text is: \"%s\" (%d==%lu bytes in %lu byte buffer)", decoded, len, strlen(decoded), sizeof(decoded) );
	return (decoded);
}
