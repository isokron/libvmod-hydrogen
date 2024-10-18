
DESCRIPTION
===========

This is vmod-hydrogen implementing data encryption in Varnish VCL.

From https://github.com/jedisct1/libhydrogen :

> The Hydrogen library is a small, easy-to-use, hard-to-misuse cryptographic library.

Main purpose of this module is to easily encrypt and decrypt cookies made inside
Varnish and kept on the client side. Bonus points for getting integrity protection
"for free".


USAGE
=====


::

        import std;
        import hydrogen;

        sub vcl_recv {
                if (req.http.cookie !~ "session-id") {
                        set req.http.x-cookie-value = regsub(req.http.Cookie, ".*session-id=([^;]*).*$", "\1");
                        set req.http.x-session-id = hydrogen.decrypt(req.http.x-cookie-value, "very_secret_key", "fallback");

                        # If key is incorrect, or body fails libhydrogen's integrity checks, we get the fallback value.
                        if (req.http.x-session-id == "fallback") {
                                return(synth(401, "Bad Request"));
                        }

                        std.log("session-id is: " + req.http.x-session-id);
                }
        }

        sub vcl_deliver {
                if (req.http.cookie !~ "session-id") {
                        #set resp.http.Set-Cookie = "session-id=" + hydrogen.encrypt("" + std.random(1000, 9999), "very_secret_key") + ";";
                }
        }


FUNCTIONS
=========


::

    STRING encrypt(STRING str, STRING key)

Encrypt the string in `str` using key `key` and return a HEX encoded value of it.


::

    STRING decrypt(STRING str, STRING key, STRING fallback)

Decrypt a HEX encoded encrypted string `str` using `key` and return the plaintext
version of it. If decoding or decryption fails, return `fallback`.


::

    STRING random_string(INT length)

Return a cryptographically safe string of a given length.

Use is for session keys, nonces, and similar where std.random() is unsafe.


AUTHOR
======

Copyright Isokron AS (c) 2019-2024.

Author: Lasse Karstensen <lasse@isokron.no>
