/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The cryptography WPA2-PSK key management needs (IEEE 802.11 12.7): SHA-1,
 * HMAC-SHA1, PBKDF2 for the passphrase, the 802.11 PRF for the pairwise keys,
 * and AES key wrap for the group key. For WPA3 (SAE, AKM 8): SHA-256,
 * HMAC-SHA256, the 802.11 KDF and AES-CMAC. Plain C with no Linux or kernel types,
 * so the userspace smoke test can use the same code to play the authenticator.
 *
 * Frame encryption itself (CCMP) is done by the hardware; TKIP, which some
 * chips cannot do, is decrypted here for the group frames of a WPA/WPA2 mixed
 * network.
 */
#ifndef _RTW89_CRYPTO_H
#define _RTW89_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTW89_SHA1_LEN 20
#define RTW89_SHA256_LEN 32

void rtw89_sha1(const uint8_t *data, size_t len, uint8_t out[RTW89_SHA1_LEN]);

/* HMAC-SHA1 over the concatenation of @num pieces. */
void rtw89_hmac_sha1_vector(const uint8_t *key, size_t key_len, size_t num,
                            const uint8_t *const pieces[], const size_t lens[],
                            uint8_t out[RTW89_SHA1_LEN]);
void rtw89_hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len,
                     uint8_t out[RTW89_SHA1_LEN]);

/* PBKDF2-HMAC-SHA1 (RFC 2898). WPA2: 4096 iterations, salt = SSID, 32 bytes out. */
void rtw89_pbkdf2_sha1(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len, unsigned int iterations,
                       uint8_t *out, size_t out_len);

/* IEEE 802.11 PRF: HMAC-SHA1(key, label || 0 || data || counter), concatenated. */
void rtw89_sha1_prf(const uint8_t *key, size_t key_len, const char *label,
                    const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);

void rtw89_sha256(const uint8_t *data, size_t len, uint8_t out[RTW89_SHA256_LEN]);
void rtw89_hmac_sha256_vector(const uint8_t *key, size_t key_len, size_t num,
                              const uint8_t *const pieces[], const size_t lens[],
                              uint8_t out[RTW89_SHA256_LEN]);
void rtw89_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len,
                       uint8_t out[RTW89_SHA256_LEN]);
/* IEEE 802.11 KDF-SHA-256 (12.7.1.6.2): HMAC-SHA256(key, i || label || context ||
 * Length), i and Length in bits as 16-bit little-endian, the label without
 * its NUL; @out_len bytes. */
void rtw89_kdf_sha256(const uint8_t *key, size_t key_len, const char *label,
                      const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len);

void rtw89_aes128_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void rtw89_aes128_decrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/* AES key wrap (RFC 3394) with a 128-bit KEK. @plain_len is a multiple of 8,
 * at least 16; the wrapped form is 8 bytes longer. unwrap returns false if the
 * integrity check fails. */
void rtw89_aes_wrap(const uint8_t kek[16], const uint8_t *plain, size_t plain_len,
                    uint8_t *wrapped);
bool rtw89_aes_unwrap(const uint8_t kek[16], const uint8_t *wrapped, size_t wrapped_len,
                      uint8_t *plain);

/* AES-CMAC (RFC 4493) over the concatenation of @num pieces. */
void rtw89_aes_cmac_vector(const uint8_t key[16], size_t num, const uint8_t *const pieces[],
                           const size_t lens[], uint8_t mac[16]);
void rtw89_aes_cmac(const uint8_t key[16], const uint8_t *data, size_t len, uint8_t mac[16]);

/*
 * CCMP (IEEE 802.11 12.5.3) in software, for the management frames protected
 * under 802.11w that most of these chips leave to the host: AES-CCM with an
 * 8-byte MIC. @hdr is the 802.11 header (its frame control with the
 * Protected bit as sent); @payload is encrypted or decrypted in place.
 * decrypt returns false if the MIC does not match (and @payload is then
 * garbage).
 */
#define RTW89_CCMP_MIC_LEN 8
void rtw89_ccmp_encrypt(const uint8_t tk[16], const uint8_t *hdr, size_t hdr_len, uint64_t pn,
                        uint8_t *payload, size_t len, uint8_t mic[RTW89_CCMP_MIC_LEN]);
bool rtw89_ccmp_decrypt(const uint8_t tk[16], const uint8_t *hdr, size_t hdr_len, uint64_t pn,
                        uint8_t *payload, size_t len, const uint8_t mic[RTW89_CCMP_MIC_LEN]);

/* Compare without leaking where the difference is. */
bool rtw89_crypto_equal(const uint8_t *a, const uint8_t *b, size_t len);

/*
 * TKIP (IEEE 802.11 12.5.2) in software, for the group key of a WPA/WPA2
 * mixed network, which rtw89 does not put in the chip where its
 * hw_tkip_crypto is false (the RTL8852B among others): mac80211 then decrypts
 * the AP's group frames itself, and so does rtw89_data.c. The pairwise
 * cipher of such a network stays CCMP, in the hardware.
 *
 * @body: an MPDU's bytes after its 802.11 header: the 8-byte IV and Extended
 * IV, the MSDU with its Michael MIC, and the 4-byte ICV. decrypt works in
 * place and leaves the IV as it is; it returns false if @body is too short,
 * has no Extended IV, or its ICV does not match (as
 * ieee80211_tkip_decrypt_data()). The replay check, on rtw89_tkip_tsc(), and
 * the Michael check are the caller's. encrypt is for the userspace smoke
 * test's access point: it writes the IV and the ICV around the plaintext.
 */
#define RTW89_TKIP_IV_LEN 8
#define RTW89_TKIP_ICV_LEN 4
#define RTW89_MICHAEL_LEN 8
uint64_t rtw89_tkip_tsc(const uint8_t iv[RTW89_TKIP_IV_LEN]);
bool rtw89_tkip_decrypt(const uint8_t tk[16], const uint8_t ta[6], uint8_t *body, size_t len);
void rtw89_tkip_encrypt(const uint8_t tk[16], const uint8_t ta[6], uint64_t tsc, uint8_t keyid,
                        uint8_t *body, size_t len);
/* The key mixing on its own, for the test vectors: phase 1 of the TSC's high
 * 32 bits, phase 2 of its low 16 bits to the per-frame RC4 key. */
void rtw89_tkip_phase1(const uint8_t tk[16], const uint8_t ta[6], uint32_t iv32, uint16_t p1k[5]);
void rtw89_tkip_phase2(const uint8_t tk[16], const uint16_t p1k[5], uint16_t iv16,
                       uint8_t rc4key[16]);
void rtw89_rc4(const uint8_t *key, size_t key_len, uint8_t *data, size_t len);
/* The IEEE 802.3 CRC-32, WEP's and TKIP's ICV. */
uint32_t rtw89_crc32(const uint8_t *data, size_t len);

/*
 * Michael (12.5.2.3), TKIP's message integrity code: over an MSDU from @sa to
 * @da at @priority (the TID of a QoS frame, else 0), the 8-byte key being the
 * one its sender signs with. _raw is the bare function over @msg, for the
 * standard's test vectors.
 */
void rtw89_michael(const uint8_t key[8], const uint8_t da[6], const uint8_t sa[6],
                   uint8_t priority, const uint8_t *data, size_t len,
                   uint8_t mic[RTW89_MICHAEL_LEN]);
void rtw89_michael_raw(const uint8_t key[8], const uint8_t *msg, size_t len,
                       uint8_t mic[RTW89_MICHAEL_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* _RTW89_CRYPTO_H */
