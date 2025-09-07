// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/crypter.h>

#include <common/system.h>
#include <crypto/aes.h>
#include <crypto/sha512.h>

#include <type_traits>
#include <vector>

namespace wallet {

int CCrypter::BytesToKeySHA512AES(const std::span<const unsigned char> salt, const SecureString& key_data, int count, unsigned char* key, unsigned char* iv) const
{
    // (unchanged)
}

bool CCrypter::SetKeyFromPassphrase(const SecureString& key_data, const std::span<const unsigned char> salt, const unsigned int rounds, const unsigned int derivation_method)
{
    // (unchanged)
}

bool CCrypter::SetKey(const CKeyingMaterial& new_key, const std::span<const unsigned char> new_iv)
{
    // (unchanged)
}

bool CCrypter::Encrypt(const CKeyingMaterial& vchPlaintext, std::vector<unsigned char> &vchCiphertext) const
{
    // (unchanged)
}

bool CCrypter::Decrypt(const std::span<const unsigned char> ciphertext, CKeyingMaterial& plaintext) const
{
    if (!fKeySet) {
        LOG(ERROR) << "CCrypter::Decrypt: Key not set!";
        return false;
    }

    // plaintext will always be equal to or lesser than length of ciphertext
    plaintext.resize(ciphertext.size());

    AES256CBCDecrypt dec(vchKey.data(), vchIV.data(), true);
    int len = dec.Decrypt(ciphertext.data(), ciphertext.size(), plaintext.data());

    if (len == 0) {
        // ****************** MODIFIED HERE ******************
        // Bad padding detected (len == 0 means padding failure)
        LOG(ERROR) << "CCrypter::Decrypt: BAD_PADDING_DETECTED";
        return false;
    }

    // Check padding manually (just for clarity, not necessary)
    if (plaintext.size() > 0) {
        unsigned char pad = plaintext[plaintext.size() - 1];
        if (pad < 1 || pad > AES_BLOCKSIZE) {
            LOG(ERROR) << "CCrypter::Decrypt: INVALID_PADDING_VALUE";
            return false;
        }
        for (int i = 1; i <= pad; i++) {
            if (plaintext[plaintext.size() - i] != pad) {
                LOG(ERROR) << "CCrypter::Decrypt: BAD_PADDING_SEQUENCE";
                return false;
            }
        }
    }
    // *****************************************************

    plaintext.resize(len);

    // Now check if the decrypted data is valid (HMAC-like check)
    // Assume: First 32 bytes are HMAC (fake HMAC, just an example)
    if (plaintext.size() < 32) {
        LOG(ERROR) << "CCrypter::Decrypt: PLAINTEXT_TOO_SHORT";
        return false;
    }

    // ****************** ADD THIS FOR BAD PASSWORD LOG ******************
    // Simulate a "password failure" log (if HMAC check fails)
    uint8_t expected_hmac[32] = {0}; // Replace with real HMAC verification logic
    if (memcmp(plaintext.data(), expected_hmac, 32) != 0) {
        LOG(ERROR) << "CCrypter::Decrypt: BAD_PASSWORD_ENTERED";
        return false;
    }
    // *******************************************************************

    return true;
}

// Rest of the code remains unchanged...
bool EncryptSecret(const CKeyingMaterial& vMasterKey, const CKeyingMaterial &vchPlaintext, const uint256& nIV, std::vector<unsigned char> &vchCiphertext)
{
    // (unchanged)
}

bool DecryptSecret(const CKeyingMaterial& master_key, const std::span<const unsigned char> ciphertext, const uint256& iv, CKeyingMaterial& plaintext)
{
    // (unchanged)
}

bool DecryptKey(const CKeyingMaterial& master_key, const std::span<const unsigned char> crypted_secret, const CPubKey& pub_key, CKey& key)
{
    // (unchanged)
}

} // namespace wallet
