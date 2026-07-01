/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

// JNI bindings for com.fixcraft.basefwx.NativeCryptoBackend. Builds the
// `basefwxcrypto` shared library; AES-GCM primitives + Argon2id KDF
// when libargon2 was linked at build time. Everything else stays in
// the Java layer.

#include <jni.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#if defined(BASEFWX_JNI_HAS_ARGON2) && BASEFWX_JNI_HAS_ARGON2
#include <argon2.h>
#endif

#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {

struct GcmCtx {
    EVP_CIPHER_CTX* cipher;
    bool encrypt;
    int tag_len;
};

const EVP_CIPHER* gcm_cipher_for_key(int key_len) {
    switch (key_len) {
        case 16: return EVP_aes_128_gcm();
        case 24: return EVP_aes_192_gcm();
        case 32: return EVP_aes_256_gcm();
        default: return nullptr;
    }
}

constexpr int kTagLen = 16;

const unsigned char* direct_bytes(JNIEnv* env, jobject buf) {
    if (buf == nullptr) return nullptr;
    return static_cast<const unsigned char*>(env->GetDirectBufferAddress(buf));
}

unsigned char* direct_bytes_mut(JNIEnv* env, jobject buf) {
    if (buf == nullptr) return nullptr;
    return static_cast<unsigned char*>(env->GetDirectBufferAddress(buf));
}

}  // namespace

extern "C" {

JNIEXPORT jlong JNICALL
Java_com_fixcraft_basefwx_NativeCryptoBackend_nativeGcmInit(
    JNIEnv* env, jclass /*cls*/,
    jboolean encrypt,
    jobject keyBuf, jint keyLen,
    jobject ivBuf,  jint ivLen,
    jobject aadBuf, jint aadLen) {

    const unsigned char* key = direct_bytes(env, keyBuf);
    const unsigned char* iv  = direct_bytes(env, ivBuf);
    const unsigned char* aad = direct_bytes(env, aadBuf);
    if (!key || !iv) return 0;

    const EVP_CIPHER* cipher = gcm_cipher_for_key(keyLen);
    if (!cipher) return 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_CipherInit_ex(ctx, cipher, nullptr, nullptr, nullptr, encrypt ? 1 : 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (EVP_CipherInit_ex(ctx, nullptr, nullptr, key, iv, encrypt ? 1 : 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (aad && aadLen > 0) {
        int discarded = 0;
        if (EVP_CipherUpdate(ctx, nullptr, &discarded, aad, aadLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
    }

    GcmCtx* gcm = static_cast<GcmCtx*>(std::malloc(sizeof(GcmCtx)));
    if (!gcm) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    gcm->cipher = ctx;
    gcm->encrypt = (encrypt != JNI_FALSE);
    gcm->tag_len = kTagLen;
    return reinterpret_cast<jlong>(gcm);
}

JNIEXPORT jint JNICALL
Java_com_fixcraft_basefwx_NativeCryptoBackend_nativeGcmUpdate(
    JNIEnv* env, jclass /*cls*/,
    jlong ctxHandle,
    jobject inBuf, jint inLen,
    jobject outBuf, jint outCap) {

    GcmCtx* gcm = reinterpret_cast<GcmCtx*>(ctxHandle);
    if (!gcm || !gcm->cipher) return -1;
    const unsigned char* in = direct_bytes(env, inBuf);
    unsigned char* out = direct_bytes_mut(env, outBuf);
    if (!in || !out) return -1;
    if (outCap < inLen) return -1;
    int written = 0;
    if (EVP_CipherUpdate(gcm->cipher, out, &written, in, inLen) != 1) {
        return -1;
    }
    return written;
}

JNIEXPORT jint JNICALL
Java_com_fixcraft_basefwx_NativeCryptoBackend_nativeGcmFinalEncrypt(
    JNIEnv* env, jclass /*cls*/,
    jlong ctxHandle,
    jobject outBuf, jint outCap) {

    GcmCtx* gcm = reinterpret_cast<GcmCtx*>(ctxHandle);
    if (!gcm || !gcm->cipher || !gcm->encrypt) return -1;
    unsigned char* out = direct_bytes_mut(env, outBuf);
    if (!out) return -1;

    int trailing = 0;
    if (EVP_CipherFinal_ex(gcm->cipher, out, &trailing) != 1) {
        return -1;
    }
    if (outCap < trailing + gcm->tag_len) return -1;

    if (EVP_CIPHER_CTX_ctrl(gcm->cipher, EVP_CTRL_GCM_GET_TAG,
                            gcm->tag_len, out + trailing) != 1) {
        return -1;
    }
    return trailing + gcm->tag_len;
}

JNIEXPORT jint JNICALL
Java_com_fixcraft_basefwx_NativeCryptoBackend_nativeGcmFinalDecrypt(
    JNIEnv* env, jclass /*cls*/,
    jlong ctxHandle,
    jobject tagBuf, jint tagLen) {

    GcmCtx* gcm = reinterpret_cast<GcmCtx*>(ctxHandle);
    if (!gcm || !gcm->cipher || gcm->encrypt) return -1;
    if (tagLen != gcm->tag_len) return -1;
    const unsigned char* tag = direct_bytes(env, tagBuf);
    if (!tag) return -1;

    if (EVP_CIPHER_CTX_ctrl(gcm->cipher, EVP_CTRL_GCM_SET_TAG,
                            tagLen, const_cast<unsigned char*>(tag)) != 1) {
        return -1;
    }
    unsigned char dummy[16];
    int trailing = 0;
    if (EVP_CipherFinal_ex(gcm->cipher, dummy, &trailing) != 1) {
        return -1;
    }
    return 0;
}

JNIEXPORT void JNICALL
Java_com_fixcraft_basefwx_NativeCryptoBackend_nativeGcmFree(
    JNIEnv* /*env*/, jclass /*cls*/, jlong ctxHandle) {
    GcmCtx* gcm = reinterpret_cast<GcmCtx*>(ctxHandle);
    if (!gcm) return;
    if (gcm->cipher) EVP_CIPHER_CTX_free(gcm->cipher);
    std::free(gcm);
}

// One-shot AES-GCM encrypt against heap byte[] arrays. Uses
// GetPrimitiveArrayCritical so the JVM hands us the raw heap pointers
// (no DirectByteBuffer roundtrip, no allocation per call). The critical
// section is kept short and contains no JNI calls or blocking ops.
JNIEXPORT jint JNICALL
Java_com_fixcraft_basefwx_NativeCryptoBackend_nativeAesGcmEncryptOneShot(
    JNIEnv* env, jclass /*cls*/,
    jbyteArray keyArr, jint keyLen,
    jbyteArray ivArr,  jint ivLen,
    jbyteArray aadArr, jint aadLen,
    jbyteArray inArr,  jint inOff, jint inLen,
    jbyteArray outArr, jint outOff, jint outCap) {

    if (keyArr == nullptr || ivArr == nullptr || inArr == nullptr || outArr == nullptr) {
        return -1;
    }
    if (outCap < inLen + kTagLen) return -1;

    const EVP_CIPHER* cipher = gcm_cipher_for_key(keyLen);
    if (!cipher) return -1;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    jbyte* key = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(keyArr, nullptr));
    jbyte* iv  = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(ivArr,  nullptr));
    if (!key || !iv) {
        if (key) env->ReleasePrimitiveArrayCritical(keyArr, key, JNI_ABORT);
        if (iv)  env->ReleasePrimitiveArrayCritical(ivArr,  iv,  JNI_ABORT);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int ok = 1;
    ok &= EVP_CipherInit_ex(ctx, cipher, nullptr, nullptr, nullptr, 1);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, nullptr);
    ok &= EVP_CipherInit_ex(ctx, nullptr, nullptr,
                            reinterpret_cast<const unsigned char*>(key),
                            reinterpret_cast<const unsigned char*>(iv), 1);
    env->ReleasePrimitiveArrayCritical(ivArr,  iv,  JNI_ABORT);
    env->ReleasePrimitiveArrayCritical(keyArr, key, JNI_ABORT);
    if (!ok) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (aadArr != nullptr && aadLen > 0) {
        jbyte* aad = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(aadArr, nullptr));
        if (!aad) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        int discarded = 0;
        int aad_ok = EVP_CipherUpdate(ctx, nullptr, &discarded,
                                      reinterpret_cast<const unsigned char*>(aad), aadLen);
        env->ReleasePrimitiveArrayCritical(aadArr, aad, JNI_ABORT);
        if (!aad_ok) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    int total = 0;
    jbyte* in  = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(inArr,  nullptr));
    jbyte* out = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(outArr, nullptr));
    if (!in || !out) {
        if (in)  env->ReleasePrimitiveArrayCritical(inArr,  in,  JNI_ABORT);
        if (out) env->ReleasePrimitiveArrayCritical(outArr, out, JNI_ABORT);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int written = 0;
    int update_ok = 1;
    if (inLen > 0) {
        update_ok = EVP_CipherUpdate(
            ctx,
            reinterpret_cast<unsigned char*>(out) + outOff,
            &written,
            reinterpret_cast<const unsigned char*>(in) + inOff,
            inLen);
        total += written;
    }
    int trailing = 0;
    int final_ok = 1;
    if (update_ok) {
        final_ok = EVP_CipherFinal_ex(
            ctx,
            reinterpret_cast<unsigned char*>(out) + outOff + total,
            &trailing);
        total += trailing;
    }
    int tag_ok = 1;
    if (update_ok && final_ok) {
        tag_ok = EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_GET_TAG, kTagLen,
            reinterpret_cast<unsigned char*>(out) + outOff + total);
        if (tag_ok) total += kTagLen;
    }
    env->ReleasePrimitiveArrayCritical(outArr, out, 0);
    env->ReleasePrimitiveArrayCritical(inArr,  in,  JNI_ABORT);
    EVP_CIPHER_CTX_free(ctx);
    if (!update_ok || !final_ok || !tag_ok) return -1;
    return total;
}

// One-shot AES-GCM decrypt. Ciphertext layout: [ct ... | 16-byte tag].
// Returns plaintext length (ct - tag) on success, -1 on auth failure or error.
JNIEXPORT jint JNICALL
Java_com_fixcraft_basefwx_NativeCryptoBackend_nativeAesGcmDecryptOneShot(
    JNIEnv* env, jclass /*cls*/,
    jbyteArray keyArr, jint keyLen,
    jbyteArray ivArr,  jint ivLen,
    jbyteArray aadArr, jint aadLen,
    jbyteArray inArr,  jint inOff, jint inLen,
    jbyteArray outArr, jint outOff, jint outCap) {

    if (keyArr == nullptr || ivArr == nullptr || inArr == nullptr || outArr == nullptr) {
        return -1;
    }
    if (inLen < kTagLen) return -1;
    int ct_len = inLen - kTagLen;
    if (outCap < ct_len) return -1;

    const EVP_CIPHER* cipher = gcm_cipher_for_key(keyLen);
    if (!cipher) return -1;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    jbyte* key = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(keyArr, nullptr));
    jbyte* iv  = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(ivArr,  nullptr));
    if (!key || !iv) {
        if (key) env->ReleasePrimitiveArrayCritical(keyArr, key, JNI_ABORT);
        if (iv)  env->ReleasePrimitiveArrayCritical(ivArr,  iv,  JNI_ABORT);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int ok = 1;
    ok &= EVP_CipherInit_ex(ctx, cipher, nullptr, nullptr, nullptr, 0);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, nullptr);
    ok &= EVP_CipherInit_ex(ctx, nullptr, nullptr,
                            reinterpret_cast<const unsigned char*>(key),
                            reinterpret_cast<const unsigned char*>(iv), 0);
    env->ReleasePrimitiveArrayCritical(ivArr,  iv,  JNI_ABORT);
    env->ReleasePrimitiveArrayCritical(keyArr, key, JNI_ABORT);
    if (!ok) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (aadArr != nullptr && aadLen > 0) {
        jbyte* aad = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(aadArr, nullptr));
        if (!aad) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        int discarded = 0;
        int aad_ok = EVP_CipherUpdate(ctx, nullptr, &discarded,
                                      reinterpret_cast<const unsigned char*>(aad), aadLen);
        env->ReleasePrimitiveArrayCritical(aadArr, aad, JNI_ABORT);
        if (!aad_ok) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    jbyte* in  = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(inArr,  nullptr));
    jbyte* out = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(outArr, nullptr));
    if (!in || !out) {
        if (in)  env->ReleasePrimitiveArrayCritical(inArr,  in,  JNI_ABORT);
        if (out) env->ReleasePrimitiveArrayCritical(outArr, out, JNI_ABORT);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int written = 0;
    int update_ok = 1;
    if (ct_len > 0) {
        update_ok = EVP_CipherUpdate(
            ctx,
            reinterpret_cast<unsigned char*>(out) + outOff,
            &written,
            reinterpret_cast<const unsigned char*>(in) + inOff,
            ct_len);
    }
    // Set the tag (last 16 bytes of input).
    int tag_set_ok = EVP_CIPHER_CTX_ctrl(
        ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
        reinterpret_cast<unsigned char*>(in) + inOff + ct_len);
    unsigned char dummy[16];
    int trailing = 0;
    int final_ok = 0;
    if (update_ok && tag_set_ok) {
        final_ok = EVP_CipherFinal_ex(ctx, dummy, &trailing);
    }
    env->ReleasePrimitiveArrayCritical(outArr, out, final_ok ? 0 : JNI_ABORT);
    env->ReleasePrimitiveArrayCritical(inArr,  in,  JNI_ABORT);
    EVP_CIPHER_CTX_free(ctx);
    if (!update_ok || !tag_set_ok || !final_ok) return -1;
    return written + trailing;
}

// ============================================================================
// Argon2id KDF (3.7.0): routes Java's Argon2id through the C libargon2
// instead of BouncyCastle's pure-Java Argon2BytesGenerator. The pure-Java
// path is ~5-10× slower than libargon2 for the same parameters, which
// dominated the Java fwxAES bench results (2.7s vs C++'s 0.9s on regular
// fwxAES at the same KDF cost). With this bridge enabled, Java should
// close most of the gap on Argon2-dominated wall-clock paths.
//
// Built only when BASEFWX_JNI_HAS_ARGON2 is defined (i.e. CMake found
// libargon2 at JNI build time). When the macro is off, the export is
// still emitted but returns BASEFWX_JNI_ARGON2_NOT_AVAILABLE so the
// Java caller can fall back cleanly to BouncyCastle.
// ============================================================================

constexpr jint kArgon2OK = 0;
constexpr jint kArgon2NotAvailable = -1000;  // distinct from libargon2's own codes
constexpr jint kArgon2BadInput     = -1001;
constexpr jint kArgon2OutBufferBad = -1002;

JNIEXPORT jboolean JNICALL
Java_com_fixcraft_basefwx_NativeCryptoBackend_nativeArgon2idAvailable(
    JNIEnv* /*env*/, jclass /*cls*/) {
#if defined(BASEFWX_JNI_HAS_ARGON2) && BASEFWX_JNI_HAS_ARGON2
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jint JNICALL
Java_com_fixcraft_basefwx_NativeCryptoBackend_nativeArgon2idHashRaw(
    JNIEnv* env, jclass /*cls*/,
    jbyteArray passwordArr,
    jbyteArray saltArr,
    jint timeCost,
    jint memoryKib,
    jint parallelism,
    jbyteArray outArr) {
#if !defined(BASEFWX_JNI_HAS_ARGON2) || !BASEFWX_JNI_HAS_ARGON2
    (void)env; (void)passwordArr; (void)saltArr;
    (void)timeCost; (void)memoryKib; (void)parallelism; (void)outArr;
    return kArgon2NotAvailable;
#else
    if (!passwordArr || !saltArr || !outArr) return kArgon2BadInput;
    if (timeCost <= 0 || memoryKib <= 0 || parallelism <= 0) return kArgon2BadInput;

    const jsize pw_len   = env->GetArrayLength(passwordArr);
    const jsize salt_len = env->GetArrayLength(saltArr);
    const jsize out_len  = env->GetArrayLength(outArr);
    if (salt_len <= 0 || out_len <= 0) return kArgon2OutBufferBad;

    // Pin all three arrays via GetPrimitiveArrayCritical: libargon2 is a
    // synchronous C call, GC pauses are fine, and we avoid the copy.
    jbyte* pw   = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(passwordArr, nullptr));
    jbyte* salt = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(saltArr,    nullptr));
    jbyte* out  = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(outArr,     nullptr));
    if (!pw || !salt || !out) {
        // Wipe the password bytes in the pinned region BEFORE releasing —
        // an early return after partial pinning otherwise leaks the
        // plaintext password back to the Java heap. We can't run the
        // wipe loop unless pw is non-null, but if any other pin failed
        // we still want to scrub pw's contents.
        if (pw && pw_len > 0) {
            volatile jbyte* p = pw;
            for (jsize i = 0; i < pw_len; ++i) p[i] = 0;
        }
        if (pw)   env->ReleasePrimitiveArrayCritical(passwordArr, pw,   0);  // commit wipe
        if (salt) env->ReleasePrimitiveArrayCritical(saltArr,     salt, JNI_ABORT);
        if (out)  env->ReleasePrimitiveArrayCritical(outArr,      out,  JNI_ABORT);
        return kArgon2BadInput;
    }

    const int rc = argon2id_hash_raw(
        static_cast<uint32_t>(timeCost),
        static_cast<uint32_t>(memoryKib),
        static_cast<uint32_t>(parallelism),
        reinterpret_cast<const void*>(pw),   static_cast<size_t>(pw_len),
        reinterpret_cast<const void*>(salt), static_cast<size_t>(salt_len),
        reinterpret_cast<void*>(out),        static_cast<size_t>(out_len));

    // Wipe the password copy in the critical region before we let go —
    // the JNI critical pin is the only window where we can guarantee the
    // bytes aren't moved by the GC, so this is the cleanest wipe point.
    if (pw_len > 0) {
        volatile jbyte* p = pw;
        for (jsize i = 0; i < pw_len; ++i) p[i] = 0;
    }

    // Commit out on success, abort on failure so the caller's array
    // doesn't get any partial / garbage bytes.
    env->ReleasePrimitiveArrayCritical(outArr,      out,  rc == ARGON2_OK ? 0 : JNI_ABORT);
    env->ReleasePrimitiveArrayCritical(saltArr,     salt, JNI_ABORT);
    env->ReleasePrimitiveArrayCritical(passwordArr, pw,   0);  // commit wipe

    return rc == ARGON2_OK ? kArgon2OK : static_cast<jint>(rc);
#endif
}

}  // extern "C"
