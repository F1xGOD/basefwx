/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

// JNI bindings for com.fixcraft.basefwx.NativeCryptoBackend. Builds the
// `basefwxcrypto` shared library; only AEAD primitives live here, everything
// else is in the Java layer.

#include <jni.h>

#include <openssl/evp.h>
#include <openssl/err.h>

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

}  // extern "C"
