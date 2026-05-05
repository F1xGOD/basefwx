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

}  // extern "C"
