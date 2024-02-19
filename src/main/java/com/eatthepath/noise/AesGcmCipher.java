package com.eatthepath.noise;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

@ThreadSafe
class AesGcmCipher extends AbstractNoiseCipher {

  @Override
  protected Cipher getCipher() {
    try {
      return Cipher.getInstance("AES/GCM/NoPadding");
    } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new AssertionError("All Java implementations must support AES/GCM/NoPadding");
    }
  }

  @Override
  protected AlgorithmParameterSpec getAlgorithmParameters(final long nonce) {
    return new GCMParameterSpec(128, ByteBuffer.allocate(12).putLong(4, nonce).array());
  }

  @Override
  public String getName() {
    return "AESGCM";
  }

  @Override
  public Key buildKey(final byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, "AES");
  }
}
