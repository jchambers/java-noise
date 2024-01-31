package com.eatthepath.noise;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

@NotThreadSafe
class AesGcmCipher extends AbstractNoiseCipher {

  private final ByteBuffer nonceBuffer = ByteBuffer.allocate(12);

  public AesGcmCipher() {
    super(getCipher());
  }

  private static Cipher getCipher() {
    try {
      return Cipher.getInstance("AES/GCM/NoPadding");
    } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new AssertionError("All Java implementations must support AES/GCM/NoPadding");
    }
  }

  @Override
  protected AlgorithmParameterSpec getAlgorithmParameters(final long nonce) {
    nonceBuffer.putLong(4, nonce);
    return new IvParameterSpec(nonceBuffer.array());
  }
}
