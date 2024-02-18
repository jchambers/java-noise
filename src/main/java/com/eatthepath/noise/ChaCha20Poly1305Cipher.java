package com.eatthepath.noise;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

@NotThreadSafe
class ChaCha20Poly1305Cipher extends AbstractNoiseCipher {

  private final ByteBuffer nonceBuffer = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN);

  public ChaCha20Poly1305Cipher() throws NoSuchAlgorithmException {
    super(getCipher());
  }

  private static Cipher getCipher() throws NoSuchAlgorithmException {
    // This is mostly just a dance to accommodate the pre-Java-22 "super must be the first statement in a constructor"
    // requirement
    try {
      return Cipher.getInstance("ChaCha20-Poly1305");
    } catch (final NoSuchPaddingException e) {
      // This should never happen since we're not specifying a padding
      throw new AssertionError("Padding not supported, but no padding specified", e);
    }
  }

  @Override
  protected AlgorithmParameterSpec getAlgorithmParameters(final long nonce) {
    nonceBuffer.putLong(4, nonce);
    return new IvParameterSpec(nonceBuffer.array());
  }

  @Override
  public String getName() {
    return "ChaChaPoly";
  }
}
