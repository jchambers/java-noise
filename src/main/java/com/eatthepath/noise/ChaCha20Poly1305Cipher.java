package com.eatthepath.noise;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

@ThreadSafe
class ChaCha20Poly1305Cipher extends AbstractNoiseCipher {

  private static final String ALGORITHM = "ChaCha20-Poly1305";

  public ChaCha20Poly1305Cipher() throws NoSuchAlgorithmException {
    // Make sure that we can instantiate a cipher and fail fast if not
    try {
      Cipher.getInstance(ALGORITHM);
    } catch (final NoSuchPaddingException e) {
      // This should never happen since we're not specifying a padding
      throw new AssertionError("Padding not supported, but no padding specified", e);
    }
  }

  @Override
  protected Cipher getCipher() {
    try {
      return Cipher.getInstance(ALGORITHM);
    } catch (final NoSuchPaddingException e) {
      // This should never happen since we're not specifying a padding
      throw new AssertionError("Padding not supported, but no padding specified", e);
    } catch (final NoSuchAlgorithmException e) {
      // This should never happen since we were able to get an instance of this cipher at construction time
      throw new RuntimeException(e);
    }
  }

  @Override
  protected AlgorithmParameterSpec getAlgorithmParameters(final long nonce) {
    return new IvParameterSpec(ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        .putLong(4, nonce)
        .array());
  }

  @Override
  public String getName() {
    return "ChaChaPoly";
  }
}
