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

  public ChaCha20Poly1305Cipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    super(Cipher.getInstance("ChaCha20-Poly1305"));
  }

  @Override
  protected AlgorithmParameterSpec getAlgorithmParameters(final long nonce) {
    nonceBuffer.putLong(4, nonce);
    return new IvParameterSpec(nonceBuffer.array());
  }
}
