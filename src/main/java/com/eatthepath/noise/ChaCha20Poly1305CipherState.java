package com.eatthepath.noise;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.spec.AlgorithmParameterSpec;

class ChaCha20Poly1305CipherState extends CipherState {

  private final ByteBuffer nonceBuffer = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN);

  public ChaCha20Poly1305CipherState(final Cipher cipher) {
    super(cipher);

    if (!"ChaCha20-Poly1305".equals(cipher.getAlgorithm())) {
      throw new IllegalArgumentException("Unexpected cipher algorithm: " + cipher.getAlgorithm());
    }
  }

  @Override
  protected AlgorithmParameterSpec getAlgorithmParameters(final long nonce) {
    nonceBuffer.putLong(4, nonce);
    return new IvParameterSpec(nonceBuffer.array());
  }
}
