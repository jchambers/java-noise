package com.eatthepath.noise;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;

class AesGcmCipherState extends CipherState {

  private final ByteBuffer nonceBuffer = ByteBuffer.allocate(12);

  public AesGcmCipherState(final Cipher cipher) {
    super(cipher);

    if (!"AES/GCM/NoPadding".equals(cipher.getAlgorithm())) {
      throw new IllegalArgumentException("Unexpected cipher algorithm: " + cipher.getAlgorithm());
    }
  }

  @Override
  protected AlgorithmParameterSpec getAlgorithmParameters(final long nonce) {
    nonceBuffer.putLong(4, nonce);
    return new IvParameterSpec(nonceBuffer.array());
  }
}
