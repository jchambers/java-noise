package com.eatthepath.noise;

import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;

public class NoiseMessageWriter {

  private final CipherState writerState;

  NoiseMessageWriter(final CipherState writerState) {
    this.writerState = writerState;
  }

  public ByteBuffer writeMessage(final ByteBuffer plaintext) {
    return writerState.encrypt(null, plaintext);
  }

  public int writeMessage(final ByteBuffer plaintext, final ByteBuffer ciphertext) throws ShortBufferException {
    return writerState.encrypt(null, plaintext, ciphertext);
  }

  public byte[] writeMessage(final byte[] plaintext) {
    return writerState.encrypt(null, plaintext);
  }

  public int writeMessage(final byte[] plaintext,
                          final int plaintextOffset,
                          final int plaintextLength,
                          final byte[] ciphertext,
                          final int ciphertextOffset) throws ShortBufferException {

    return writerState.encrypt(null, 0, 0,
        plaintext, plaintextOffset, plaintextLength,
        ciphertext, ciphertextOffset);
  }

  public void rekey() {
    writerState.rekey();
  }

  public int getCiphertextLength(final int plaintextLength) {
    return writerState.getCiphertextLength(plaintextLength);
  }
}
