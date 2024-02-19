package com.eatthepath.noise;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;

public class NoiseMessageReader {

  private final CipherState readerState;

  NoiseMessageReader(final CipherState readerState) {
    this.readerState = readerState;
  }

  public ByteBuffer readMessage(final ByteBuffer ciphertext) throws AEADBadTagException {
    return readerState.decrypt(null, ciphertext);
  }

  public int readMessage(final ByteBuffer ciphertext, final ByteBuffer plaintext) throws ShortBufferException, AEADBadTagException {
    return readerState.decrypt(null, ciphertext, plaintext);
  }

  public byte[] readMessage(final byte[] ciphertext) throws AEADBadTagException {
    return readerState.decrypt(null, ciphertext);
  }

  public int readMessage(final byte[] ciphertext,
                         final int ciphertextOffset,
                         final int ciphertextLength,
                         final byte[] plaintext,
                         final int plaintextOffset) throws ShortBufferException, AEADBadTagException {

    return readerState.decrypt(null, 0, 0,
        ciphertext, ciphertextOffset, ciphertextLength,
        plaintext, plaintextOffset);
  }

  public void rekey() {
    readerState.rekey();
  }

  public int getPlaintextLength(final int ciphertextLength) {
    return readerState.getPlaintextLength(ciphertextLength);
  }
}
