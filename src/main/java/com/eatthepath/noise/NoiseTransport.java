package com.eatthepath.noise;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;

public class NoiseTransport {

  private final CipherState readerState;
  private final CipherState writerState;

  public NoiseTransport(final CipherState readerState, final CipherState writerState) {
    this.readerState = readerState;
    this.writerState = writerState;
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

  public void rekeyReader() {
    readerState.rekey();
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

  public void rekeyWriter() {
    writerState.rekey();
  }

  public int getPlaintextLength(final int ciphertextLength) {
    return readerState.getPlaintextLength(ciphertextLength);
  }

  public int getCiphertextLength(final int plaintextLength) {
    return writerState.getCiphertextLength(plaintextLength);
  }
}
