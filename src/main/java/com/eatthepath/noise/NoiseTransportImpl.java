package com.eatthepath.noise;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;

class NoiseTransportImpl implements NoiseTransport {

  private final CipherState readerState;
  private final CipherState writerState;

  NoiseTransportImpl(final CipherState readerState, final CipherState writerState) {
    this.readerState = readerState;
    this.writerState = writerState;
  }

  @Override
  public int getPlaintextLength(final int ciphertextLength) {
    return readerState.getPlaintextLength(ciphertextLength);
  }

  @Override
  public int getCiphertextLength(final int plaintextLength) {
    return writerState.getCiphertextLength(plaintextLength);
  }

  @Override
  public ByteBuffer readMessage(final ByteBuffer ciphertext) throws AEADBadTagException {
    return readerState.decrypt(null, ciphertext);
  }

  @Override
  public int readMessage(final ByteBuffer ciphertext, final ByteBuffer plaintext) throws ShortBufferException, AEADBadTagException {
    return readerState.decrypt(null, ciphertext, plaintext);
  }

  @Override
  public byte[] readMessage(final byte[] ciphertext) throws AEADBadTagException {
    return readerState.decrypt(null, ciphertext);
  }

  @Override
  public int readMessage(final byte[] ciphertext,
                         final int ciphertextOffset,
                         final int ciphertextLength,
                         final byte[] plaintext,
                         final int plaintextOffset) throws ShortBufferException, AEADBadTagException {

    return readerState.decrypt(null, 0, 0,
        ciphertext, ciphertextOffset, ciphertextLength,
        plaintext, plaintextOffset);
  }

  @Override
  public ByteBuffer writeMessage(final ByteBuffer plaintext) {
    return writerState.encrypt(null, plaintext);
  }

  @Override
  public int writeMessage(final ByteBuffer plaintext, final ByteBuffer ciphertext) throws ShortBufferException {
    return writerState.encrypt(null, plaintext, ciphertext);
  }

  @Override
  public byte[] writeMessage(final byte[] plaintext) {
    return writerState.encrypt(null, plaintext);
  }

  @Override
  public int writeMessage(final byte[] plaintext,
                          final int plaintextOffset,
                          final int plaintextLength,
                          final byte[] ciphertext,
                          final int ciphertextOffset) throws ShortBufferException {

    return writerState.encrypt(null, 0, 0,
        plaintext, plaintextOffset, plaintextLength,
        ciphertext, ciphertextOffset);
  }

  @Override
  public void rekeyReader() {
    readerState.rekey();
  }

  @Override
  public void rekeyWriter() {
    writerState.rekey();
  }
}
