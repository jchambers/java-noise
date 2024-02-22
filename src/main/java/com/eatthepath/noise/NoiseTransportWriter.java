package com.eatthepath.noise;

import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;

public interface NoiseTransportWriter {

  int getCiphertextLength(final int plaintextLength);

  ByteBuffer writeMessage(final ByteBuffer plaintext);

  int writeMessage(final ByteBuffer plaintext, final ByteBuffer ciphertext) throws ShortBufferException;

  byte[] writeMessage(final byte[] plaintext);

  int writeMessage(final byte[] plaintext,
                   final int plaintextOffset,
                   final int plaintextLength,
                   final byte[] ciphertext,
                   final int ciphertextOffset) throws ShortBufferException;

  void rekeyWriter();
}
