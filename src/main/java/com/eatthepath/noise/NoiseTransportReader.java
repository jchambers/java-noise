package com.eatthepath.noise;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;

public interface NoiseTransportReader {

  int getPlaintextLength(final int ciphertextLength);

  ByteBuffer readMessage(final ByteBuffer ciphertext) throws AEADBadTagException;

  int readMessage(final ByteBuffer ciphertext, final ByteBuffer plaintext) throws ShortBufferException, AEADBadTagException;

  byte[] readMessage(final byte[] ciphertext) throws AEADBadTagException;

  int readMessage(final byte[] ciphertext,
                  final int ciphertextOffset,
                  final int ciphertextLength,
                  final byte[] plaintext,
                  final int plaintextOffset) throws ShortBufferException, AEADBadTagException;

  void rekeyReader();
}
