package com.eatthepath.noise;

import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;

@ThreadSafe
public interface NoiseCipher {

  String getName();

  default ByteBuffer encrypt(final Key key,
                             final long nonce,
                             @Nullable final ByteBuffer associatedData,
                             final ByteBuffer plaintext) {

    final ByteBuffer ciphertext = ByteBuffer.allocate(getCiphertextLength(plaintext.remaining()));

    try {
      encrypt(key, nonce, associatedData, plaintext, ciphertext);
      ciphertext.flip();
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return ciphertext;
  }

  int encrypt(final Key key,
              final long nonce,
              @Nullable final ByteBuffer associatedData,
              final ByteBuffer plaintext,
              final ByteBuffer ciphertext)
      throws ShortBufferException;

  default byte[] encrypt(final Key key,
                         final long nonce,
                         @Nullable final byte[] associatedData,
                         final byte[] plaintext) {

    final byte[] ciphertext = new byte[getCiphertextLength(plaintext.length)];

    try {
      encrypt(key,
          nonce,
          associatedData,
          0,
          associatedData != null ? associatedData.length : 0,
          plaintext,
          0,
          plaintext.length,
          ciphertext,
          0);
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return ciphertext;
  }

  int encrypt(final Key key,
              final long nonce,
              @Nullable final byte[] associatedData,
              final int aadOffset,
              final int aadLength,
              final byte[] plaintext,
              final int plaintextOffset,
              final int plaintextLength,
              final byte[] ciphertext,
              final int ciphertextOffset) throws ShortBufferException;

  default ByteBuffer decrypt(final Key key,
                             final long nonce,
                             @Nullable final ByteBuffer associatedData,
                             final ByteBuffer ciphertext) throws AEADBadTagException {

    final ByteBuffer plaintext = ByteBuffer.allocate(getPlaintextLength(ciphertext.remaining()));

    try {
      decrypt(key, nonce, associatedData, ciphertext, plaintext);
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return plaintext;
  }

  int decrypt(final Key key,
              final long nonce,
              @Nullable final ByteBuffer associatedData,
              final ByteBuffer ciphertext,
              final ByteBuffer plaintext)
      throws AEADBadTagException, ShortBufferException;

  default byte[] decrypt(final Key key,
                         final long nonce,
                         @Nullable final byte[] associatedData,
                         final byte[] ciphertext) throws AEADBadTagException {

    final byte[] plaintext = new byte[getPlaintextLength(ciphertext.length)];

    try {
      decrypt(key,
          nonce,
          associatedData,
          0,
          associatedData != null ? associatedData.length : 0,
          ciphertext,
          0,
          ciphertext.length,
          plaintext,
          0);
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return plaintext;
  }

  int decrypt(final Key key,
              final long nonce,
              @Nullable final byte[] associatedData,
              final int aadOffset,
              final int aadLength,
              final byte[] ciphertext,
              final int ciphertextOffset,
              final int ciphertextLength,
              final byte[] plaintext,
              final int plaintextOffset) throws AEADBadTagException, ShortBufferException;

  default int getCiphertextLength(final int plaintextLength) {
    return plaintextLength + 16;
  }

  default int getPlaintextLength(final int ciphertextLength) {
    if (ciphertextLength < 16) {
      throw new IllegalArgumentException("Ciphertexts must be at least 16 bytes long");
    }

    return ciphertextLength - 16;
  }

  Key buildKey(byte[] keyBytes);

  default Key rekey(final Key key) {
    return new SecretKeySpec(encrypt(key, 0xffffffffffffffffL, null, new byte[32]), "RAW");
  }
}
