package com.eatthepath.noise.component;

import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

@ThreadSafe
abstract class AbstractNoiseCipher implements NoiseCipher {

  @FunctionalInterface
  private interface CipherFinalizer<T> {
    T doFinal() throws IllegalBlockSizeException, BadPaddingException, ShortBufferException;
  }

  protected abstract Cipher getCipher();

  protected abstract AlgorithmParameterSpec getAlgorithmParameters(final long nonce);

  @Override
  public int encrypt(final Key key,
                     final long nonce,
                     @Nullable final ByteBuffer associatedData,
                     final ByteBuffer plaintext,
                     final ByteBuffer ciphertext) throws ShortBufferException {

    final Cipher cipher = getCipher();

    initCipher(cipher, Cipher.ENCRYPT_MODE, key, nonce);

    if (associatedData != null) {
      final byte[] adBytes = new byte[associatedData.remaining()];
      associatedData.get(adBytes);

      cipher.updateAAD(adBytes);
    }

    return finishEncryption(() -> cipher.doFinal(plaintext, ciphertext));
  }

  @Override
  public int encrypt(final Key key,
                     final long nonce,
                     @Nullable final byte[] associatedData,
                     final int aadOffset,
                     final int aadLength,
                     final byte[] plaintext,
                     final int plaintextOffset,
                     final int plaintextLength,
                     final byte[] ciphertext,
                     final int ciphertextOffset) throws ShortBufferException {

    final Cipher cipher = getCipher();

    initCipher(cipher, Cipher.ENCRYPT_MODE, key, nonce);

    if (associatedData != null) {
      cipher.updateAAD(associatedData, aadOffset, aadLength);
    }

    return finishEncryption(() ->
        cipher.doFinal(plaintext, plaintextOffset, plaintextLength, ciphertext, ciphertextOffset));
  }

  @Override
  public int decrypt(final Key key,
                     final long nonce,
                     @Nullable final ByteBuffer associatedData,
                     final ByteBuffer ciphertext,
                     final ByteBuffer plaintext) throws AEADBadTagException, ShortBufferException {

    final Cipher cipher = getCipher();

    initCipher(cipher, Cipher.DECRYPT_MODE, key, nonce);

    if (associatedData != null) {
      final byte[] adBytes = new byte[associatedData.remaining()];
      associatedData.get(adBytes);

      cipher.updateAAD(adBytes);
    }

    return finishDecryption(() -> cipher.doFinal(ciphertext, plaintext));
  }

  @Override
  public int decrypt(final Key key,
                     final long nonce,
                     @Nullable final byte[] associatedData,
                     final int aadOffset,
                     final int aadLength,
                     final byte[] ciphertext,
                     final int ciphertextOffset,
                     final int ciphertextLength,
                     final byte[] plaintext,
                     final int plaintextOffset) throws AEADBadTagException, ShortBufferException {

    final Cipher cipher = getCipher();

    initCipher(cipher, Cipher.DECRYPT_MODE, key, nonce);

    if (associatedData != null) {
      cipher.updateAAD(associatedData, aadOffset, aadLength);
    }

    return finishDecryption(() ->
        cipher.doFinal(ciphertext, ciphertextOffset, ciphertextLength, plaintext, plaintextOffset));
  }

  protected void initCipher(final Cipher cipher, final int mode, final Key key, final long nonce) {
    final AlgorithmParameterSpec algorithmParameterSpec = getAlgorithmParameters(nonce);

    try {
      cipher.init(mode, key, algorithmParameterSpec);
    } catch (final InvalidAlgorithmParameterException e) {
      // This should never happen for a known algorithm with a known "shape" of parameters
      throw new AssertionError(e);
    } catch (final InvalidKeyException e) {
      // This should never happen for a key we control
      throw new AssertionError(e);
    }
  }

  private static <T> T finishDecryption(final CipherFinalizer<T> finalizer)
      throws AEADBadTagException, ShortBufferException {

    try {
      return finalizer.doFinal();
    } catch (final IllegalBlockSizeException e) {
      // We're not using a block cipher
      throw new AssertionError(e);
    } catch (final BadPaddingException e) {
      if (e instanceof AEADBadTagException aeadBadTagException) {
        throw aeadBadTagException;
      }

      // We're also not using padding
      throw new AssertionError(e);
    }
  }

  private static <T> T finishEncryption(final CipherFinalizer<T> finalizer) throws ShortBufferException {
    try {
      return finalizer.doFinal();
    } catch (final IllegalBlockSizeException e) {
      // We're not using a block cipher
      throw new AssertionError(e);
    } catch (final BadPaddingException e) {
      // We're also not using padding
      throw new AssertionError(e);
    }
  }
}
