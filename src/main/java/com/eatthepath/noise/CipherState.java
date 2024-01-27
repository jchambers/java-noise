package com.eatthepath.noise;

import javax.annotation.Nullable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

@NotThreadSafe
public abstract class CipherState {

  private Key key;
  private long nonce;

  private final Cipher cipher;

  private static final long MAX_NONCE = 0xffffffffffffffffL;

  @FunctionalInterface
  private interface CipherFinalizer<T> {

    T doFinal() throws IllegalBlockSizeException, BadPaddingException, ShortBufferException;
  }

  public CipherState(final Cipher cipher) {
    this.cipher = cipher;
  }

  public void setKey(final Key key) {
    this.key = key;
    this.nonce = 0;
  }

  public boolean hasKey() {
    return this.key != null;
  }

  public void setNonce(final long nonce) {
    this.nonce = nonce;
  }

  public ByteBuffer decrypt(@Nullable final ByteBuffer associatedData, final ByteBuffer ciphertext)
      throws AEADBadTagException {

    final ByteBuffer plaintext = ByteBuffer.allocate(getPlaintextLength(ciphertext.remaining()));

    try {
      decrypt(associatedData, ciphertext, plaintext);
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return plaintext;
  }

  public int decrypt(@Nullable final ByteBuffer associatedData, final ByteBuffer ciphertext, final ByteBuffer plaintext)
      throws AEADBadTagException, ShortBufferException {

    if (hasKey()) {
      initCipher(Cipher.DECRYPT_MODE, nonce);

      if (associatedData != null) {
        cipher.updateAAD(associatedData);
      }

      final int plaintextLength = finishDecryption(() -> cipher.doFinal(ciphertext, plaintext));
      nonce += 1;

      return plaintextLength;
    } else {
      final int ciphertextLength = ciphertext.remaining();
      plaintext.put(ciphertext);

      return ciphertextLength;
    }
  }

  public byte[] decrypt(@Nullable final byte[] associatedData, final byte[] ciphertext) throws AEADBadTagException {
    final byte[] plaintext = new byte[getPlaintextLength(ciphertext.length)];

    try {
      decrypt(associatedData,
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

  public int decrypt(@Nullable final byte[] associatedData,
                     final int aadOffset,
                     final int aadLength,
                     final byte[] ciphertext,
                     final int ciphertextOffset,
                     final int ciphertextLength,
                     final byte[] plaintext,
                     final int plaintextOffset) throws AEADBadTagException, ShortBufferException {

    if (hasKey()) {
      initCipher(Cipher.DECRYPT_MODE, nonce);

      if (associatedData != null) {
        cipher.updateAAD(associatedData, aadOffset, aadLength);
      }

      final int plaintextLength = finishDecryption(() ->
          cipher.doFinal(ciphertext, ciphertextOffset, ciphertextLength, plaintext, plaintextOffset));

      nonce += 1;

      return plaintextLength;
    } else {
      System.arraycopy(ciphertext, ciphertextOffset, plaintext, plaintextOffset, ciphertextLength);
      return ciphertextLength;
    }
  }

  public ByteBuffer encrypt(@Nullable final ByteBuffer associatedData, final ByteBuffer plaintext) {
    final ByteBuffer ciphertext = ByteBuffer.allocate(getCiphertextLength(plaintext.remaining()));

    try {
      encrypt(associatedData, plaintext, ciphertext);
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return ciphertext;
  }

  public int encrypt(@Nullable final ByteBuffer associatedData, final ByteBuffer plaintext, final ByteBuffer ciphertext) throws ShortBufferException {
    if (hasKey()) {
      initCipher(Cipher.ENCRYPT_MODE, nonce);

      if (associatedData != null) {
        cipher.updateAAD(associatedData);
      }

      final int ciphertextLength = finishEncryption(() -> cipher.doFinal(plaintext, ciphertext));
      nonce += 1;

      return ciphertextLength;
    } else {
      final int plaintextLength = plaintext.remaining();
      ciphertext.put(plaintext);

      return plaintextLength;
    }
  }

  public byte[] encrypt(@Nullable final byte[] associatedData, final byte[] plaintext) {
    final byte[] ciphertext = new byte[getCiphertextLength(plaintext.length)];

    try {
      encrypt(associatedData,
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

  public int encrypt(@Nullable final byte[] associatedData,
                       final int aadOffset,
                       final int aadLength,
                       final byte[] plaintext,
                       final int plaintextOffset,
                       final int plaintextLength,
                       final byte[] ciphertext,
                       final int ciphertextOffset) throws ShortBufferException {

    if (hasKey()) {
      initCipher(Cipher.ENCRYPT_MODE, nonce);

      if (associatedData != null) {
        cipher.updateAAD(associatedData, aadOffset, aadLength);
      }

      final int ciphertextLength = finishEncryption(() ->
          cipher.doFinal(plaintext, plaintextOffset, plaintextLength, ciphertext, ciphertextOffset));

      nonce += 1;

      return ciphertextLength;
    } else {
      System.arraycopy(plaintext, plaintextOffset, ciphertext, ciphertextOffset, plaintextLength);
      return plaintextLength;
    }
  }

  public void rekey() {
    if (!hasKey()) {
      throw new IllegalStateException("No key set");
    }

    key = rekey(key);
  }

  protected Key rekey(final Key key) {
    initCipher(Cipher.ENCRYPT_MODE, MAX_NONCE, key);

    try {
      return new SecretKeySpec(finishEncryption(() -> cipher.doFinal(new byte[32])), "RAW");
    } catch (final ShortBufferException e) {
      // This should never happen when we're returning a new byte array
      throw new AssertionError(e);
    }
  }

  private void initCipher(final int mode, final long nonce) {
    initCipher(mode, nonce, this.key);
  }

  private void initCipher(final int mode, final long nonce, final Key key) {
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

  protected abstract AlgorithmParameterSpec getAlgorithmParameters(final long nonce);

  public int getCiphertextLength(final int plaintextLength) {
    return hasKey() ? plaintextLength + 16 : plaintextLength;
  }

  public int getPlaintextLength(final int ciphertextLength) {
    if (hasKey()) {
      if (ciphertextLength < 16) {
        throw new IllegalArgumentException("Ciphertexts must be at least 16 bytes long");
      }

      return ciphertextLength - 16;
    } else {
      return ciphertextLength;
    }
  }
}
