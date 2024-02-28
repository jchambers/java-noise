package com.eatthepath.noise.component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;

/**
 * A Noise hash implementation encapsulates the hashing functionality of a Noise protocol. A Noise hash provides
 * {@link MessageDigest} instances that implement the Noise hash's hashing algorithm, {@link Mac} instances using the
 * same algorithm for calculating HMAC digests, and key derivation function.
 */
public interface NoiseHash {

  /**
   * Returns the name of this Noise hash as it would appear in a full Noise protocol name.
   *
   * @return the name of this Noise hash as it would appear in a full Noise protocol name
   */
  String getName();

  /**
   * Returns a new {@link MessageDigest} for calculating hashes using this Noise hash's hashing algorithm.
   *
   * @return a new {@link MessageDigest} for calculating hashes
   */
  MessageDigest getMessageDigest();

  /**
   * Returns a new {@link Mac} instance for calculating HMAC digests using this Noise hash's hashing algorithm.
   *
   * @return a new {@code Mac} instance for calculating HMAC digests
   */
  Mac getHmac();

  /**
   * Returns the length of a digest produced by the {@link MessageDigest} or {@link Mac} provided by this Noise hash.
   *
   * @return the length of a digest produced by this Noise hash
   */
  int getHashLength();

  /**
   * Derives two or three pseudo-random keys from the given chaining key and input key material using the HKDF
   * algorithm with this Noise hash's HMAC algorithm.
   * <p>
   * As the Noise Protocol Framework specification notes:
   * <p>
   * <blockquote>Note that [the derived keys] are all [{@link #getHashLength()}] bytes in length. Also note that the
   * [{@code deriveKeys}] function is simply HKDF from [IETF RFC 5869] with the chaining_key as HKDF salt, and
   * zero-length HKDF info.</blockquote>
   *
   * @param chainingKey the chaining key (salt) from which to derive new keys
   * @param inputKeyMaterial the input key material from which to derive new keys
   * @param outputKeys the number of keys to derive; must be either 2 or 3
   *
   * @return an array containing {@code outputKeys} derived keys
   *
   * @see <a href="https://www.ietf.org/rfc/rfc5869.txt">IETF RFC 5869: HMAC-based Extract-and-Expand Key Derivation
   * Function (HKDF)</a>
   */
  default byte[][] deriveKeys(final byte[] chainingKey, final byte[] inputKeyMaterial, final int outputKeys) {
    if (outputKeys < 2 || outputKeys > 3) {
      throw new IllegalArgumentException("Illegal output key count");
    }

    final byte[][] derivedKeys = new byte[getHashLength()][outputKeys];

    final Mac hmac = getHmac();

    try {
      hmac.init(new SecretKeySpec(chainingKey, "RAW"));
      final Key tempKey = new SecretKeySpec(hmac.doFinal(inputKeyMaterial), "RAW");

      for (byte k = 0; k < outputKeys; k++) {
        hmac.init(tempKey);

        if (k > 0) {
          hmac.update(derivedKeys[k - 1]);
        }

        hmac.update((byte) (k + 1));
        derivedKeys[k] = hmac.doFinal();
      }

      return derivedKeys;
    } catch (final InvalidKeyException e) {
      // This should never happen for keys we derive/control
      throw new AssertionError(e);
    }
  }
}
