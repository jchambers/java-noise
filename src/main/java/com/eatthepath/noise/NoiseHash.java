package com.eatthepath.noise;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;

public interface NoiseHash {

  String getName();

  MessageDigest getMessageDigest();

  Mac getHmac();

  int getHashLength();

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
