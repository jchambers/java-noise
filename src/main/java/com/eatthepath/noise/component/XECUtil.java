package com.eatthepath.noise.component;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.XECKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

class XECUtil {

  static final byte[] X25519_X509_PREFIX = HexFormat.of().parseHex("302a300506032b656e032100");
  static final byte[] X448_X509_PREFIX = HexFormat.of().parseHex("3042300506032b656f033900");

  private XECUtil() {
  }

  static byte[] serializePublicKey(final PublicKey publicKey, final int publicKeyLength, final byte[] x509Prefix) {
    // This is a little hacky, but the structure for an X.509 public key defines the order in which its elements appear.
    // The first part of the key, which defines the algorithm and its parameters, is always the same for keys of the
    // same type, and the last N bytes are the literal key material.
    final byte[] serializedPublicKey = new byte[publicKeyLength];
    System.arraycopy(publicKey.getEncoded(), x509Prefix.length, serializedPublicKey, 0, publicKeyLength);

    return serializedPublicKey;
  }

  static PublicKey deserializePublicKey(final byte[] publicKeyBytes,
                                        final int publicKeyLength,
                                        final byte[] x509Prefix,
                                        final KeyFactory keyFactory) {

    if (publicKeyBytes.length != publicKeyLength) {
      throw new IllegalArgumentException("Unexpected serialized public key length");
    }

    final byte[] x509Bytes = new byte[publicKeyLength + x509Prefix.length];
    System.arraycopy(x509Prefix, 0, x509Bytes, 0, x509Prefix.length);
    System.arraycopy(publicKeyBytes, 0, x509Bytes, x509Prefix.length, publicKeyLength);

    try {
      return keyFactory.generatePublic(new X509EncodedKeySpec(x509Bytes, keyFactory.getAlgorithm()));
    } catch (final InvalidKeySpecException e) {
      throw new IllegalArgumentException("Invalid key", e);
    }
  }

  static void checkKey(final Key key, final String algorithm) throws InvalidKeyException {
    if (key instanceof XECKey xecKey) {
      if (xecKey.getParams() instanceof NamedParameterSpec namedParameterSpec) {
        if (!algorithm.equals(namedParameterSpec.getName())) {
          throw new InvalidKeyException("Unexpected key algorithm: " + namedParameterSpec.getName());
        }
      } else {
        throw new InvalidKeyException("Unexpected key parameter type: " + xecKey.getParams().getClass());
      }
    } else {
      throw new InvalidKeyException("Unexpected key type: " + key.getClass());
    }
  }
}
