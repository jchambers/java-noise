package com.eatthepath.noise;

import java.security.NoSuchAlgorithmException;

public class DefaultProtocolNameResolver implements ProtocolNameResolver {

  @Override
  public NoiseKeyAgreement getKeyAgreement(final String name) throws NoSuchAlgorithmException {
    return switch (name) {
      case "25519" -> new X25519KeyAgreement();
      case "448" -> new X448KeyAgreement();
      default -> throw new NoSuchAlgorithmException("Unrecognized key agreement name: " + name);
    };
  }

  @Override
  public NoiseCipher getCipher(final String name) throws NoSuchAlgorithmException {
    return switch (name) {
      case "ChaChaPoly" -> new ChaCha20Poly1305Cipher();
      case "AESGCM" -> new AesGcmCipher();
      default -> throw new NoSuchAlgorithmException("Unrecognized cipher name: " + name);
    };
  }

  @Override
  public NoiseHash getHash(final String name) throws NoSuchAlgorithmException {
    return switch (name) {
      case "SHA256" -> new Sha256Hash();
      case "SHA512" -> new Sha512Hash();
      default -> throw new NoSuchAlgorithmException("Unrecognized hash name: " + name);
    };
  }
}
