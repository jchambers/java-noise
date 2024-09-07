package com.eatthepath.noise.component;

import javax.crypto.KEM;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface NoiseKeyEncapsulationMechanism {

  static NoiseKeyEncapsulationMechanism getInstance(final String name) {
    throw new IllegalArgumentException("Unrecognized key encapsulation method name: " + name);
  }

  String getName();

  KeyPair generateKeyPair();

  /**
   *
   * @param publicKey the remote public key with which to encapsulate a shared secret
   *
   * @return an encapsulated shared secret key
   */
  KEM.Encapsulated encapsulate(PublicKey publicKey);

  byte[] decapsulate(PrivateKey privateKey, byte[] encapsulation);

  int getPublicKeyLength();

  int getEncapsulationLength();

  byte[] serializePublicKey(PublicKey publicKey);

  PublicKey deserializePublicKey(byte[] publicKeyBytes);

  byte[] serializeSharedSecret(SecretKey sharedSecret);

  SecretKey deserializeSharedSecret(byte[] sharedSecretBytes);
}
