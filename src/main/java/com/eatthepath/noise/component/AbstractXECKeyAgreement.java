package com.eatthepath.noise.component;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

abstract class AbstractXECKeyAgreement implements NoiseKeyAgreement {

  private final KeyAgreement keyAgreement;
  private final KeyPairGenerator keyPairGenerator;
  private final KeyFactory keyFactory;

  protected AbstractXECKeyAgreement(final KeyAgreement keyAgreement,
                          final KeyPairGenerator keyPairGenerator,
                          final KeyFactory keyFactory) {

    this.keyAgreement = keyAgreement;
    this.keyPairGenerator = keyPairGenerator;
    this.keyFactory = keyFactory;
  }

  protected abstract byte[] getX509Prefix();

  @Override
  public KeyPair generateKeyPair() {
    return keyPairGenerator.generateKeyPair();
  }

  @Override
  public byte[] generateSecret(final PrivateKey privateKey, final PublicKey publicKey) {
    try {
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(publicKey, true);
      return keyAgreement.generateSecret();
    } catch (final InvalidKeyException e) {
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public byte[] serializePublicKey(final PublicKey publicKey) {
    // TODO This is a pretty hacky way of dealing with key serialization; come back to this with a real encoder
    final byte[] serializedPublicKey = new byte[getPublicKeyLength()];
    System.arraycopy(publicKey.getEncoded(), getX509Prefix().length, serializedPublicKey, 0, getPublicKeyLength());

    return serializedPublicKey;
  }

  @Override
  public PublicKey deserializePublicKey(final byte[] publicKeyBytes) {
    // TODO This is a pretty hacky way of dealing with key deserialization; come back to this with a real decoder
    final int publicKeyLength = getPublicKeyLength();

    if (publicKeyBytes.length != publicKeyLength) {
      throw new IllegalArgumentException("Unexpected serialized public key length");
    }

    final byte[] x509Prefix = getX509Prefix();
    final byte[] x509Bytes = new byte[publicKeyLength + x509Prefix.length];
    System.arraycopy(x509Prefix, 0, x509Bytes, 0, x509Prefix.length);
    System.arraycopy(publicKeyBytes, 0, x509Bytes, x509Prefix.length, publicKeyLength);

    try {
      return keyFactory.generatePublic(new X509EncodedKeySpec(x509Bytes, keyFactory.getAlgorithm()));
    } catch (final InvalidKeySpecException e) {
      throw new IllegalArgumentException("Invalid key", e);
    }
  }

  @Override
  public void checkPublicKey(final PublicKey publicKey) throws InvalidKeyException {
    checkKeyPair(new KeyPair(publicKey, generateKeyPair().getPrivate()));
  }

  @Override
  public void checkKeyPair(final KeyPair keyPair) throws InvalidKeyException {
    keyAgreement.init(keyPair.getPrivate());
    keyAgreement.doPhase(keyPair.getPublic(), true);
    keyAgreement.generateSecret();
  }
}
