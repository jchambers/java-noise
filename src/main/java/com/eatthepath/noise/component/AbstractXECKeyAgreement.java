package com.eatthepath.noise.component;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.interfaces.XECKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
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
    return XECUtil.serializePublicKey(publicKey, getPublicKeyLength(), getX509Prefix());
  }

  @Override
  public PublicKey deserializePublicKey(final byte[] publicKeyBytes) {
    return XECUtil.deserializePublicKey(publicKeyBytes, getPublicKeyLength(), getX509Prefix(), keyFactory);
  }

  @Override
  public void checkPublicKey(final PublicKey publicKey) throws InvalidKeyException {
    XECUtil.checkKey(publicKey, keyAgreement.getAlgorithm());
  }

  @Override
  public void checkKeyPair(final KeyPair keyPair) throws InvalidKeyException {
    XECUtil.checkKey(keyPair.getPublic(), keyAgreement.getAlgorithm());
    XECUtil.checkKey(keyPair.getPrivate(), keyAgreement.getAlgorithm());
  }
}
