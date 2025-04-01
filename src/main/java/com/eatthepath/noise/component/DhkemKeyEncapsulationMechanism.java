package com.eatthepath.noise.component;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class DhkemKeyEncapsulationMechanism implements NoiseKeyEncapsulationMechanism {

  private final KEM kem;
  private final KeyPairGenerator keyPairGenerator;
  private final KeyFactory keyFactory;

  public DhkemKeyEncapsulationMechanism() throws NoSuchAlgorithmException {
    this.keyPairGenerator = KeyPairGenerator.getInstance("X25519");
    this.keyFactory = KeyFactory.getInstance("X25519");
    this.kem = KEM.getInstance("DHKEM");
  }

  @Override
  public String getName() {
    return "DHKEM";
  }

  @Override
  public KeyPair generateKeyPair() {
    return keyPairGenerator.generateKeyPair();
  }

  @Override
  public KEM.Encapsulated encapsulate(final PublicKey publicKey) {
    try {
      return kem.newEncapsulator(publicKey).encapsulate();
    } catch (final InvalidKeyException e) {
      throw new IllegalArgumentException("Invalid public key for encapsulation", e);
    }
  }

  @Override
  public byte[] decapsulate(final PrivateKey privateKey, final byte[] encapsulation) {
    try {
      return serializeSharedSecret(kem.newDecapsulator(privateKey).decapsulate(encapsulation));
    } catch (final DecapsulateException e) {
      throw new IllegalArgumentException("Invalid encapsulation", e);
    } catch (final InvalidKeyException e) {
      throw new IllegalArgumentException("Invalid private key for decapsulation", e);
    }
  }

  @Override
  public int getPublicKeyLength() {
    return 32;
  }

  @Override
  public int getEncapsulationLength() {
    return 32;
  }

  @Override
  public byte[] serializePublicKey(final PublicKey publicKey) {
    return XECUtil.serializePublicKey(publicKey, getPublicKeyLength(), XECUtil.X25519_X509_PREFIX);
  }

  @Override
  public PublicKey deserializePublicKey(final byte[] publicKeyBytes) {
    return XECUtil.deserializePublicKey(publicKeyBytes, getPublicKeyLength(), XECUtil.X25519_X509_PREFIX, keyFactory);
  }

  @Override
  public byte[] serializeSharedSecret(final SecretKey sharedSecret) {
    // For DHKEM, the shared secret has a "raw" encoding
    return sharedSecret.getEncoded();
  }

  @Override
  public SecretKey deserializeSharedSecret(final byte[] sharedSecretBytes) {
    return new SecretKeySpec(sharedSecretBytes, "Generic");
  }
}
