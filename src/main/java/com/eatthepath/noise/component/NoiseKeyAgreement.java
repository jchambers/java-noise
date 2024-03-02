package com.eatthepath.noise.component;

import javax.crypto.KeyAgreement;
import java.security.*;

/**
 * A Noise key agreement implementation encapsulates the key agreement functions of a Noise protocol. A Noise key
 * agreement generates key pairs for key agreement operations with the remote party in a Noise handshake, performs key
 * agreement operations, and converts keys to and from "raw" formats for serialization in Noise messages.
 */
public interface NoiseKeyAgreement {

  /**
   * Returns a {@code NoiseKeyAgreement} instance that implements the named key agreement algorithm. This method
   * recognizes the following key agreement algorithm names:
   * <dl>
   *   <dt>25519</dt>
   *   <dd>Returns a Noise key agreement implementation backed by the {@link KeyAgreement} returned by the
   *   most preferred security provider that supports the "X25519" algorithm</dd>
   *
   *   <dt>448</dt>
   *   <dd>Returns a Noise key agreement implementation backed by the {@link KeyAgreement} returned by the
   *   most preferred security provider that supports the "X448" algorithm</dd>
   * </dl>
   *
   * @param noiseKeyAgreementName the name of the Noise key agreement algorithm for which to return a concrete
   * {@code NoiseKeyAgreement} implementation
   *
   * @return a concrete {@code NoiseKeyAgreement} implementation for the given algorithm name
   *
   * @throws NoSuchAlgorithmException if the given name is a known Noise key agreement name, but the underlying key
   * agreement algorithm is not supported by any security provider in the current JVM
   * @throws IllegalArgumentException if the given name is not a known Noise key agreement name
   *
   * @see KeyAgreement#getInstance(String)
   */
  static NoiseKeyAgreement getInstance(final String noiseKeyAgreementName) throws NoSuchAlgorithmException {
    return switch (noiseKeyAgreementName) {
      case "25519" -> new X25519KeyAgreement();
      case "448" -> new X448KeyAgreement();
      default -> throw new IllegalArgumentException("Unrecognized key agreement name: " + noiseKeyAgreementName);
    };
  }

  /**
   * Returns the name of this Noise key agreement as it would appear in a full Noise protocol name.
   *
   * @return the name of this Noise key agreement as it would appear in a full Noise protocol name
   */
  String getName();

  /**
   * Generates a new key pair compatible with this key agreement algorithm for use in a Noise handshake.
   *
   * @return a new key pair for use in a Noise handshake
   */
  KeyPair generateKeyPair();

  /**
   * Calculates a shared secret from a local private key and a remote public key.
   *
   * @param privateKey the local private key from which to calculate a shared secret
   * @param publicKey the remote public key from which to calculate a shared secret
   *
   * @return a shared secret of length {@link #getPublicKeyLength()}
   *
   * @throws IllegalArgumentException if either the local private key or remote public key is not a valid key for this
   * key agreement algorithm
   */
  byte[] generateSecret(PrivateKey privateKey, PublicKey publicKey);

  /**
   * Returns the length of public keys and shared secrets generated by this key agreement algorithm.
   *
   * @return the length of public keys and shared secrets generated by this key agreement algorithm
   */
  int getPublicKeyLength();

  /**
   * Serializes a public key compatible with this key agreement algorithm to an array of bytes suitable for transmission
   * in a Noise handshake message.
   *
   * @param publicKey the public key to serialize as an array of bytes
   *
   * @return a byte array containing the "raw" public key
   *
   * @see #deserializePublicKey(byte[])
   */
  byte[] serializePublicKey(PublicKey publicKey);

  /**
   * Interprets a "raw" public key as a {@link PublicKey} compatible with this key agreement algorithm.
   *
   * @param publicKeyBytes the "raw" public key bytes to interpret; must have a length of {@link #getPublicKeyLength()}
   *
   * @return a {@code PublicKey} instance defined by the given {@code publicKeyBytes}
   *
   * @throws IllegalArgumentException if the given array of bytes could not be interpreted as a public key compatible
   * with this key agreement algorithm for any reason
   *
   * @see #serializePublicKey(PublicKey)
   */
  PublicKey deserializePublicKey(byte[] publicKeyBytes);

  /**
   * Checks that the given public key is compatible with this key agreement algorithm.
   *
   * @param publicKey the public key to check for compatibility with this key agreement algorithm
   *
   * @throws InvalidKeyException if the given key is not compatible with this key agreement algorithm
   */
  void checkPublicKey(PublicKey publicKey) throws InvalidKeyException;

  /**
   * Checks that both of the keys in the given key pair are compatible with this key agreement algorithm.
   *
   * @param keyPair the key pair to check for compatibility with this key agreement algorithm
   *
   * @throws InvalidKeyException if either key in the given key pair is not compatible with this key agreement algorithm
   */
  void checkKeyPair(KeyPair keyPair) throws InvalidKeyException;
}
