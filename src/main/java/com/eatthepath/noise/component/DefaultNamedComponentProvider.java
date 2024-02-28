package com.eatthepath.noise.component;

import java.security.NoSuchAlgorithmException;

/**
 * The default named component provider constructs concrete implementations of all key agreement algorithms, ciphers,
 * and hashes enumerated in the <a href="https://noiseprotocol.org/noise.html">Noise Protocol Framework
 * specification</a>.
 *
 * <h2>Supported component names</h2>
 *
 * <h3>Key agreement algorithms</h3>
 *
 * <dl>
 *   <dt>25519</dt>
 *   <dd>A Noise key agreement implementation backed by the {@link javax.crypto.KeyAgreement} returned by the most
 *   preferred security provider that supports the "X25519" algorithm</dd>
 *
 *   <dt>448</dt>
 *   <dd>A Noise key agreement implementation backed by the {@link javax.crypto.KeyAgreement} returned by the most
 *   preferred security provider that supports the "X448" algorithm</dd>
 * </dl>
 *
 * <h3>Ciphers</h3>
 *
 * <dl>
 *   <dt>ChaChaPoly</dt>
 *   <dd>A Noise cipher implementation backed by the {@link javax.crypto.Cipher} returned by the most preferred security
 *   provider that supports the "ChaCha20-Poly1305" cipher transformation</dd>
 *
 *   <dt>AESGCM</dt>
 *   <dd>A Noise cipher implementation backed by the {@link javax.crypto.Cipher} returned by the most preferred security
 *   provider that supports the "AES/GCM/NoPadding" cipher transformation</dd>
 * </dl>
 *
 * <h3>Hash algorithms</h3>
 *
 * <dl>
 *   <dt>SHA256</dt>
 *   <dd>A Noise hash implementation backed by the {@link java.security.MessageDigest} returned by the most preferred
 *   security provider that supports the "SHA-256" algorithm and the {@link javax.crypto.Mac} returned by the most
 *   preferred security provider that supports the "HmacSHA256" algorithm</dd>
 *
 *   <dt>SHA512</dt>
 *   <dd>A Noise hash implementation backed by the {@link java.security.MessageDigest} returned by the most preferred
 *   security provider that supports the "SHA-512" algorithm and the {@link javax.crypto.Mac} returned by the most
 *   preferred security provider that supports the "HmacSHA512" algorithm</dd>
 *
 *   <dt>BLAKE2s</dt>
 *   <dd>A noise hash implementation backed by {@link com.eatthepath.noise.crypto.Blake2s256MessageDigest} and
 *   {@link com.eatthepath.noise.crypto.HmacBlake2s256Mac}</dd>
 *
 *   <dt>BLAKE2b</dt>
 *   <dd>A noise hash implementation backed by {@link com.eatthepath.noise.crypto.Blake2b512MessageDigest} and
 *   {@link com.eatthepath.noise.crypto.HmacBlake2b512Mac}</dd>
 * </dl>
 * 
 * @see javax.crypto.KeyAgreement#getInstance(String) 
 * @see javax.crypto.Cipher#getInstance(String)
 * @see javax.crypto.Mac#getInstance(String) 
 * @see java.security.MessageDigest#getInstance(String)
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html">Java Security
 * Standard Algorithm Names</a>
 */
public class DefaultNamedComponentProvider implements NamedComponentProvider {

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
      case "SHA256" -> new Sha256NoiseHash();
      case "SHA512" -> new Sha512NoiseHash();
      case "BLAKE2s" -> new Blake2sNoiseHash();
      case "BLAKE2b" -> new Blake2bNoiseHash();
      default -> throw new NoSuchAlgorithmException("Unrecognized hash name: " + name);
    };
  }
}
