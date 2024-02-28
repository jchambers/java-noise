package com.eatthepath.noise.component;

import com.eatthepath.noise.NoiseHandshake;

import java.security.NoSuchAlgorithmException;

/**
 * A named component provider produces concrete implementations of Noise protocol components (key agreement algorithms,
 * ciphers, and hash algorithms) given the names of those components. Callers may provide their own implementations of
 * this interface to add support for components not enumerated in the
 * <a href="https://noiseprotocol.org/noise.html">Noise Protocol Framework specification</a>.
 *
 * @see DefaultNamedComponentProvider
 * @see com.eatthepath.noise.NoiseHandshakeBuilder#setNamedComponentProvider(NamedComponentProvider)
 * @see com.eatthepath.noise.NamedProtocolHandshakeBuilder#NamedProtocolHandshakeBuilder(String, NoiseHandshake.Role, NamedComponentProvider)
 */
public interface NamedComponentProvider {

  /**
   * Returns a new, concrete {@link NoiseKeyAgreement} implementation for the given name.
   *
   * @param name the name of the key agreement algorithm to instantiate
   *
   * @return a new, concrete {@code NoiseKeyAgreement} implementation for the given name
   *
   * @throws NoSuchAlgorithmException if this provider does not recognize the given name, or if the underlying algorithm
   * is not supported by the current JVM
   */
  NoiseKeyAgreement getKeyAgreement(String name) throws NoSuchAlgorithmException;

  /**
   * Returns a new, concrete {@link NoiseCipher} implementation for the given name.
   *
   * @param name the name of the cipher to instantiate
   *
   * @return a new, concrete {@code NoiseCipher} implementation for the given name
   *
   * @throws NoSuchAlgorithmException if this provider does not recognize the given name, or if the underlying algorithm
   * is not supported by the current JVM
   */
  NoiseCipher getCipher(String name) throws NoSuchAlgorithmException;

  /**
   * Returns a new, concrete {@link NoiseHash} implementation for the given name.
   *
   * @param name the name of the hash algorithm to instantiate
   *
   * @return a new, concrete {@code NoiseHash} implementation for the given name
   *
   * @throws NoSuchAlgorithmException if this provider does not recognize the given name, or if the underlying algorithm
   * is not supported by the current JVM
   */
  NoiseHash getHash(String name) throws NoSuchAlgorithmException;
}
