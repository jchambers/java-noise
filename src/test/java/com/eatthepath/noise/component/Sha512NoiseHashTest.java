package com.eatthepath.noise.component;

import org.opentest4j.TestAbortedException;

import java.security.NoSuchAlgorithmException;

class Sha512NoiseHashTest extends AbstractNoiseHashTest {

  @Override
  protected NoiseHash getHash() {
    try {
      return new Sha512NoiseHash();
    } catch (final NoSuchAlgorithmException e) {
      throw new TestAbortedException("SHA512 not supported", e);
    }
  }
}
