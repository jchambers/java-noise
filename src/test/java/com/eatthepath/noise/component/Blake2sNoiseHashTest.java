package com.eatthepath.noise.component;

class Blake2sNoiseHashTest extends AbstractNoiseHashTest {

  @Override
  protected NoiseHash getHash() {
    return new Blake2sNoiseHash();
  }
}
