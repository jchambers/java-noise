package com.eatthepath.noise.component;

class Blake2bNoiseHashTest extends AbstractNoiseHashTest {

  @Override
  protected NoiseHash getHash() {
    return new Blake2bNoiseHash();
  }
}
