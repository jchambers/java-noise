package com.eatthepath.noise.component;

class Sha256NoiseHashTest extends AbstractNoiseHashTest {

  @Override
  protected NoiseHash getHash() {
    return new Sha256NoiseHash();
  }
}
