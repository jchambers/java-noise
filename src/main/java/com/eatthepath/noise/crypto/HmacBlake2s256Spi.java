package com.eatthepath.noise.crypto;

import java.security.MessageDigest;

class HmacBlake2s256Spi extends HmacSpi {

  HmacBlake2s256Spi() {
    super(new Blake2s256MessageDigest(), 64);
  }

  @Override
  protected int engineGetMacLength() {
    return 32;
  }
}
