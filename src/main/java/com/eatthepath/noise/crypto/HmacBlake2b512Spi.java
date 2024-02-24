package com.eatthepath.noise.crypto;

import java.security.MessageDigest;

public class HmacBlake2b512Spi extends HmacSpi {

  protected HmacBlake2b512Spi() {
    super(new Blake2b512MessageDigest(), 128);
  }

  @Override
  protected int engineGetMacLength() {
    return 64;
  }
}
