package com.eatthepath.noise.crypto;

import javax.crypto.Mac;

class HmacBlake2s256MacTest extends AbstractBlake2HmacTest {

  @Override
  protected Mac getHmac() {
    return new HmacBlake2s256Mac();
  }
}
