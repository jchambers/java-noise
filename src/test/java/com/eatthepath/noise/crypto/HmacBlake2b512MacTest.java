package com.eatthepath.noise.crypto;

import javax.crypto.Mac;

class HmacBlake2b512MacTest extends AbstractBlake2HmacTest {

  @Override
  protected Mac getHmac() {
    return new HmacBlake2b512Mac();
  }
}
