package com.eatthepath.noise.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidKeyException;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.assertEquals;

abstract class AbstractBlake2HmacTest {

  protected abstract Mac getHmac();

  @Test
  void getMacLength() throws InvalidKeyException {
    final Key key = new SecretKeySpec(new byte[32], "RAW");

    final Mac hmac = getHmac();
    hmac.init(key);
    hmac.update(new byte[32]);

    assertEquals(hmac.getMacLength(), hmac.doFinal().length);
  }
}
