package com.eatthepath.noise.component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.concurrent.ThreadLocalRandom;

class AesGcmCipherTest extends AbstractNoiseCipherTest {

  @Override
  protected NoiseCipher getNoiseCipher() {
    return new AesGcmCipher();
  }

  @Override
  protected Key generateKey() {
    final byte[] keyBytes = new byte[32];
    ThreadLocalRandom.current().nextBytes(keyBytes);

    return new SecretKeySpec(keyBytes, "AES");
  }
}
