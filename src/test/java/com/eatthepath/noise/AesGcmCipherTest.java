package com.eatthepath.noise;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

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
