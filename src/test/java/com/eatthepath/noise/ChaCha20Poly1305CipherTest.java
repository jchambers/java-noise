package com.eatthepath.noise;

import org.opentest4j.TestAbortedException;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

class ChaCha20Poly1305CipherTest extends AbstractNoiseCipherTest {

  @Override
  protected NoiseCipher getNoiseCipher() {
    try {
      return new ChaCha20Poly1305Cipher();
    } catch (final NoSuchAlgorithmException e) {
      throw new TestAbortedException("ChaCha20Poly1305 not supported", e);
    }
  }

  @Override
  protected Key generateKey() {
    final byte[] keyBytes = new byte[32];
    ThreadLocalRandom.current().nextBytes(keyBytes);

    return new SecretKeySpec(keyBytes, "RAW");
  }
}
