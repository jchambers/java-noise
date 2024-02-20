package com.eatthepath.noise;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

abstract class AbstractNoiseCipherTest {

  protected abstract NoiseCipher getNoiseCipher();

  protected abstract Key generateKey();

  @Test
  void encryptDecryptByteArray() throws AEADBadTagException {
    final Key key = generateKey();
    final long nonce = ThreadLocalRandom.current().nextLong();

    final byte[] hash = new byte[32];
    ThreadLocalRandom.current().nextBytes(hash);

    final byte[] plaintext = "Hark! Plaintext!".getBytes(StandardCharsets.UTF_8);
    final byte[] ciphertext = getNoiseCipher().encrypt(key, nonce, hash, plaintext);

    assertArrayEquals(plaintext, getNoiseCipher().decrypt(key, nonce, hash, ciphertext));
  }

  @Test
  void encryptDecryptByteBuffer() throws AEADBadTagException {
    final Key key = generateKey();
    final long nonce = ThreadLocalRandom.current().nextLong();

    final byte[] hash = new byte[32];
    ThreadLocalRandom.current().nextBytes(hash);

    final ByteBuffer plaintext = ByteBuffer.wrap("Hark! Plaintext!".getBytes(StandardCharsets.UTF_8));
    final ByteBuffer ciphertext = getNoiseCipher().encrypt(key, nonce, ByteBuffer.wrap(hash), plaintext);

    assertEquals(plaintext, getNoiseCipher().decrypt(key, nonce, ByteBuffer.wrap(hash), ciphertext));
  }
}
