package com.eatthepath.noise.component;

import org.junit.jupiter.api.Test;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

abstract class AbstractNoiseCipherTest {

  protected abstract NoiseCipher getNoiseCipher();

  protected abstract Key generateKey();

  @Test
  void encryptDecryptNewByteArray() throws AEADBadTagException {
    final Key key = generateKey();
    final long nonce = ThreadLocalRandom.current().nextLong();

    final byte[] hash = new byte[32];
    ThreadLocalRandom.current().nextBytes(hash);

    final byte[] plaintext = "Hark! Plaintext!".getBytes(StandardCharsets.UTF_8);
    final byte[] ciphertext = getNoiseCipher().encrypt(key, nonce, hash, plaintext);

    assertEquals(ciphertext.length, getNoiseCipher().getCiphertextLength(plaintext.length));
    assertEquals(plaintext.length, getNoiseCipher().getPlaintextLength(ciphertext.length));

    assertArrayEquals(plaintext, getNoiseCipher().decrypt(key, nonce, hash, ciphertext));
  }

  @Test
  void encryptDecryptByteArrayInPlace() throws AEADBadTagException, ShortBufferException {
    final Key key = generateKey();
    final long nonce = ThreadLocalRandom.current().nextLong();

    final byte[] hash = new byte[32];
    ThreadLocalRandom.current().nextBytes(hash);

    final byte[] plaintextBytes = "Hark! Plaintext!".getBytes(StandardCharsets.UTF_8);
    final byte[] buffer = new byte[getNoiseCipher().getCiphertextLength(plaintextBytes.length)];

    System.arraycopy(plaintextBytes, 0, buffer, 0, plaintextBytes.length);

    assertEquals(buffer.length, getNoiseCipher().encrypt(key, nonce,
        hash, 0, hash.length,
        buffer, 0, plaintextBytes.length,
        buffer, 0));

    assertEquals(plaintextBytes.length, getNoiseCipher().decrypt(key, nonce,
        hash, 0, hash.length,
        buffer, 0, buffer.length,
        buffer, 0));

    final byte[] decryptedPlaintextBytes = new byte[plaintextBytes.length];
    System.arraycopy(buffer, 0, decryptedPlaintextBytes, 0, decryptedPlaintextBytes.length);

    assertArrayEquals(plaintextBytes, decryptedPlaintextBytes);
  }

  @Test
  void encryptDecryptNewByteBuffer() throws AEADBadTagException {
    final Key key = generateKey();
    final long nonce = ThreadLocalRandom.current().nextLong();

    final ByteBuffer hashBuffer;
    {
      final byte[] hash = new byte[32];
      ThreadLocalRandom.current().nextBytes(hash);

      hashBuffer = ByteBuffer.wrap(hash);
    }

    final ByteBuffer plaintext = ByteBuffer.wrap("Hark! Plaintext!".getBytes(StandardCharsets.UTF_8));
    final ByteBuffer ciphertext = getNoiseCipher().encrypt(key, nonce, hashBuffer, plaintext);

    plaintext.rewind();
    hashBuffer.rewind();

    assertEquals(ciphertext.remaining(), getNoiseCipher().getCiphertextLength(plaintext.remaining()));
    assertEquals(plaintext.remaining(), getNoiseCipher().getPlaintextLength(ciphertext.remaining()));

    assertEquals(plaintext, getNoiseCipher().decrypt(key, nonce, hashBuffer, ciphertext));
  }

  @Test
  void encryptDecryptByteBufferInPlace() throws AEADBadTagException, ShortBufferException {
    final Key key = generateKey();
    final long nonce = ThreadLocalRandom.current().nextLong();

    final ByteBuffer hashBuffer;
    {
      final byte[] hash = new byte[32];
      ThreadLocalRandom.current().nextBytes(hash);

      hashBuffer = ByteBuffer.wrap(hash);
    }

    final byte[] plaintextBytes = "Hark! Plaintext!".getBytes(StandardCharsets.UTF_8);
    final byte[] sharedByteArray = new byte[getNoiseCipher().getCiphertextLength(plaintextBytes.length)];

    final ByteBuffer plaintextBuffer = ByteBuffer.wrap(sharedByteArray)
        .limit(plaintextBytes.length)
        .put(plaintextBytes)
        .flip();

    final ByteBuffer ciphertextBuffer = ByteBuffer.wrap(sharedByteArray);

    assertEquals(sharedByteArray.length,
        getNoiseCipher().encrypt(key, nonce, hashBuffer, plaintextBuffer, ciphertextBuffer));

    assertEquals(plaintextBytes.length, plaintextBuffer.limit());
    assertEquals(plaintextBuffer.limit(), plaintextBuffer.position());
    assertEquals(sharedByteArray.length, ciphertextBuffer.position());

    hashBuffer.rewind();
    plaintextBuffer.rewind();
    ciphertextBuffer.rewind();

    assertEquals(plaintextBytes.length,
        getNoiseCipher().decrypt(key, nonce, hashBuffer, ciphertextBuffer, plaintextBuffer));

    assertEquals(plaintextBytes.length, plaintextBuffer.limit());
    assertEquals(plaintextBuffer.limit(), plaintextBuffer.position());
    assertEquals(sharedByteArray.length, ciphertextBuffer.position());

    plaintextBuffer.flip();

    final byte[] decryptedPlaintextBytes = new byte[plaintextBytes.length];
    plaintextBuffer.get(decryptedPlaintextBytes);

    assertArrayEquals(plaintextBytes, decryptedPlaintextBytes);
  }

  @Test
  void decryptShortArray() {
    final Key key = generateKey();
    final long nonce = ThreadLocalRandom.current().nextLong();

    assertThrows(IllegalArgumentException.class, () -> getNoiseCipher().decrypt(key, nonce, null, new byte[12]));
  }
}
