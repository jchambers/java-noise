package com.eatthepath.noise.component;

import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

abstract class AbstractNoiseKeyAgreementTest {

  protected abstract NoiseKeyAgreement getKeyAgreement() throws NoSuchAlgorithmException;

  @Test
  void getName() throws NoSuchAlgorithmException {
    assertNotNull(getKeyAgreement().getName());
  }

  @Test
  void generateSecret() throws NoSuchAlgorithmException, InvalidKeyException {
    final NoiseKeyAgreement keyAgreement = getKeyAgreement();

    final KeyPair aliceKeyPair = keyAgreement.generateKeyPair();
    final KeyPair bobKeyPair = keyAgreement.generateKeyPair();

    assertArrayEquals(
        keyAgreement.generateSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic()),
        keyAgreement.generateSecret(bobKeyPair.getPrivate(), aliceKeyPair.getPublic()));

    assertEquals(keyAgreement.getPublicKeyLength(),
        keyAgreement.generateSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic()).length);
  }

  @Test
  void serializeDeserializePublicKey() throws NoSuchAlgorithmException {
    final NoiseKeyAgreement keyAgreement = getKeyAgreement();

    final PublicKey originalPublicKey = keyAgreement.generateKeyPair().getPublic();
    final PublicKey deserializedPublicKey =
        keyAgreement.deserializePublicKey(keyAgreement.serializePublicKey(originalPublicKey));

    assertEquals(originalPublicKey, deserializedPublicKey);
  }

  @Test
  void checkPublicKey() {
    assertDoesNotThrow(() -> getKeyAgreement().checkPublicKey(getKeyAgreement().generateKeyPair().getPublic()));
  }

  @Test
  void checkKeyPair() {
    assertDoesNotThrow(() -> getKeyAgreement().checkKeyPair(getKeyAgreement().generateKeyPair()));
  }
}
