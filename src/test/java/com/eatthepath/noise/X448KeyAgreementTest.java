package com.eatthepath.noise;

import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class X448KeyAgreementTest extends AbstractXECKeyAgreementTest {

  @Override
  protected AbstractXECKeyAgreement getKeyAgreement() throws NoSuchAlgorithmException {
    return new X448KeyAgreement();
  }

  @Test
  void getPublicKeyLength() throws NoSuchAlgorithmException {
    assertEquals(448 / 8, getKeyAgreement().getPublicKeyLength());
  }
}