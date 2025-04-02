package com.eatthepath.noise.component;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.HexFormat;

class X25519KeyAgreement extends AbstractXECKeyAgreement {

  private static final String ALGORITHM = "X25519";

  public X25519KeyAgreement() throws NoSuchAlgorithmException {
    super(KeyAgreement.getInstance(ALGORITHM), KeyPairGenerator.getInstance(ALGORITHM), KeyFactory.getInstance(ALGORITHM));
  }

  @Override
  public String getName() {
    return "25519";
  }

  @Override
  public int getPublicKeyLength() {
    return 32;
  }

  @Override
  protected byte[] getX509Prefix() {
    return XECUtil.X25519_X509_PREFIX;
  }
}
