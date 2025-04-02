package com.eatthepath.noise.component;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.HexFormat;

class X448KeyAgreement extends AbstractXECKeyAgreement {

  private static final String ALGORITHM = "X448";

  public X448KeyAgreement() throws NoSuchAlgorithmException {
    super(KeyAgreement.getInstance(ALGORITHM), KeyPairGenerator.getInstance(ALGORITHM), KeyFactory.getInstance(ALGORITHM));
  }

  @Override
  public String getName() {
    return "448";
  }

  @Override
  public int getPublicKeyLength() {
    return 56;
  }

  @Override
  protected byte[] getX509Prefix() {
    return XECUtil.X448_X509_PREFIX;
  }
}
