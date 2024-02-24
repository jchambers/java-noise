package com.eatthepath.noise.component;

import com.eatthepath.noise.crypto.Blake2s256MessageDigest;
import com.eatthepath.noise.crypto.HmacBlake2s256Mac;

import javax.crypto.Mac;
import java.security.MessageDigest;

class Blake2sNoiseHash implements NoiseHash {

  private final Blake2s256MessageDigest messageDigest;
  private final HmacBlake2s256Mac hmac;

  public Blake2sNoiseHash() {
    this.messageDigest = new Blake2s256MessageDigest();
    this.hmac = new HmacBlake2s256Mac();
  }

  @Override
  public String getName() {
    return "BLAKE2s";
  }

  @Override
  public MessageDigest getMessageDigest() {
    return messageDigest;
  }

  @Override
  public Mac getHmac() {
    return hmac;
  }

  @Override
  public int getHashLength() {
    return 32;
  }
}
