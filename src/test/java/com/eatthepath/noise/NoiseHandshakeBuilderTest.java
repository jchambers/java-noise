package com.eatthepath.noise;

import com.eatthepath.noise.component.NoiseKeyAgreement;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

class NoiseHandshakeBuilderTest {

  @Test
  void setPrologue() {
    final NoiseHandshakeBuilder noiseHandshakeBuilder = NoiseHandshakeBuilder.forNNInitiator();

    assertDoesNotThrow(() -> noiseHandshakeBuilder.setPrologue("Prologue".getBytes(StandardCharsets.UTF_8)));
    assertDoesNotThrow(() -> noiseHandshakeBuilder.setPrologue(null));
  }

  @Test
  void setComponentsFromProtocolName() {
    final NoiseHandshakeBuilder noiseHandshakeBuilder = NoiseHandshakeBuilder.forNNInitiator();

    assertDoesNotThrow(() -> noiseHandshakeBuilder.setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256"));

    assertThrows(IllegalArgumentException.class,
        () -> noiseHandshakeBuilder.setComponentsFromProtocolName("Noise_XX_25519_AESGCM_SHA256"));

    assertThrows(IllegalArgumentException.class,
        () -> noiseHandshakeBuilder.setComponentsFromProtocolName("Not a real Noise protocol name"));
  }

  @Test
  void setCipher() {
    final NoiseHandshakeBuilder noiseHandshakeBuilder = NoiseHandshakeBuilder.forNNInitiator();

    assertDoesNotThrow(() -> noiseHandshakeBuilder.setCipher("AESGCM"));
    assertThrows(IllegalArgumentException.class, () -> noiseHandshakeBuilder.setCipher("Not a Noise cipher"));
    assertThrows(NullPointerException.class, () -> noiseHandshakeBuilder.setCipher(null));
  }

  @Test
  void setHash() {
    final NoiseHandshakeBuilder noiseHandshakeBuilder = NoiseHandshakeBuilder.forNNInitiator();

    assertDoesNotThrow(() -> noiseHandshakeBuilder.setHash("SHA256"));
    assertThrows(IllegalArgumentException.class, () -> noiseHandshakeBuilder.setHash("Not a Noise hash"));
    assertThrows(NullPointerException.class, () -> noiseHandshakeBuilder.setHash(null));
  }

  @Test
  void setKeyAgreement() {
    final NoiseHandshakeBuilder noiseHandshakeBuilder = NoiseHandshakeBuilder.forNNInitiator();

    assertDoesNotThrow(() -> noiseHandshakeBuilder.setHash("SHA256"));
    assertThrows(IllegalArgumentException.class, () -> noiseHandshakeBuilder.setHash("Not a Noise hash"));
    assertThrows(NullPointerException.class, () -> noiseHandshakeBuilder.setHash(null));
  }

  @Test
  void setKeys() throws NoSuchAlgorithmException {
    final NoiseKeyAgreement noiseKeyAgreement = NoiseKeyAgreement.getInstance("25519");

    final KeyPair localStaticKeyPair = noiseKeyAgreement.generateKeyPair();
    final PublicKey remoteStaticPublicKey = noiseKeyAgreement.generateKeyPair().getPublic();
    final byte[] preSharedKey = new byte[32];
    final byte[] bogusPreSharedKey = new byte[preSharedKey.length + 1];

    assertDoesNotThrow(() ->
        NoiseHandshakeBuilder.forIKPsk1Initiator(localStaticKeyPair, remoteStaticPublicKey, preSharedKey));

    assertThrows(NullPointerException.class, () ->
        NoiseHandshakeBuilder.forIKPsk1Initiator(null, remoteStaticPublicKey, preSharedKey));

    assertThrows(NullPointerException.class, () ->
        NoiseHandshakeBuilder.forIKPsk1Initiator(localStaticKeyPair, null, preSharedKey));

    assertThrows(NullPointerException.class, () ->
        NoiseHandshakeBuilder.forIKPsk1Initiator(localStaticKeyPair, remoteStaticPublicKey, null));

    assertThrows(IllegalArgumentException.class, () ->
        NoiseHandshakeBuilder.forIKPsk1Initiator(localStaticKeyPair, remoteStaticPublicKey, bogusPreSharedKey));

  }

  @Test
  void build() throws NoSuchAlgorithmException {
    final NoiseHandshakeBuilder noiseHandshakeBuilder = NoiseHandshakeBuilder.forNNInitiator();

    assertThrows(IllegalStateException.class, noiseHandshakeBuilder::build);

    noiseHandshakeBuilder.setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256");

    assertNotNull(noiseHandshakeBuilder.build());
  }
}