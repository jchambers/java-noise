package com.eatthepath.noise;

import com.eatthepath.noise.component.*;

import javax.annotation.Nullable;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;

public class NamedProtocolHandshakeBuilder {

  private final HandshakePattern handshakePattern;
  private final NoiseKeyAgreement keyAgreement;
  private final NoiseCipher cipher;
  private final NoiseHash hash;

  private final NoiseHandshake.Role role;

  @Nullable private KeyPair localEphemeralKeyPair;
  @Nullable private KeyPair localStaticKeyPair;
  @Nullable private PublicKey remoteEphemeralPublicKey;
  @Nullable private PublicKey remoteStaticPublicKey;
  @Nullable private List<byte[]> preSharedKeys;

  @Nullable private byte[] prologue;

  public NamedProtocolHandshakeBuilder(final String noiseProtocolName, final NoiseHandshake.Role role) throws NoSuchAlgorithmException, NoSuchPatternException {
    this(noiseProtocolName, role, new DefaultProtocolNameResolver());
  }

  public NamedProtocolHandshakeBuilder(final String noiseProtocolName, final NoiseHandshake.Role role, final ProtocolNameResolver protocolNameResolver) throws NoSuchAlgorithmException, NoSuchPatternException {
    final String[] components = noiseProtocolName.split("_");

    if (components.length != 5) {
      throw new IllegalArgumentException("Invalid Noise protocol name; did not contain five sections");
    }

    if (!"Noise".equals(components[0])) {
      throw new IllegalArgumentException("Noise protocol names must begin with \"Noise_\"");
    }

    this.handshakePattern = HandshakePattern.getInstance(components[1]);
    this.keyAgreement = protocolNameResolver.getKeyAgreement(components[2]);
    this.cipher = protocolNameResolver.getCipher(components[3]);
    this.hash = protocolNameResolver.getHash(components[4]);

    this.role = role;
  }

  public NamedProtocolHandshakeBuilder setPrologue(@Nullable final byte[] prologue) {
    this.prologue = prologue;
    return this;
  }

  public NamedProtocolHandshakeBuilder setLocalEphemeralKeyPair(@Nullable final KeyPair localEphemeralKeyPair) {
    this.localEphemeralKeyPair = localEphemeralKeyPair;
    return this;
  }

  public NamedProtocolHandshakeBuilder setLocalStaticKeyPair(@Nullable final KeyPair localStaticKeyPair) {
    if (!handshakePattern.requiresLocalStaticKeyPair(role)) {
      throw new IllegalStateException(handshakePattern.name() + " handshake pattern does not allow local static keys for " + role + " role");
    }

    this.localStaticKeyPair = localStaticKeyPair;
    return this;
  }

  public NamedProtocolHandshakeBuilder setRemoteEphemeralPublicKey(@Nullable final PublicKey remoteEphemeralPublicKey) {
    this.remoteEphemeralPublicKey = remoteEphemeralPublicKey;
    return this;
  }

  public NamedProtocolHandshakeBuilder setRemoteStaticPublicKey(@Nullable final PublicKey remoteStaticPublicKey) {
    if (!handshakePattern.requiresRemoteStaticPublicKey(role)) {
      throw new IllegalStateException(handshakePattern.name() + " handshake pattern does not allow remote static key for " + role + " role");
    }

    this.remoteStaticPublicKey = remoteStaticPublicKey;
    return this;
  }

  public NamedProtocolHandshakeBuilder setPreSharedKeys(final List<byte[]> preSharedKeys) {
    final int requiredPreSharedKeys = handshakePattern.getRequiredPreSharedKeyCount();

    if (requiredPreSharedKeys == 0) {
      throw new IllegalStateException(handshakePattern.name() + " handshake pattern does not allow pre-shared keys");
    }

    if (preSharedKeys.size() != requiredPreSharedKeys) {
      throw new IllegalArgumentException(handshakePattern.name() + " requires exactly " + requiredPreSharedKeys + " pre-shared keys");
    }

    if (preSharedKeys.stream().anyMatch(preSharedKey -> preSharedKey.length != 32)) {
      throw new IllegalArgumentException("Pre-shared keys must be exactly 32 bytes");
    }

    this.preSharedKeys = preSharedKeys;
    return this;
  }

  public NoiseHandshake build() {
    if (handshakePattern.requiresRemoteStaticPublicKey(role) && remoteStaticPublicKey == null) {
      throw new IllegalStateException(handshakePattern.name() + " handshake pattern requires a remote static public key for the " + role + " role");
    }

    if (handshakePattern.requiresLocalStaticKeyPair(role) && localStaticKeyPair == null) {
      throw new IllegalStateException(handshakePattern.name() + " handshake pattern requires a local static key pair for the " + role + " role");
    }

    // TODO Check key compatibility if applicable

    return new NoiseHandshake(role, handshakePattern,
        keyAgreement, cipher,
        hash,
        prologue,
        localStaticKeyPair,
        localEphemeralKeyPair,
        remoteStaticPublicKey,
        remoteEphemeralPublicKey,
        preSharedKeys);
  }
}
