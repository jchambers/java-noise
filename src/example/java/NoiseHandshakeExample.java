import com.eatthepath.noise.*;
import com.eatthepath.noise.component.NoiseKeyAgreement;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("NewClassNamingConvention")
public class NoiseHandshakeExample {

  @SuppressWarnings("unused")
  @Test
  void bidirectionalExample() throws InvalidKeySpecException, AEADBadTagException, NoSuchAlgorithmException {
    // @start region="bidirectional-handshake"
    final NoiseHandshake initiatorHandshake = NoiseHandshakeBuilder.forNNInitiator()
        .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
        .build();

    final NoiseHandshake responderHandshake = NoiseHandshakeBuilder.forNNResponder()
        .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
        .build();

    // -> e (with an empty payload)
    final byte[] initiatorEMessage = initiatorHandshake.writeMessage(null);
    responderHandshake.readMessage(initiatorEMessage);

    // <- e, ee (with an empty payload)
    final byte[] responderEEeMessage = responderHandshake.writeMessage(null);
    initiatorHandshake.readMessage(responderEEeMessage);

    assert initiatorHandshake.isDone();
    assert responderHandshake.isDone();

    final NoiseTransport initiatorTransport = initiatorHandshake.toTransport();
    final NoiseTransport responderTransport = responderHandshake.toTransport();
    // @end
  }

  @SuppressWarnings("unused")
  @Test
  void oneWayExample() throws NoSuchAlgorithmException, InvalidKeySpecException, AEADBadTagException {
    final NoiseKeyAgreement keyAgreement = NoiseKeyAgreement.getInstance("25519");

    final KeyPair responderStaticKeyPair = keyAgreement.generateKeyPair();
    final PublicKey responderStaticPublicKey = responderStaticKeyPair.getPublic();

    // @start region="one-way-handshake"
    final NoiseHandshake initiatorHandshake = NoiseHandshakeBuilder.forNInitiator(responderStaticPublicKey)
        .setComponentsFromProtocolName("Noise_N_25519_AESGCM_SHA256")
        .build();

    final NoiseHandshake responderHandshake = NoiseHandshakeBuilder.forNResponder(responderStaticKeyPair)
        .setComponentsFromProtocolName("Noise_N_25519_AESGCM_SHA256")
        .build();

    // -> e, es (with an empty payload)
    final byte[] initiatorEphemeralKeyMessage = initiatorHandshake.writeMessage(null);
    responderHandshake.readMessage(initiatorEphemeralKeyMessage);

    assert initiatorHandshake.isDone();
    assert responderHandshake.isDone();

    final NoiseTransportWriter transportWriter = initiatorHandshake.toTransportWriter();
    final NoiseTransportReader transportReader = responderHandshake.toTransportReader();
    // @end
  }

  @Test
  void fallbackExample() throws NoSuchAlgorithmException, InvalidKeySpecException, AEADBadTagException, NoSuchPatternException {
    final NoiseKeyAgreement keyAgreement = NoiseKeyAgreement.getInstance("25519");

    final KeyPair initiatorStaticKeyPair = keyAgreement.generateKeyPair();
    final PublicKey staleRemoteStaticPublicKey = keyAgreement.generateKeyPair().getPublic();
    final KeyPair currentResponderStaticKeyPair = keyAgreement.generateKeyPair();

    // @start region="build-ik-handshake"
    final NoiseHandshake ikInitiatorHandshake =
        NoiseHandshakeBuilder.forIKInitiator(initiatorStaticKeyPair, staleRemoteStaticPublicKey)
            .setComponentsFromProtocolName("Noise_IK_25519_AESGCM_SHA256")
            .build();

    final NoiseHandshake ikResponderHandshake =
        NoiseHandshakeBuilder.forIKResponder(currentResponderStaticKeyPair)
            .setComponentsFromProtocolName("Noise_IK_25519_AESGCM_SHA256")
            .build();
    // @end

    assertThrows(AEADBadTagException.class, () -> {
      // @start region="send-initiator-static-key-message"
      // -> e, es, s, ss (with an empty payload)
      final byte[] initiatorStaticKeyMessage = ikInitiatorHandshake.writeMessage(null);

      // Throws an AEADBadTagException because the initiator has a stale static key for the responder
      ikResponderHandshake.readMessage(initiatorStaticKeyMessage);
      // @end
    });

    // @start region="responder-fallback"
    final NoiseHandshake xxFallbackResponderHandshake =
        ikResponderHandshake.fallbackTo("XXfallback");

    // <- e, ee, s, es (with an empty payload)
    final byte[] responderStaticKeyMessage = xxFallbackResponderHandshake.writeMessage(null);
    // @end

    assertThrows(AEADBadTagException.class, () -> {
      // @start region="initiator-read-fallback-message"
      // Throws an AEADBadTagException
      ikInitiatorHandshake.readMessage(responderStaticKeyMessage);
      // @end
    });

    // @start region="initiator-fallback"
    final NoiseHandshake xxFallbackInitiatorHandshake =
        ikInitiatorHandshake.fallbackTo("XXfallback");

    xxFallbackInitiatorHandshake.readMessage(responderStaticKeyMessage);

    final byte[] initiatorFallbackStaticKeyMessage =
        xxFallbackInitiatorHandshake.writeMessage(null);

    xxFallbackResponderHandshake.readMessage(initiatorFallbackStaticKeyMessage);

    assert xxFallbackInitiatorHandshake.isDone();
    assert xxFallbackResponderHandshake.isDone();
    // @end
  }
}
