import com.eatthepath.noise.NoiseHandshake;
import com.eatthepath.noise.NoiseHandshakeBuilder;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

@SuppressWarnings("NewClassNamingConvention")
public class NoiseHandshakeBuilderExample {

  @Test
  void buildIKHandshake() throws NoSuchAlgorithmException {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
    final KeyPair initiatorLocalStaticKeyPair = keyPairGenerator.generateKeyPair();
    final KeyPair responderLocalStaticKeyPair = keyPairGenerator.generateKeyPair();
    final PublicKey initiatorRemoteStaticPublicKey = responderLocalStaticKeyPair.getPublic();

    // @start region="ik-handshake-protocol-name"
    final NoiseHandshake ikInitiatorHandshake =
        NoiseHandshakeBuilder.forIKInitiator(initiatorLocalStaticKeyPair, initiatorRemoteStaticPublicKey)
            .setComponentsFromProtocolName("Noise_IK_25519_ChaChaPoly_SHA256")
            .build();
    // @end

    // @start region="ik-handshake-component-names"
    final NoiseHandshake ikResponderHandshake =
        NoiseHandshakeBuilder.forIKResponder(responderLocalStaticKeyPair)
            .setKeyAgreement("25519")
            .setCipher("ChaChaPoly")
            .setHash("SHA256")
            .build();
    // @end
  }
}
