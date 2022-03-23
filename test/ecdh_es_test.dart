import 'dart:convert';

import 'package:jose/jose.dart';
import 'package:test/test.dart';

void main() {
  const teststring =
      'You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.';
  var jwk = JsonWebKey.fromJson(jsonDecode('''{
    "kty": "EC",
        "kid": "meriadoc.brandybuck@buckland.example",
        "use": "enc",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
    }'''));
  test('Read JWE using ECDH-ES and A128-CBC-HS256', () async {
    var jwks = JsonWebKeyStore()..addKey(jwk);
    var jwe = JsonWebEncryption.fromCompactSerialization(
        'eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidWNrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZFlvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ..yc9N8v5sYyv3iGQT926IUg.BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_evAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ6195_JGG2m9Csg.WCCkNa-x4BeB9hIDIfFuhg');
    var payload = await jwe.getPayload(jwks);
    assert(payload.stringContent.compareTo(teststring) == 0);
  });

  test('Encrypt and decrypt JWE using ECDH-ES and A256GCM', () async {
    var jweb = JsonWebEncryptionBuilder();
    jweb.stringContent = teststring;
    jweb.addRecipient(jwk, algorithm: 'ECDH-ES');
    jweb.generateEphemeral('P-256');
    jweb.encryptionAlgorithm = 'A256GCM';

    var jwe = jweb.build();
    var jwes = jwe.toCompactSerialization();
    var jwe2 = JsonWebEncryption.fromCompactSerialization(jwes);
    var s =
        (await jwe2.getPayload(JsonWebKeyStore()..addKey(jwk))).stringContent;
    assert(s.compareTo(teststring) == 0);
  });
}
