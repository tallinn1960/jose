import 'dart:convert';
import 'dart:io';

import 'package:jose/jose.dart';
import 'package:jose/src/jwe.dart';
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
    jweb.addRecipient(jwk);
    jweb.encryptionAlgorithm = 'A256GCM';

    var jwe = await jweb.build();
    var jwes = jwe.toCompactSerialization();
    var jwe2 = JsonWebEncryption.fromCompactSerialization(jwes);
    var s =
        (await jwe2.getPayload(JsonWebKeyStore()..addKey(jwk))).stringContent;
    assert(s.compareTo(teststring) == 0);
  });

  test('Encrypt JWE using ECDH-ES with brainpool key', () async {
    var jweb = JsonWebEncryptionBuilder();
    jweb.stringContent = teststring;
    jweb.addRecipient(JsonWebKey.fromPem(
        File('test/pem/bp_enc_key.pub.pem').readAsStringSync()));
    jweb.encryptionAlgorithm = 'A256GCM';
    var jwe = await jweb.build();
    expect(jwe.commonProtectedHeader.algorithm, 'ECDH-ES');
    var jweb2 = JsonWebEncryption.fromCompactSerialization(
        jwe.toCompactSerialization());
    var result = await jweb2.getPayload(JsonWebKeyStore()
      ..addKey(JsonWebKey.fromJson(jsonDecode(
          '{"kty":"EC","crv":"BP-256","x":"WBmQdqmB2_l97AfM1X0_rr8T0sty_q8-xXXOrPcIrkk","y":"GiP9hUuoqlHalH45aMlUVwJzWbCCeQbWNFcH6w_0qyA","d":"L8GPC5Uq-uileoE_OBZECpJ3SwbUvpkI3jz7XWBGYmY"}'))));
    expect(result.stringContent, teststring);
  });

  test('Decrypt JWE from cjose using ECDH-ES with brainpool key', () async {
    var jweb2 = JsonWebEncryption.fromCompactSerialization(
        'eyJhbGciOiAiRUNESC1FUyIsICJlbmMiOiAiQTI1NkdDTSIsICJlcGsiOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiQlAtMjU2IiwgIngiOiAiUWdqajJVYWR4Z3MyQ3lsM1FaN001cDdiM1l4alduNVRfVFpzeHlxNnZaMCIsICJ5IjogIlZFV3N5bzRfWUo2NWsyYVhQRFMwRHRqVmlfQUlTbGZYQWRzSmZNQVduUU0ifX0..ao8KeJlqGobVMCVm.ipdnJwb3V83BjTX-nZ5T7GdK5UobV31NN9BUYXlyX8p_Dvr6iM5-XqsaHhkfVAJW-ZcyB_RU4ITt7okXGdUFk46S4LiYdwdLNBGjHorDubScGCsjurh0X8T2PESpZObx_f3ZmnC4Od2mNL53-i4_eKBx1g063UzBRlAe0xaylTOPFO7A_TnCXe8xUFhUhnL4LkGwsRLH74FeSGOUICsscJuFw7w_phl3hfqm0_8apew3KbVjFx1oHhFLAZiHWsJaV4PeYYX45qm4ckDCHmJFP_MfpNzuBl7AnDLTjTlXzTWZNKcxDdP5N2XYYUPVSUX0GL4U7CtmMGaMqtpwEALBjiX6rf6033BgODzqalS81wc8.g8LnGl39FECcj7Mw_fvbJw');
    var result = await jweb2.getPayload(JsonWebKeyStore()
      ..addKey(JsonWebKey.fromJson(jsonDecode(
          '{"kty":"EC","crv":"BP-256","x":"WBmQdqmB2_l97AfM1X0_rr8T0sty_q8-xXXOrPcIrkk","y":"GiP9hUuoqlHalH45aMlUVwJzWbCCeQbWNFcH6w_0qyA","d":"L8GPC5Uq-uileoE_OBZECpJ3SwbUvpkI3jz7XWBGYmY"}'))));
    expect(result.stringContent, teststring);
  });
  test('Decrypt JWE from jose using ECDH-ES with brainpool key2', () async {
    var jweb2 = JsonWebEncryption.fromCompactSerialization(
        'eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC1FUyIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IkJQLTI1NiIsIngiOiJSajMxdjVtMU9nR1ZsYlFYWWNpU3duNlNVYXRMQ2V3YXZ0ZkJFaFVTRW00IiwieSI6IkpjMDl0LTJ3MDFvTEpTaTVvUEppTEtSZDkzS2lTVmRWOUVhdDV4RWI4cW8ifX0..M9AE68KPsWqREio7Oy_zsQ.im-mB3TGTuRvFjayXekJSYpe5otqJPhUmTT8xyAsf5JasRg31QP8Rn9CYh2C5PHGRicR9cVhtTbszePUGbhVqG0Qn8a_ctMiy7tZ5OdFKeYIgJTyJMur6N0V6u4RqBcqEKeZcIWpy3938A_LC96wuuo_knSMxTOugdhhUZzRH3OPBbiVGO_BTemStGKqhSwS-B-7Kmn4asOBQAH2OAWkHNTu-DaFMmp7sNJvUEHN9aH2uGaeGH0zoPJ50a0q88gM_qGkjKC8D812yiSEiXVeotyUhusyzhy1sNP49VEv0g8cTfsbH8yA-Z6jwBZqNi_o8Qn7LgbLZ8YUGK2dcswCKbfe7Bi4ALM_39T-HlaWEgAW.ULWqpKgu-soL_Cms48Txrw');
    var result = await jweb2.getPayload(JsonWebKeyStore()
      ..addKey(JsonWebKey.fromJson(jsonDecode(
          '{"kty":"EC","crv":"BP-256","x":"WBmQdqmB2_l97AfM1X0_rr8T0sty_q8-xXXOrPcIrkk","y":"GiP9hUuoqlHalH45aMlUVwJzWbCCeQbWNFcH6w_0qyA","d":"L8GPC5Uq-uileoE_OBZECpJ3SwbUvpkI3jz7XWBGYmY"}'))));
    expect(result.stringContent, teststring);
    base64Decode('M9AE68KPsWqREio7Oy_zsQ==').forEach((element) {
      print('$element, ');
    });
  });
}
