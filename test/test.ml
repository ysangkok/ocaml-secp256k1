open Libsecp256k1

module Num = struct
  open Internal
  open Num
  let basic () =
    let z = zero () in
    Alcotest.(check bool "Num.is_zero" true (is_zero z))

  let runtest =
    [ "basic", `Quick, basic ;
    ]
end

module Scalar = struct
  open Internal
  open Scalar
  let basic () =
    let z = zero () in
    Alcotest.(check bool "Scalar.is_zero" true (is_zero z)) ;
    (* set_int z 1 ; *)
    let z = const ~d0:1L () in
    Alcotest.(check bool "Scalar.is_zero" false (is_zero z)) ;
    Alcotest.(check bool "Scalar.is_even" false (is_even z)) ;
    Alcotest.(check bool "Scalar.is_one" true (is_one z))

  let runtest =
    [ "basic", `Quick, basic ;
    ]
end

module External = struct
  open External
  let buffer_of_hex s =
    Cstruct.to_bigarray (Hex.to_cstruct (`Hex s))

  let ctx = Context.create ()

  let cstruct_testable =
    Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

  let assert_eq_cstruct a b =
    let a = Cstruct.of_bigarray a in
    let b = Cstruct.of_bigarray b in
    assert (Alcotest.equal cstruct_testable a b)

  let test_schnorr_1_seckey_1 () =
    (*let sk = Key.read_sk_exn ctx (buffer_of_hex "0000000000000000000000000000000000000000000000000000000000000001") in*)
    let pk = Key.read_pk_exn ctx (buffer_of_hex "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798") in
    let msg = buffer_of_hex "0000000000000000000000000000000000000000000000000000000000000000" in
    let signature = Sign.read_schnorr_exn ctx (buffer_of_hex "787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05") in
    assert (Sign.verify_schnorr_exn ctx ~pk ~msg ~signature)

  let test_schnorr_2_valid () =
    let sk = Key.read_sk_exn ctx (buffer_of_hex "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF") in
    (*let pk = Key.read_pk_exn ctx (buffer_of_hex "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659") in*)
    let msg = buffer_of_hex "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89" in
    let signature = Sign.read_schnorr_exn ctx (buffer_of_hex "2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD") in
    let sign = Sign.sign_schnorr_exn ctx ~sk msg in
    assert (Sign.equal sign signature)

  let test_schnorr_7_pubkey_not_on_curve () =
    match Key.read_pk ctx (buffer_of_hex "03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34") with
    | Error _ -> ()
    | Ok _ -> assert false
    (*let msg = buffer_of_hex "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703" in
    let signature = Sign.read_schnorr_exn ctx (buffer_of_hex "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D") in
    assert (not (Sign.verify_schnorr_exn ctx ~signature ~pk ~msg))*)

  let test_signature_of_string () =
    let sign_orig = buffer_of_hex
        "3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589" in
    let signature = Sign.read_der_exn ctx sign_orig in
    let sign = Sign.to_bytes ~der:true ctx signature in
    assert_eq_cstruct sign_orig sign

  let test_valid_signature _ =
    let msg = buffer_of_hex
        "CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90" in
    let signature = Sign.read_der_exn ctx
        (buffer_of_hex "3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589") in
    let pk = Key.read_pk_exn ctx
        (buffer_of_hex "040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40") in
    assert (Sign.verify_exn ctx ~signature ~pk ~msg)

  let test_invalid_signature _  =
    let msg = buffer_of_hex
        "CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A91" in
    let signature = Sign.read_der_exn ctx
        (buffer_of_hex "3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589") in
    let pk = Key.read_pk_exn ctx
        (buffer_of_hex "040a629506e1b65cd9d2e0ba9c75df9c4fed0db16dc9625ed14397f0afc836fae595dc53f8b0efe61e703075bd9b143bac75ec0e19f82a2208caeb32be53414c40") in
    assert (not (Sign.verify_exn ctx ~signature ~pk ~msg))

  let test_public_module _ =
    let pubtrue =
      buffer_of_hex "04c591a8ff19ac9c4e4e5793673b83123437e975285e7b442f4ee2654dffca5e2d2103ed494718c697ac9aebcfd19612e224db46661011863ed2fc54e71861e2a6" in
    let pub = Key.read_pk_exn ctx pubtrue in
    let pub_serialized = Key.to_bytes ~compress:false ctx pub in
    assert_eq_cstruct pubtrue pub_serialized

  let test_pubkey_creation _ =
    let seckey = buffer_of_hex "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530" in
    let pubtrue = buffer_of_hex "04c591a8ff19ac9c4e4e5793673b83123437e975285e7b442f4ee2654dffca5e2d2103ed494718c697ac9aebcfd19612e224db46661011863ed2fc54e71861e2a6" in
    let seckey = Key.read_sk_exn ctx seckey in
    let pubkey = Key.neuterize_exn ctx seckey in
    let buf_pk_comp = Cstruct.create 33 in
    let buf_pk_uncomp = Cstruct.create 65 in
    let nb_written = Key.write ~compress:true ctx buf_pk_comp.buffer pubkey in
    assert (nb_written = 33) ;
    let nb_written = Key.write ~compress:false ctx buf_pk_uncomp.buffer pubkey in
    assert (nb_written = 65) ;
    let nb_written = Key.write ~compress:true ctx buf_pk_uncomp.buffer ~pos:32 pubkey in
    assert (nb_written = 33) ;
    let pubkey_serialized = Key.to_bytes ~compress:false ctx pubkey in
    assert_eq_cstruct pubtrue pubkey_serialized

  let test_sign _ =
    let msg =  buffer_of_hex "CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90" in
    let sk = Key.read_sk_exn ctx (buffer_of_hex "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530") in
    let validsign = Sign.read_der_exn ctx (buffer_of_hex "30440220182a108e1448dc8f1fb467d06a0f3bb8ea0533584cb954ef8da112f1d60e39a202201c66f36da211c087f3af88b50edf4f9bdaa6cf5fd6817e74dca34db12390c6e9") in
    let sign = Sign.sign_exn ctx ~sk msg in
    assert (Sign.equal sign validsign)

  let test_recover _ =
    let msg = buffer_of_hex "CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90" in
    let seckey = Key.read_sk_exn ctx (buffer_of_hex "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530") in
    let pubkey = Key.neuterize_exn ctx seckey in
    let recoverable_sign = Sign.sign_recoverable_exn ctx ~sk:seckey msg in
    let usual_sign = Sign.to_plain ctx recoverable_sign in
    assert (Sign.verify_exn ctx ~pk:pubkey ~signature:usual_sign ~msg);
    let recoverable_bytes = Sign.to_bytes ctx recoverable_sign in
    let usual_sign' = Sign.read_exn ctx recoverable_bytes in
    assert (Sign.equal usual_sign' usual_sign) ;
    let recoverable_sign' = Sign.read_recoverable_exn ctx recoverable_bytes in
    assert (Sign.equal recoverable_sign' recoverable_sign);
    match Sign.recover ctx ~signature:recoverable_sign msg with
    | Error _ -> assert false
    | Ok recovered -> assert (Key.equal recovered pubkey)

  let runtest = [
    "schnorr_7_pubkey_not_on_curve", `Quick, test_schnorr_7_pubkey_not_on_curve ;
    "schnorr_1_seckey_1", `Quick, test_schnorr_1_seckey_1 ;
    "schnorr_2_valid", `Quick, test_schnorr_2_valid ;
    "signature_of_string", `Quick, test_signature_of_string ;
    "valid_signature", `Quick, test_valid_signature ;
    "invalid_signature", `Quick, test_invalid_signature ;
    "public_module", `Quick, test_public_module ;
    "pubkey_creation", `Quick, test_pubkey_creation ;
    "sign", `Quick, test_sign ;
    "recover", `Quick, test_recover ;
  ]
end

let () =
  Alcotest.run "secp256k1" [
    "Num", Num.runtest ;
    "Scalar", Scalar.runtest ;
    "External", External.runtest ;
  ]
