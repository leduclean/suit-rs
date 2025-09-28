<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## B.1. Example 0: Secure Boot
https://tools.ietf.org/html/draft-ietf-suit-manifest-27#appendix-B.1

{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'6658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -9 / ESP256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'8679a7bde316a9c8a7dd701f3f153f011368749fce6c12e4e2c9f704d3bd104fb77559d2d9723ac9ce550dc69e7bf8cc3a1a460dc6f2b851780bd23cf6669c29'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 0,
    / common / 3: << {
      / components / 2: [
        [h'00']
      ],
      / shared-sequence / 4: << [
        / directive-override-parameters / 20, {
          / vendor-id / 1: h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
          / class-id / 2: h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
          / image-digest / 3: << [
            / algorithm-id: / -16 / SHA-256 /,
            / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
          ] >>,
          / image-size / 14: 34768
        },
        / condition-vendor-identifier / 1, 15,
        / condition-class-identifier / 2, 15
      ] >>
    } >>,
    / validate / 7: << [
      / condition-image-match / 3, 15
    ] >>,
    / invoke / 9: << [
      / directive-invoke / 23, 2
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
d86ba2025873825824822f58206658ea560262696dd1f13b782239a064da
7c6c5cbaf52fded428a6fc83c7e5af584ad28443a10128a0f658408679a7
bde316a9c8a7dd701f3f153f011368749fce6c12e4e2c9f704d3bd104fb7
7559d2d9723ac9ce550dc69e7bf8cc3a1a460dc6f2b851780bd23cf6669c
29035871a50101020003585fa202818141000458568614a40150fa6b4a53
d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45
035824822f582000112233445566778899aabbccddeeff0123456789abcd
effedcba98765432100e1987d0010f020f074382030f0943821702
~~~~