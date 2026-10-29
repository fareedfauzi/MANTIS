import "hash"

rule Win32_Ransomware_Maui_Hashes {
    meta:
        description = "Detects Maui ransomware samples based on MD5, SHA1, and SHA256 file hash indicators investigated by msudosos."
        author = "Serhii Kocherhan"
        date = "2026-09-18"
        yarahub_twitter = "@skocherhan"
        yarahub_uuid = "a55480c4-6c79-4187-a93c-4601697ed3e1"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "4d6ecc87bd6314c443dfeb35867c1fae"

    condition:
        // Validate MD5 Hashes
        hash.md5(0, filesize) == "02192bb033061b5de70ccb189e6b4ba4" or
        hash.md5(0, filesize) == "e3a4122d2d472d877e5b63503e4bbd43" or
        hash.md5(0, filesize) == "4d6ecc87bd6314c443dfeb35867c1fae" or

        // Validate SHA1 Hashes
        hash.sha1(0, filesize) == "0b405f5ec22ab9188630302ab37ea33a3e6edbd9" or
        hash.sha1(0, filesize) == "1b01a2dbc1310588f28935f3b28a5258402cea97" or
        hash.sha1(0, filesize) == "ef34ab61479a094fc471f35e4fbbc6a70823e548" or

        // Validate SHA256 Hashes
        hash.sha256(0, filesize) == "57e7ec6ff703cabc74b13ff33e73dc8acb54742866628982bcb451a5ae3dd0cb" or
        hash.sha256(0, filesize) == "908b53ab6ed3eef2fc8b8b2b98c93363eb877a344ef2c50fb362a15333dcec88" or
        hash.sha256(0, filesize) == "f7595a2fb876a70f02d0e0b55417d8f5b3a64adf3462899bcc63c09fbb06ee57" or
        hash.sha256(0, filesize) == "05b9e0371cb90c7f5fd0ed5739eafbb68cb71d945a3ff206a38d476665364935" or
        hash.sha256(0, filesize) == "10e6bb9cc4c2c9e7442f95eb76fa7681a331a27c9438e8533e96199cbd9c1a6e" or
        hash.sha256(0, filesize) == "223ad4a45971b8f111b04e95a8c7d1fc0e6de05379676bd221c94021d1b8bd4b" or
        hash.sha256(0, filesize) == "226d2338f10136793f5880b5ec2e1cc4eb3ac801dd68bfd8ad246e8c7fc6d85f" or
        hash.sha256(0, filesize) == "24c56b9934feaa2f223d05ff18844e78634395e6b332d521232c53487403672d" or
        hash.sha256(0, filesize) == "254020e7b6d9e6862edcbaee17a80ac5f9cb33e91960ac7b3c26b5ccd079abfb" or
        hash.sha256(0, filesize) == "276b4606bd67a0af078d0ddf47e8b4a2afd18f25020b5d751fa8c6237aab5e7a" or
        hash.sha256(0, filesize) == "30061ad891bdead6419d6f8eab23eda2d69c7a448f038ee1fb375da0eac5f383" or
        hash.sha256(0, filesize) == "3127f3a07e5547e8a9531e0b3bbb1e7341dc217c9e5bc994e5197ba920f50047" or
        hash.sha256(0, filesize) == "3195ef82ec2ae97d288e02b429c3d6f9179b4b6913a88e1f7cc9c003c0661865" or
        hash.sha256(0, filesize) == "31cd2226bcc68038f7c970aaea6ebb4bf4af89036a6a46e2f75efc3d97c064b9" or
        hash.sha256(0, filesize) == "3728f4b08e0e742ac6d18f6f2abf0826626b48479e338109f6800abf5c926941" or
        hash.sha256(0, filesize) == "374151a11189403af573d8e11ceb2d6fe375cceac27361a8648a93de71a6e171" or
        hash.sha256(0, filesize) == "3f361569248278bee2d5cbc64970e30297e1b6e894d91cfdd8edece4b004c599" or
        hash.sha256(0, filesize) == "4987ba0e53790afe38b131c52306d190da14fb65b2717190fb5c54b73881e341" or
        hash.sha256(0, filesize) == "4b200318803b9260e381c815a83b95e005ac8d88cf937275620d7bd10ccdd9e6" or
        hash.sha256(0, filesize) == "4c5cbb46b7252657e9a8e34aa8e8adb015c7796589e14d868aeca8e0a4e25732" or
        hash.sha256(0, filesize) == "4e353462a0b046db62481719b2c7c622e71f2b40bca21e33dd823d7a8cfcfae5" or
        hash.sha256(0, filesize) == "4e85d85b17962c2563c755fca4bb81c42b0567c62fb88cafc134bf1a67d38cb2" or
        hash.sha256(0, filesize) == "4f37a09c5dd92e4d9fdaec72130fdec11608767fc8044e85ec2b21161f8ed366" or
        hash.sha256(0, filesize) == "4f5d75b92ed25f7ccbb541d90195711d7f00bcecbc0ddb97b160ef51306e0531" or
        hash.sha256(0, filesize) == "511fb5843c67f0055dc950b78fef9cc4edfe1a032f528bfa11b0c73090d638ca" or
        hash.sha256(0, filesize) == "553167ef1f68e274f6a5c85c51ae39916dfe316b022cf50007a3bdc1ef7184c0" or
        hash.sha256(0, filesize) == "59fef8134f5ab9b81bc185c14f8994039e036dce4e44eb16906a83467286e8dd" or
        hash.sha256(0, filesize) == "5d2c80eb85d112df4123639e1a4271d94aacf4fd735a74840d24a67fb3c67017" or
        hash.sha256(0, filesize) == "5e50cebe9a6de8fff7d9530cf50c1483676c1d70b5fbf863560a6b4785a500e3" or
        hash.sha256(0, filesize) == "6b245cf834d13c27ebd81cca12ac23b093aef1081e4729b4e205e1e9e794069c" or
        hash.sha256(0, filesize) == "6d58b29bf1fd23d09ce53d50892aef7c150b634496a98f449997844d94d52fa1" or
        hash.sha256(0, filesize) == "6dbefec2e46ec3ca1ff040ff1394b4455542bc197ee1c57c66f393f46c423859" or
        hash.sha256(0, filesize) == "7010ff1a3b4c62a413cdcdaf2218278c564cc7e9f0fd15806acf77eb8dfa29ec" or
        hash.sha256(0, filesize) == "73d9a38d9cf6cab2462725a79de1f65ab08c3e9a06a126b22e09243e61d94c1e" or
        hash.sha256(0, filesize) == "7723d47c94fcfeb2dd96c94110b9bb9d5ae28daf060da38a308310056e091149" or
        hash.sha256(0, filesize) == "7f400acca510c93d59b90ea9cc62b24c8a9369b5eed071fea470bbcd5098c47d" or
        hash.sha256(0, filesize) == "85470c94156dbaf0226958ddd17be5d66ab5434834c4d765c0f94321dc7f08e1" or
        hash.sha256(0, filesize) == "85b99dcbbc15e4f45f92727003d703d35686990b8c53c24b90e9c945b3f98472" or
        hash.sha256(0, filesize) == "87d2a64e46d60ed94098e19178e511b2034342fabe1c62b4e5e06670a0036dc2" or
        hash.sha256(0, filesize) == "89aa0eda96858b8d4d5bfe81ea1a70363b1dc2217804841b8032faf74390f069" or
        hash.sha256(0, filesize) == "8d3a6b769e9a0831496d4af1258cff38d03317e57321826ef86d9c51167d6640" or
        hash.sha256(0, filesize) == "8f8c021b9a0474b5a478781a0b72a1f8a14927150b96f38cfc4375e1c3ccfe48" or
        hash.sha256(0, filesize) == "940d1cddc4b34f7860a65935464b2d4bc0241926d01d16dfe5ab392058208dde" or
        hash.sha256(0, filesize) == "959e0d1c4135858b11c7da51b30c0ab503569386e14620b67e0de3fe75107e59" or
        hash.sha256(0, filesize) == "98a574a09840463d78bbd2d475e4570d289d795e028358084a31e320d6a8afab" or
        hash.sha256(0, filesize) == "b54aa056e3bb4e46e9a0f219098ea53963c1f1c902b2bf685a969dbec3c381b5" or
        hash.sha256(0, filesize) == "b71fbf14645e6d5c99775a0a52b71ac2918408ca38cf9a5bc15a6b52034293bc" or
        hash.sha256(0, filesize) == "bc5fd008bdc0da6344ca09de402a294301a6c96b2d4e6c1c93e73dfa128f0dbe" or
        hash.sha256(0, filesize) == "c91eaa66286fb62d3efcb7c62b23dde42a6ba9d1fa6a5d762e90ffdb3472c7ff" or
        hash.sha256(0, filesize) == "cee4aa1bc6f20a31b1b8418834ad77fc179eaec69232ae1370135efdd0a6b6bb" or
        hash.sha256(0, filesize) == "cf77eaef778da2602cd42c62fc47d390ccd9cf00c2ad56679753464bb3ed4dab" or
        hash.sha256(0, filesize) == "d13a45009cd008b64ab47def340878947c7669caf8bbcca7f5cdab06535e100c" or
        hash.sha256(0, filesize) == "d166c01d6676bc3dac2ea03c75218bfd87c2e398f0351438a620a74d3eeeb435" or
        hash.sha256(0, filesize) == "d567a4892c4eeb8a3025e86568fc9ac17d8654eb0443d2f9375a5b165a562058" or
        hash.sha256(0, filesize) == "d72ca2c3a1b9bb6a0dd9282e3be73dcfb02258c720c317a8df2faa506d1f57d8" or
        hash.sha256(0, filesize) == "d74949339892593e97dfe3412523db98bd2bfbebfcc7ea04f5a7c04f0592be0f" or
        hash.sha256(0, filesize) == "d7e24932874c6f12b7f689b97fd31d4cad4ca2e36b761d43e8378f10c8207b0d" or
        hash.sha256(0, filesize) == "d8dceba6b02d03d08a4c0c18a8cc7cf0a193e392a20a27f370bbb1c0611f0eb4" or
        hash.sha256(0, filesize) == "dd30d845b68251689c75d8d5ac2267b6851d2ee95de60367a9a7f14e75ac496f" or
        hash.sha256(0, filesize) == "e23c534c924c13548914b365ec5579384030c0d5f07c6f2bc8b190511139f448" or
        hash.sha256(0, filesize) == "e80599012f32a2e7a57ea97f3f45c1b25d67559d406a4d2d12075748242f5a36" or
        hash.sha256(0, filesize) == "e9805bb66a3b44780cf25653f189e3ada4b77f10918c9675a2b501de3cf7ad5d" or
        hash.sha256(0, filesize) == "eb2df339934e4eaec9a45b7c5644fd108829732af2f9edb5f0b4b71644ca6267" or
        hash.sha256(0, filesize) == "f1ddc370b692d349f8611b8798a22aecf8e984617b7da66051bd0e78179299c6" or
        hash.sha256(0, filesize) == "f34bc90aa03e0447d86d504534d35b8e08e761cfc6ef3cc2bae1014d835ab6b1" or
        hash.sha256(0, filesize) == "f7ebfd397abfc645e70ac1d7964f7c6a75341c3a0fdfcfcaef3a4b57503cfd66" or
        hash.sha256(0, filesize) == "f8ef11dca01909068af91fc3f8eaf5cabc0f6714631c1a59df12bebd05ebc175" or
        hash.sha256(0, filesize) == "fc8937d1d60ea1e75f2d9eb08c05449e79e0d008d1cda2e2eaf68b4acb9cac93" or
        hash.sha256(0, filesize) == "fda4ba97c6bc0101f3e420ac1a6f90ca5e9ea56e22ff8e971abaad758540cb52" or
        hash.sha256(0, filesize) == "0482016c016a007600c2317e574519a345ee7f38deb29041ebc7c2215a22bf7f"
}