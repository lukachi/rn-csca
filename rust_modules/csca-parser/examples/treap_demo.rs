use std::fs;

use csca_parser::{
    build_cert_tree_and_gen_proof, build_cert_tree_root, parse_ldif, OwnedCertificate,
};
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Treap Tree Implementation...");

    // Read the LDIF file
    let data = fs::read("assets/icaopkd-list.ldif")?;

    // Parse LDIF and get certificates (this will be empty with mock data)
    match parse_ldif(data) {
        Ok(certificates) => {
            println!("Parsed {} certificates", certificates.len());

            if !certificates.is_empty() {
                // Build certificate tree and get root
                match build_cert_tree_root(certificates.clone()) {
                    Ok(Some(root)) => {
                        // TODO: expect root to be 790cb6af6d25c91270fd0c11409325dbb2ec297d5ba15516ab6cc0c16a0e3f88
                        println!("Certificate tree root: {}", root);

                        let target_cert = OwnedCertificate::from_der(hex::decode("3082048d30820414a003020102020136300a06082a8648ce3d0403033057310b3009060355040613024c5631243022060355040a0c1b4e6174696f6e616c20536563757269747920417574686f726974793114301206035504030c0b43534341204c6174766961310c300a06035504051303303038301e170d3230303632393133343535395a170d3333303932393133343535395a3057310b3009060355040613024c5631243022060355040a0c1b4e6174696f6e616c20536563757269747920417574686f726974793114301206035504030c0b43534341204c6174766961310c300a06035504051303303038308201b53082014d06072a8648ce3d020130820140020101303c06072a8648ce3d01010231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53306404307bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826043004a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c110461041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c53150231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e90465650201010362000465f48a6a05d2a1a7f038a0dc909d572023e42e119638e48097436185f6f46b4007ca81ce970d679e41574ad47223e7820d560be7bbda5a7081f729c0f530ec4053f849add568bbf30047515327d264abaf867b35c87d24a1f8ed3dc039138c0aa38201713082016d301f0603551d23041830168014b72748d1e35062f7f6bd5b2df43eb8ccb8601ea030120603551d130101ff040830060101ff020100300d06076781080101060104020500302b0603551d1004243022800f32303230303632393133343535395a810f32303233303632393133343535395a301d0603551d0e04160414b72748d1e35062f7f6bd5b2df43eb8ccb8601ea0302d0603551d1204263024a410300e310c300a06035504070c034c564181106e706b6440706d6c702e676f762e6c76302d0603551d1104263024a410300e310c300a06035504070c034c564181106e706b6440706d6c702e676f762e6c76306d0603551d1f046630643030a02ea02c862a68747470733a2f2f706b64646f776e6c6f6164312e6963616f2e696e742f43524c732f4c56412e63726c3030a02ea02c862a68747470733a2f2f706b64646f776e6c6f6164322e6963616f2e696e742f43524c732f4c56412e63726c300e0603551d0f0101ff040403020106300a06082a8648ce3d040303036700306402300b8c04f6d584f2d9f2bf53bda5c320aad8dc96d9046910351cbfe394e8694615871fa8974dd222c2ec36f62fc9817c290230572c76e18b380480e8aecd677e4a5e13a97eed52b0d59d384fe99201f5f00a25d723a6374ddf53e19bb064e21b1c7b7b")?)?;

                        // Generate inclusion proof for the first certificate
                        match build_cert_tree_and_gen_proof(
                            certificates.clone(),
                            target_cert.der_data().to_vec(),
                        ) {
                            Ok(proof) => {
                                println!("Inclusion proof generated with {} siblings", proof.len());
                                for (i, sibling) in proof.iter().enumerate() {
                                    println!("  Sibling {}: {}", i, sibling);
                                    // expect siblings to be:
                                    // [0]: 503d207b986e0d1bf6fb07c44b861a804e36fb8ac9e8d5489babb99c5c9c6025
                                    // [1]: f714619d1fb0e7ba3d0a49b6512096c7968f634e83b5171a72f95bb03af0855f
                                    // [2]: f54e4cec38ba6db5cbb06fade7b2df48043456a7a32da2446e2305801c1c7fea
                                    // [3]: ad728bc5c073bdf5da2986a2e94242fe92a2185969487edac8ac14f7992e15bb
                                    // [4]: f5307f266aaadb3f2541d4e1ea68703aa4ad2d99c39a6506ce756b03f35bd2b2
                                    // [5]: 764e0ced73003e3419c3ee7807b2b39b395643241596f2b40b4e152c21368375
                                    // [6]: f26977b3dfa55c4541f588a146744a55536c927c6550ce865b1e1611c04a8b54
                                    // [7]: 87f43213e7f9b6f9992229dedaa45c8495d4ffe1c17696785bed4a1d032a6456
                                    // [8]: e491cb18c10b784d7d3f92f365587e00012f44c6423ea0b20e46b830709cc4d8
                                    // [9]: 1894634e79278ccc93d901678b93d73e02f8eeffa115dd04096b51fe4dde10b6
                                    // [10]: f84c7b83b057017bcf01f6174bf5d5036e3c5d86fdcbd3fbbe0c1f16722c190c
                                    // [11]: f01bd04a52aa978379dac2fbbc311c4c170ed9289fe57ed0b69d8ddffb028a17
                                    // [12]: d0b0ad4f05454084c7adeeb122dfc9ce3145307961900eca89ba8ecfd19885e6
                                    // [13]: 6f163fbce3b8f6bd44fbff7f25d9025544cf1b6f4a9ebe00ed74468f38bdc5a5
                                    // [14]: c4e55f230de84fc3e1db995139f5526f1fe6ae449b161c108af405e77a528663
                                    // [15]: ba24ba389cc4d0896ea47cf66069c5e6f0e4a9c9010b23465dc65b9a0cc17fc5
                                    // [16]: ac52f309e1a4bc20daf2206ca76b2fd6e283f36d4d01ffc3f2e8e0686ad2344b
                                    // [17]: 57fe0cf20224b6aaa5bc317c30fab5b5c50d1fc17ef4186d0b03c50865a2f34f
                                    // [18]: 19351d9eeea3bb4c4b3a9be8d3daeb09f229f5d9d6745616c25e0dd4708d5fa4
                                    //
                                }
                            }
                            Err(e) => println!("Error generating inclusion proof: {}", e),
                        }
                    }
                    Ok(None) => println!("No certificates to build tree from"),
                    Err(e) => println!("Error building certificate tree: {}", e),
                }
            } else {
                println!("No certificates found in LDIF data");
            }
        }
        Err(e) => {
            println!("Error parsing LDIF: {}", e);
        }
    }

    println!("Demo completed successfully!");

    Ok(())
}
