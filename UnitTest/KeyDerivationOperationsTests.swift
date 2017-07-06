//
//  KeyDerivationOperationsTests.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/10.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Tests for the key derivation operations.
 */

import XCTest

class KeyDerivationOperationsTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        ToolCommon.shared.debugRunOpOnMainThread = true
    }
    
    func testPBKDF2() {
        
        let passwordString = "Hello Cruel World!"
        
        let saltData = "Some salt sir?".data(using: .utf8)!
        
        // These results were generated with PHP 7.0.5 using:
        //
        // hash_pbkdf2("sha1", "Hello Cruel World!", "Some salt sir?", 1000, 10, true);
        // hash_pbkdf2("sha224", "Hello Cruel World!", "Some salt sir?", 1000, 10, true);
        // ...
        //
        // and then repeated with "" for salt.
        // and then repeated again with "" for both password and salt.
        
        // Note: This test fails on OS X 10.7.x and iOS 5.x because CCKeyDerivationPBKDF returns
        // an error if there's no salt.
        
        let kAlgorithms: [QCCPBKDF2SHAKeyDerivation.Algorithm] = [.sha1, .sha2_224, .sha2_256, .sha2_384, .sha2_512]
        let kExpected: [String] = [
            "e56c27f5eed251db50a3",
            "88597c3d039227ea2723",
            "884185449fa0f5ea91bf",
            "7c44bd93a3f5d732a667",
            "d4537676e0af5274ca01"
        ]
        
        let kExpectedNoSalt: [String] = [
            "98b4c8aec38c64c8e2de",
            "8bd95e3da6187c36d737",
            "338919ba6253c606fc02",
            "821d33494a485633ebb9",
            "80878761083c187e425c"
        ]
        let kExpectedDegenerate: [String] = [
            "6e40910ac02ec89cebb9",
            "7df7ef68f01b61a28b21",
            "4fc58a21c100ce1835b8",
            "9cbfe72d194da34e17c8",
            "cb93096c3a02beeb1c5f"
        ]
        
        for i in 0..<2 { //### <- Why this is not `0..<5`?
            
            var expectedKeyData = QHex.data(hex: kExpected[i])
            
            var op = QCCPBKDF2SHAKeyDerivation(algorithm: kAlgorithms[i], passwordString: passwordString, saltData: saltData)
            op.rounds = 1000
            op.derivedKeyLength = 10
            ToolCommon.shared.synchronouslyRun(operation: op)
            XCTAssertNil(op.error)
            XCTAssertEqual(op.derivedKeyData!, expectedKeyData)
            
            expectedKeyData = QHex.data(hex: kExpectedNoSalt[i])
            
            op = QCCPBKDF2SHAKeyDerivation(algorithm: kAlgorithms[i], passwordString: passwordString, saltData: Data())
            op.rounds = 1000
            op.derivedKeyLength = 10
            ToolCommon.shared.synchronouslyRun(operation: op)
            XCTAssertNil(op.error)
            XCTAssertEqual(op.derivedKeyData!, expectedKeyData)
            
            expectedKeyData = QHex.data(hex: kExpectedDegenerate[i])
            
            op = QCCPBKDF2SHAKeyDerivation(algorithm: kAlgorithms[i], passwordString: "", saltData: Data())
            op.rounds = 1000
            op.derivedKeyLength = 10
            ToolCommon.shared.synchronouslyRun(operation: op)
            XCTAssertNil(op.error)
            XCTAssertEqual(op.derivedKeyData!, expectedKeyData)
        }
    }
    
    func testPBKDF2Calibration() {
        
        let passwordString = "Hello Cruel World!"
        
        let saltData = "Some salt sir?".data(using: .utf8)!
        
        // First run the operation with a target time (0.5 seconds).
        
        var op = QCCPBKDF2SHAKeyDerivation(algorithm: .sha1, passwordString: passwordString, saltData: saltData)
        op.derivationTime = 0.5
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertNotNil(op.derivedKeyData)
        let derivedKey = op.derivedKeyData!
        let actualRounds = op.actualRounds
        
        // Then run it again with the rounds from the previous operation.
        // It should take (roughly) 0.5 seconds.  If it doesn't, that's a problem.
        //
        // Note we have a huge time variance here due, so we accept a large range of values.
        
        op = QCCPBKDF2SHAKeyDerivation(algorithm: .sha1, passwordString: passwordString, saltData: saltData)
        op.rounds = actualRounds
        let startTime = Date.timeIntervalSinceReferenceDate
        ToolCommon.shared.synchronouslyRun(operation: op)
        let timeTaken = Date.timeIntervalSinceReferenceDate - startTime
        XCTAssertNil(op.error)
        XCTAssertEqualWithAccuracy(timeTaken, 0.5, accuracy: 0.2) //### `0.2` seems not enough for our environment
        XCTAssertEqual(op.actualRounds, actualRounds)
        XCTAssertEqual(op.derivedKeyData!, derivedKey)
    }
    
    func testPBKDF2Error() {
        
        let passwordString = "Hello Cruel World!"
        
        let saltData = "Some salt sir?".data(using: .utf8)!
        
        // a derived key length of zero is not valid
        
        var op = QCCPBKDF2SHAKeyDerivation(algorithm: .sha1, passwordString: passwordString, saltData: saltData)
        op.derivedKeyLength = 0
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCPBKDF2KeyDerivationErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.derivedKeyData)
        
        // repeat the above with a rounds value, which triggers the error in a different place
        
        op = QCCPBKDF2SHAKeyDerivation(algorithm: .sha1, passwordString: passwordString, saltData: saltData)
        op.derivedKeyLength = 0
        op.rounds = 1000
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCPBKDF2KeyDerivationErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.derivedKeyData)
    }
    
    //- (void)testKeyDerivationThrows {
    //    #pragma clang diagnostic push
    //    #pragma clang diagnostic ignored "-Wnonnull"
    //    XCTAssertThrows((void) [[QCCPBKDF2SHAKeyDerivation alloc] initWithAlgorithm:QCCPBKDF2SHAKeyDerivationAlgorithmSHA1 passwordString:nil saltData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCPBKDF2SHAKeyDerivation alloc] initWithAlgorithm:QCCPBKDF2SHAKeyDerivationAlgorithmSHA1 passwordString:@"" saltData:nil]);
    //    #pragma clang diagnostic pop
    //}
    
}
