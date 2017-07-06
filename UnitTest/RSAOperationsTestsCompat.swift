//
//  RSAOperationsTestsCompat.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/12.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Tests for the RSA compatibility operations.
 */

import XCTest

private var sUseCompatibilityCode: Bool = false

class RSAOperationsTestsCompat: RSAOperationsTestsBase {
    
    override func setUp() {
        super.setUp()
        
        ToolCommon.shared.debugRunOpOnMainThread = true
    }
    
    let kAlgorithms: [QCCRSASHASignatureCompatAlgorithm] = [.sha1, .sha2_224, .sha2_256, .sha2_384, .sha2_512]
    let kSignatures: [String] = [
        "test.cer-sha1",
        "test.cer-sha2-224",
        "test.cer-sha2-256",
        "test.cer-sha2-384",
        "test.cer-sha2-512",
        ]
    
    private func verifyCountForFile(_ fileName: String) -> Int {
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: fileName, withExtension: "cer")!)
        
        var result = 0
        for i in 0..<5 {
            
            let signatureData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: kSignatures[i], withExtension: "sig")!)
            
            let op = QCCRSASHAVerifyCompat(algorithm: kAlgorithms[i], input: fileData, publicKey: self.publicKey!, signature: signatureData)
            op.debugUseCompatibilityCode = sUseCompatibilityCode
            ToolCommon.shared.synchronouslyRun(operation: op)
            assert(op.error == nil)
            if op.verified {
                result += 1
            }
        }
        
        return result
        
    }
    
    func testRSASHAVerify() {
        XCTAssertEqual(self.verifyCountForFile("test"), 5)
        XCTAssertEqual(self.verifyCountForFile("test-corrupted"), 0)
    }
    
    func testRSASHASign() {
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "cer")!)
        
        for i in 0..<5 {
            
            let expectedSignatureData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: kSignatures[i], withExtension: "sig")!)
            
            let op = QCCRSASHASignCompat(algorithm: kAlgorithms[i], input: fileData, privateKey: self.privateKey!)
            op.debugUseCompatibilityCode = sUseCompatibilityCode
            ToolCommon.shared.synchronouslyRun(operation: op)
            XCTAssertNil(op.error)
            XCTAssertEqual(op.signatureData!, expectedSignatureData)
        }
    }
    
    // When you encrypt with padding you can't test a fixed encryption because the padding
    // adds some randomness so that no two encryptions are the same.  Thus, we can only test
    // the round trip case (-testRSASmallCryptor) and the decrypt case (-testRSADecryptPKCS1
    // and -testRSADecryptOAEP).
    
    func testRSASmallCryptor() {
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-32", withExtension: "dat")!)
        
        var op = QCCRSASmallCryptorCompat(toEncryptSmallInput: fileData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        
        if let smallOutputData = op.smallOutputData {
            op = QCCRSASmallCryptorCompat(toDecryptSmallInput: smallOutputData, key: self.privateKey!)
            op.debugUseCompatibilityCode = sUseCompatibilityCode
            ToolCommon.shared.synchronouslyRun(operation: op)
            XCTAssertNil(op.error)
            
            XCTAssertEqual(fileData, op.smallOutputData)
        }
    }
    
    func testRSADecryptPKCS1() {
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-32", withExtension: "dat")!)
        
        // This is the "plaintext-32.dat" data encrypted with the public key using the
        // following OpenSSL command:
        //
        // $ openssl rsautl -encrypt -pkcs -pubin -inkey TestData/public.pem -in TestData/plaintext-32.dat
        
        let cyphertext32Data = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-pkcs1-32", withExtension: "dat")!)
        
        let op = QCCRSASmallCryptorCompat(toDecryptSmallInput: cyphertext32Data, key: self.privateKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        
        XCTAssertEqual(fileData, op.smallOutputData)
    }
    
    func testRSADecryptOAEP() {
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-32", withExtension: "dat")!)
        
        // This is the "plaintext-32.dat" data encrypted with the public key using the
        // following OpenSSL command:
        //
        // $ openssl rsautl -encrypt -oaep -pubin -inkey TestData/public.pem -in TestData/plaintext-32.dat
        
        let cyphertext32Data = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-oaep-32", withExtension: "dat")!)
        
        let op = QCCRSASmallCryptorCompat(toDecryptSmallInput: cyphertext32Data, key: self.privateKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(fileData, op.smallOutputData)
    }
    
    func testRSAVerifyError() {
        
        // passing private key to verify
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "cer")!)
        
        let signatureData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test.cer-sha1", withExtension: "sig")!)
        
        let op = QCCRSASHAVerifyCompat(algorithm: .sha1, input: fileData, publicKey: self.privateKey!, signature: signatureData)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        // We skip the error check because some OS releases make it impossible to determine
        // where there was a very failure or a parameter error.  What matters here is that
        // op.verified is false.
        //
        // XCTAssertNotNil(op.error);
        // XCTAssertEqualObjects(op.error.domain, @"Internal CSSM error");
        // XCTAssertTrue(op.error.code != 0);
        XCTAssertFalse(op.verified)        // this would be true if we'd passed in self.publicKey
    }
    
    func testRSASignError() {
        
        // Note: This test fails on OS X 10.7.x because the signing transform doesn't fail if
        // you pass it a public key; rather it succeeds, but produces gibberish results.
        
        // passing public key to sign
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "cer")!)
        
        let op = QCCRSASHASignCompat(algorithm: .sha1, input: fileData, privateKey: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertNotNil((op.error as NSError?)?.domain)
        XCTAssert((op.error as NSError?)?.code != 0); // We don't check the specific error here because different OS releases given you different values.
        XCTAssertNil(op.signatureData)
    }
    
    func testRSACryptorErrorWrongKeys() {
        
        // encrypt with the private key
        
        let plaintextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-32", withExtension: "dat")!)
        
        var op = QCCRSASmallCryptorCompat(toEncryptSmallInput: plaintextData, key: self.privateKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssertTrue((op.error as NSError?)?.code != 0) // We don't check the specific error here because different OS releases given you different values.
        XCTAssertNil(op.smallOutputData)
        
        // decrypt with the public key
        
        let cyphertextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-pkcs1-32", withExtension: "dat")!)
        
        op = QCCRSASmallCryptorCompat(toDecryptSmallInput: cyphertextData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssert((op.error as NSError?)?.code != 0); // We don't check the specific error here because different OS releases given you different values.
        XCTAssertNil(op.smallOutputData)
    }
    
    func testRSACryptorErrorTooBig() {
        
        // PKCS#1
        
        var plaintextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332", withExtension: "dat")!)
        
        var op = QCCRSASmallCryptorCompat(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<256)
        
        op = QCCRSASmallCryptorCompat(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<246)
        
        op = QCCRSASmallCryptorCompat(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        // Note: The following test fails on iOS 5.x because of an off-by-one error in the data
        // length check in the Security framework.  To make it work on 5.x you have to change
        // 245 to 244.  245 is definitely the right number, so I've left the test as it should be
        // and commented about the failure here.
        
        plaintextData = plaintextData.subdata(in: 0..<245)
        
        op = QCCRSASmallCryptorCompat(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        
        // OAEP
        
        plaintextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332", withExtension: "dat")!)
        
        op = QCCRSASmallCryptorCompat(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<256)
        
        op = QCCRSASmallCryptorCompat(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<215)
        
        op = QCCRSASmallCryptorCompat(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<214)
        
        op = QCCRSASmallCryptorCompat(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
    }
    
    func testRSACryptorErrorWrongLength() {
        
        // PKCS#1
        
        var cyphertextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-pkcs1-32", withExtension: "dat")!)
        
        cyphertextData = cyphertextData.subdata(in: 0..<255)
        
        var op = QCCRSASmallCryptorCompat(toDecryptSmallInput: cyphertextData, key: self.privateKey!)
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        // OAEP
        
        cyphertextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-oaep-32", withExtension: "dat")!)
        
        cyphertextData = cyphertextData.subdata(in: 0..<255)
        
        op = QCCRSASmallCryptorCompat(toDecryptSmallInput: cyphertextData, key: self.privateKey!)
        op.padding = .oaep
        op.debugUseCompatibilityCode = sUseCompatibilityCode
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
    }
    
    //- (void)testRSAThrows {
    //    #pragma clang diagnostic push
    //    #pragma clang diagnostic ignored "-Wnonnull"
    //
    //    XCTAssertThrows((void) [[QCCRSASHAVerifyCompat alloc] initWithAlgorithm:QCCRSASHASignatureCompatAlgorithmSHA1 inputData:nil publicKey:self.publicKey signatureData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCRSASHAVerifyCompat alloc] initWithAlgorithm:QCCRSASHASignatureCompatAlgorithmSHA1 inputData:[NSData data] publicKey:NULL signatureData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCRSASHAVerifyCompat alloc] initWithAlgorithm:QCCRSASHASignatureCompatAlgorithmSHA1 inputData:[NSData data] publicKey:self.publicKey signatureData:nil]);
    //
    //    XCTAssertThrows((void) [[QCCRSASHASignCompat alloc] initWithAlgorithm:QCCRSASHASignatureCompatAlgorithmSHA1 inputData:nil privateKey:self.privateKey]);
    //    XCTAssertThrows((void) [[QCCRSASHASignCompat alloc] initWithAlgorithm:QCCRSASHASignatureCompatAlgorithmSHA1 inputData:[NSData data] privateKey:NULL]);
    //
    //    XCTAssertThrows((void) [[QCCRSASmallCryptorCompat alloc] initToDecryptSmallInputData:nil key:self.publicKey]);
    //    XCTAssertThrows((void) [[QCCRSASmallCryptorCompat alloc] initToDecryptSmallInputData:[NSData data] key:NULL]);
    //    XCTAssertThrows((void) [[QCCRSASmallCryptorCompat alloc] initToEncryptSmallInputData:nil key:self.privateKey]);
    //    XCTAssertThrows((void) [[QCCRSASmallCryptorCompat alloc] initToEncryptSmallInputData:[NSData data] key:NULL]);
    //
    //    #pragma clang diagnostic pop
    //}
    
}
