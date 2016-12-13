//
//  RSAOperationsTests.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/12.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Tests for the RSA operations.
 */

import XCTest

@available(OSX 10.12, iOS 10.0, *)
class RSAOperationsTests: RSAOperationsTestsBase {
    
    override func setUp() {
        super.setUp()
        
        ToolCommon.shared.debugRunOpOnMainThread = true
    }
    
    private let kAlgorithms: [QCCRSASHASignatureAlgorithm] = [.sha1, .sha2_224, .sha2_256, .sha2_384, .sha2_512]
    private let kSignatures: [String] = [
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
            
            let op = QCCRSASHAVerify(algorithm: kAlgorithms[i], input: fileData, publicKey: self.publicKey!, signature: signatureData)
            ToolCommon.shared.synchronouslyRun(operation: op)
            assert(op.error == nil)
            if op.verified {
                result += 1
            }
        }
        return result
    }
    
    func testRSASHAVerify() {
        if !self.hasUnifiedCrypto {return}
        XCTAssertEqual(self.verifyCountForFile("test"), 5)
        XCTAssertEqual(self.verifyCountForFile("test-corrupted"), 0)
    }
    
    func testRSASHASign() {
        if !self.hasUnifiedCrypto {return}
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "cer")!)
        
        for i in 0..<5 {
            
            let expectedSignatureData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: kSignatures[i], withExtension: "sig")!)
            
            let op = QCCRSASHASign(algorithm: kAlgorithms[i], input: fileData, privateKey: self.privateKey!)
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
        if !self.hasUnifiedCrypto {return}
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-32", withExtension: "dat")!)
        
        var op = QCCRSASmallCryptor(toEncryptSmallInput: fileData, key: self.publicKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        
        if let smallOutputData = op.smallOutputData {
            op = QCCRSASmallCryptor(toDecryptSmallInput: smallOutputData, key: self.privateKey!)
            ToolCommon.shared.synchronouslyRun(operation: op)
            XCTAssertNil(op.error)
            
            XCTAssertEqual(fileData, op.smallOutputData)
        }
    }
    
    func testRSADecryptPKCS1() {
        if !self.hasUnifiedCrypto {return}
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-32", withExtension: "dat")!)
        
        // This is the "plaintext-32.dat" data encrypted with the public key using the
        // following OpenSSL command:
        //
        // $ openssl rsautl -encrypt -pkcs -pubin -inkey TestData/public.pem -in TestData/plaintext-32.dat
        
        let cyphertext32Data = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-pkcs1-32", withExtension: "dat")!)
        
        let op = QCCRSASmallCryptor(toDecryptSmallInput: cyphertext32Data, key: self.privateKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        
        XCTAssertEqual(fileData, op.smallOutputData)
    }
    
    func testRSADecryptOAEP() {
        if !self.hasUnifiedCrypto {return}
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-32", withExtension: "dat")!)
        
        // This is the "plaintext-32.dat" data encrypted with the public key using the
        // following OpenSSL command:
        //
        // $ openssl rsautl -encrypt -oaep -pubin -inkey TestData/public.pem -in TestData/plaintext-32.dat
        
        let cyphertext32Data = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-oaep-32", withExtension: "dat")!)
        
        let op = QCCRSASmallCryptor(toDecryptSmallInput: cyphertext32Data, key: self.privateKey!)
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(fileData, op.smallOutputData)
    }
    
    func testRSAVerifyError() {
        if !self.hasUnifiedCrypto {return}
        
        // passing private key to verify
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "cer")!)
        
        let signatureData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test.cer-sha1", withExtension: "sig")!)
        
        let op = QCCRSASHAVerify(algorithm: .sha1, input: fileData, publicKey: self.privateKey!, signature: signatureData)
        ToolCommon.shared.synchronouslyRun(operation: op)
        // We skip the error check because some OS releases make it impossible to determine
        // where there was a very failure or a parameter error.  What matters here is that
        // op.verified is false.
        //
        // XCTAssertNotNil(op.error);
        // XCTAssertEqualObjects(op.error.domain, NSOSStatusErrorDomain);
        // XCTAssertEqual(op.error.code, (NSInteger) errSecUnimplemented);
        XCTAssertFalse(op.verified)        // this would be true if we'd passed in self.publicKey
    }
    
    func testRSASignError() {
        if !self.hasUnifiedCrypto {return}
        
        // passing public key to sign
        
        let fileData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "cer")!)
        
        let op = QCCRSASHASign(algorithm: .sha1, input: fileData, privateKey: self.publicKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertNotNil((op.error as? NSError)?.domain)
        XCTAssert((op.error as? NSError)?.code != 0); // We don't check the specific error here because different OS releases given you different values.
        XCTAssertNil(op.signatureData)
    }
    
    func testRSACryptorErrorWrongKeys() {
        if !self.hasUnifiedCrypto {return}
        
        // encrypt with the private key
        
        let plaintextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-32", withExtension: "dat")!)
        
        var op = QCCRSASmallCryptor(toEncryptSmallInput: plaintextData, key: self.privateKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssert((op.error as? NSError)?.code != 0); // We don't check the specific error here because different OS releases given you different values.
        XCTAssertNil(op.smallOutputData)
        
        // decrypt with the public key
        
        let cyphertextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-pkcs1-32", withExtension: "dat")!)
        
        op = QCCRSASmallCryptor(toDecryptSmallInput: cyphertextData, key: self.publicKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssert((op.error as? NSError)?.code != 0); // We don't check the specific error here because different OS releases given you different values.
        XCTAssertNil(op.smallOutputData)
    }
    
    func testRSACryptorErrorTooBig() {
        if !self.hasUnifiedCrypto {return}
        
        // PKCS#1
        
        var plaintextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332", withExtension: "dat")!)
        
        var op = QCCRSASmallCryptor(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as? NSError)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<256)
        
        op = QCCRSASmallCryptor(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as? NSError)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<246)
        
        op = QCCRSASmallCryptor(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as? NSError)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<245)
        
        op = QCCRSASmallCryptor(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        
        // OAEP
        
        plaintextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332", withExtension: "dat")!)
        
        op = QCCRSASmallCryptor(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as? NSError)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<256)
        
        op = QCCRSASmallCryptor(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as? NSError)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<215)
        
        op = QCCRSASmallCryptor(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as? NSError)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        plaintextData = plaintextData.subdata(in: 0..<214)
        
        op = QCCRSASmallCryptor(toEncryptSmallInput: plaintextData, key: self.publicKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
    }
    
    func testRSACryptorErrorWrongLength() {
        if !self.hasUnifiedCrypto {return}
        
        // PKCS#1
        
        var cyphertextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-pkcs1-32", withExtension: "dat")!)
        
        cyphertextData = cyphertextData.subdata(in: 0..<255)
        
        var op = QCCRSASmallCryptor(toDecryptSmallInput: cyphertextData, key: self.publicKey!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as? NSError)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
        
        // OAEP
        
        cyphertextData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-rsa-oaep-32", withExtension: "dat")!)
        
        cyphertextData = cyphertextData.subdata(in: 0..<255)
        
        op = QCCRSASmallCryptor(toDecryptSmallInput: cyphertextData, key: self.privateKey!)
        op.padding = .oaep
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as? NSError)?.domain, NSOSStatusErrorDomain)
        XCTAssertEqual((op.error as? NSError)?.code, Int(errSecParam))
        XCTAssertNil(op.smallOutputData)
    }
    
    //- (void)testRSAThrows {
    //    if ( ! self.hasUnifiedCrypto ) { return; }
    //    #pragma clang diagnostic push
    //    #pragma clang diagnostic ignored "-Wnonnull"
    //
    //    XCTAssertThrows((void) [[QCCRSASHAVerify alloc] initWithAlgorithm:QCCRSASHASignatureAlgorithmSHA1 inputData:nil publicKey:self.publicKey signatureData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCRSASHAVerify alloc] initWithAlgorithm:QCCRSASHASignatureAlgorithmSHA1 inputData:[NSData data] publicKey:NULL signatureData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCRSASHAVerify alloc] initWithAlgorithm:QCCRSASHASignatureAlgorithmSHA1 inputData:[NSData data] publicKey:self.publicKey signatureData:nil]);
    //
    //    XCTAssertThrows((void) [[QCCRSASHASign alloc] initWithAlgorithm:QCCRSASHASignatureAlgorithmSHA1 inputData:nil privateKey:self.privateKey]);
    //    XCTAssertThrows((void) [[QCCRSASHASign alloc] initWithAlgorithm:QCCRSASHASignatureAlgorithmSHA1 inputData:[NSData data] privateKey:NULL]);
    //
    //    XCTAssertThrows((void) [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:nil key:self.publicKey]);
    //    XCTAssertThrows((void) [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:[NSData data] key:NULL]);
    //    XCTAssertThrows((void) [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:nil key:self.privateKey]);
    //    XCTAssertThrows((void) [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:[NSData data] key:NULL]);
    //
    //    #pragma clang diagnostic pop
    //}
    
}
