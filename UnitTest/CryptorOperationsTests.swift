//
//  CryptorOperationsTests.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/10.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Tests for the cryptor operations.
 */

import XCTest

class CryptorOperationsTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        ToolCommon.shared.debugRunOpOnMainThread = true
    }
    
    //MARK: * QCCAESCryptor
    
    // AES-128 ECB
    
    func testAES128ECBEncryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-336", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-ecb-336", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let op = QCCAESCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = nil
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES128ECBEncryptionEmpty() {
        
        let inputData = Data()
        
        let expectedOutputData = Data()
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let op = QCCAESCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = nil
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES128ECBDecryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-ecb-336", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-336", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let op = QCCAESCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = nil
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES128ECBDecryptionEmpty() {
        
        let inputData = Data()
        
        let expectedOutputData = Data()
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let op = QCCAESCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = nil
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    // AES-128 CBC
    
    func testAES128CBCEncryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-336", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-336", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES128CBCEncryptionEmpty() {
        
        let inputData = Data()
        
        let expectedOutputData = Data()
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES128CBCDecryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-336", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-336", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES128CBCDecryptionEmpty() {
        
        let inputData = Data()
        
        let expectedOutputData = Data()
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    // AES-256 ECB
    
    func testAES256ECBEncryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-336", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-256-ecb-336", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a")
        
        let op = QCCAESCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = nil
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES256ECBDecryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-256-ecb-336", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-336", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a")
        
        let op = QCCAESCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = nil
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    // AES-256 CBC
    
    func testAES256CBCEncryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-336", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-256-cbc-336", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES256CBCDecryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-256-cbc-336", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-336", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    // errors
    
    func testAESErrors() {
        
        // data not a multiple of the block size
        
        var inputData = QHex.data(hex: "000102030405060708090a0b0c0d0e")
        
        var keyData = QHex.data(hex: "000102030405060708090a0b0c0d0e0f")
        
        var op = QCCAESCryptor(toEncryptInput: inputData, key: keyData)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
        
        op = QCCAESCryptor(toDecryptInput: inputData, key: keyData)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
        
        // key not one of the standard AES key lengths
        
        inputData = QHex.data(hex: "000102030405060708090a0b0c0d0e0f")
        
        keyData = QHex.data(hex: "000102030405060708090a0b0c0d0e")
        
        op = QCCAESCryptor(toEncryptInput: inputData, key: keyData)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
        
        op = QCCAESCryptor(toDecryptInput: inputData, key: keyData)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
        
        // IV specified, but not a multiple of the block size
        
        inputData = QHex.data(hex: "000102030405060708090a0b0c0d0e0f")
        
        keyData = QHex.data(hex: "000102030405060708090a0b0c0d0e0f")
        
        let ivData = QHex.data(hex: "000102030405060708090a0b0c0d0e")
        
        op = QCCAESCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
        
        op = QCCAESCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
    }
    
    //- (void)testAESThrows {
    //    #pragma clang diagnostic push
    //    #pragma clang diagnostic ignored "-Wnonnull"
    //    XCTAssertThrows((void) [[QCCAESCryptor alloc] initToDecryptInputData:nil keyData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCAESCryptor alloc] initToDecryptInputData:[NSData data] keyData:nil]);
    //    XCTAssertThrows((void) [[QCCAESCryptor alloc] initToEncryptInputData:nil keyData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCAESCryptor alloc] initToEncryptInputData:[NSData data] keyData:nil]);
    //    #pragma clang diagnostic pop
    //}
    
    //MARK: * QCCAESCryptor
    
    // AES-128 Pad CBC
    
    func testAES128PadCBCEncryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332",withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-332", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESPadCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES128PadCBCEncryptionEmpty() {
        
        let inputData = Data()
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-0", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESPadCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES128PadCBCDecryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-332", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESPadCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES128PadCBCDecryptionEmpty() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-0", withExtension: "dat")!)
        
        let expectedOutputData = Data()
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESPadCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    // AES-256 Pad CBC
    
    func testAES256PadCBCEncryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-256-cbc-332", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESPadCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    func testAES256PadCBCDecryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-256-cbc-332", withExtension: "dat")!)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESPadCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    // errors
    
    func testAESPadErrors() {
        
        // data not a multiple of the block size
        
        // Note that we don't test the encrypt case here because the whole point of padding
        // is to allow us to encrypt data that's not a multiple of the block length.
        
        var inputData = QHex.data(hex: "000102030405060708090a0b0c0d0e")
        
        var keyData = QHex.data(hex: "000102030405060708090a0b0c0d0e0f")
        
        var op = QCCAESPadCryptor(toDecryptInput: inputData, key: keyData)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESPadCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
        
        // key not one of the standard AES key lengths
        
        inputData = QHex.data(hex: "000102030405060708090a0b0c0d0e0f")
        
        keyData = QHex.data(hex: "000102030405060708090a0b0c0d0e")
        
        op = QCCAESPadCryptor(toEncryptInput: inputData, key: keyData)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESPadCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
        
        op = QCCAESPadCryptor(toDecryptInput: inputData, key: keyData)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESPadCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
        
        // IV specified, but not a multiple of the block size
        
        inputData = QHex.data(hex: "000102030405060708090a0b0c0d0e0f")
        
        keyData = QHex.data(hex: "000102030405060708090a0b0c0d0e0f")
        
        let ivData = QHex.data(hex: "000102030405060708090a0b0c0d0e")
        
        op = QCCAESPadCryptor(toEncryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESPadCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
        
        op = QCCAESPadCryptor(toDecryptInput: inputData, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESPadCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssertNil(op.outputData)
    }
    
    //- (void)testAESPadThrows {
    //    #pragma clang diagnostic push
    //    #pragma clang diagnostic ignored "-Wnonnull"
    //    XCTAssertThrows((void) [[QCCAESPadCryptor alloc] initToDecryptInputData:nil keyData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCAESPadCryptor alloc] initToDecryptInputData:[NSData data] keyData:nil]);
    //    XCTAssertThrows((void) [[QCCAESPadCryptor alloc] initToEncryptInputData:nil keyData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCAESPadCryptor alloc] initToEncryptInputData:[NSData data] keyData:nil]);
    //    #pragma clang diagnostic pop
    //}
    
    //MARK: * QCCAESPadBigCryptor
    
    // AES-128 Pad Big CBC
    
    func testAES128PadBigCBCEncryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332", withExtension: "dat")!)
        
        let inputStream = InputStream(data: inputData)
        
        let outputStream = OutputStream(toMemory: ())
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-332", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESPadBigCryptor(toEncryptInput: inputStream, toOutput: outputStream, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data)
    }
    
    func testAES128PadBigCBCDecryption() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-332", withExtension: "dat")!)
        
        let inputStream = InputStream(data: inputData)
        
        let outputStream = OutputStream(toMemory: ())
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-332", withExtension: "dat")!)
        
        let keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        let ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        let op = QCCAESPadBigCryptor(toDecryptInput: inputStream, toOutput: outputStream, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNil(op.error)
        XCTAssertEqual(expectedOutputData, outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data)
    }
    
    #if false
    
    // This test has been disabled because modern versions of CommonCrypto do /not/ return
    // errors (because they allow for padding oracle attacks).
    //
    // <https://en.wikipedia.org/wiki/Padding_oracle_attack>
    
    //- (void)testAES128PadBigErrors {
    //    NSData *                inputData;
    //    NSInputStream *         inputStream;
    //    NSOutputStream *        outputStream;
    //    NSData *                keyData;
    //    NSData *                ivData;
    //    QCCAESPadBigCryptor *   op;
    //    NSData *                expectedOutputData;
    //    NSData *                actualOutputData;
    //
    //    // data not a multiple of the block size
    //
    //    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-332" withExtension:@"dat"]];
    //    assert(inputData != nil);
    //
    //    inputData = [inputData subdataWithRange:NSMakeRange(0, [inputData length] - 1)];
    //    assert(inputData != nil);
    //
    //    inputStream = [NSInputStream inputStreamWithData:inputData];
    //    assert(inputStream != nil);
    //
    //    outputStream = [NSOutputStream outputStreamToMemory];
    //    assert(outputStream != nil);
    //
    //    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    //    assert(expectedOutputData != nil);
    //
    //    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    //    assert(keyData != nil);
    //
    //    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    //    assert(ivData != nil);
    //
    //    op = [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:inputStream toOutputStream:outputStream keyData:keyData];
    //    op.ivData = ivData;
    //    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    //    XCTAssertNotNil(op.error);
    //    XCTAssertEqualObjects(op.error.domain, QCCAESPadBigCryptorErrorDomain);
    //    // The actual error we get is kCCBufferTooSmall, which doesn't make much sense in this
    //    // context, but that's what Common Crypto gives us.  Rather than test for a specific
    //    // error, we test for any error.
    //    XCTAssertTrue(op.error.code != kCCSuccess);
    //    // We actually get partial output data.  Check that the any data we got is correct.
    //    actualOutputData = [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
    //    XCTAssertNotNil(actualOutputData);
    //    XCTAssertTrue([actualOutputData length] < [expectedOutputData length]);     // shouldn't have got all the bytes
    //    XCTAssertEqualObjects(actualOutputData, [expectedOutputData subdataWithRange:NSMakeRange(0, [actualOutputData length])]);
    //}
    
    #endif
    
    func testAES128PadBigErrors2() {
        
        // key not one of the standard AES key lengths
        
        var inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-332", withExtension: "dat")!)
        
        var inputStream = InputStream(data: inputData)
        
        var outputStream = OutputStream(toMemory: ())
        
        var keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF757")
        
        var ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFFB7")
        
        var op = QCCAESPadBigCryptor(toDecryptInput: inputStream, toOutput: outputStream, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESPadBigCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssert((outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data).isEmpty)
        
        // IV specified, but not a multiple of the block size
        
        inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "cyphertext-aes-128-cbc-332", withExtension: "dat")!)
        
        inputStream = InputStream(data: inputData)
        
        outputStream = OutputStream(toMemory: ())
        
        keyData = QHex.data(hex: "0C1032520302EC8537A4A82C4EF7579D")
        
        ivData = QHex.data(hex: "AB5BBEB426015DA7EEDCEE8BEE3DFF")
        
        op = QCCAESPadBigCryptor(toDecryptInput: inputStream, toOutput: outputStream, key: keyData)
        op.ivData = ivData
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertNotNil(op.error)
        XCTAssertEqual((op.error as NSError?)?.domain, QCCAESPadBigCryptor.ErrorDomain)
        XCTAssertEqual((op.error as NSError?)?.code, kCCParamError)
        XCTAssert((outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data).isEmpty)
    }
    
    //- (void)testAESPadBigThrows {
    //    #pragma clang diagnostic push
    //    #pragma clang diagnostic ignored "-Wnonnull"
    //    XCTAssertThrows((void) [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:nil toOutputStream:[NSOutputStream outputStreamToMemory] keyData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:[NSInputStream inputStreamWithData:[NSData data]] toOutputStream:nil keyData:[NSData data]]);
    //    XCTAssertThrows((void) [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:[NSInputStream inputStreamWithData:[NSData data]] toOutputStream:[NSOutputStream outputStreamToMemory] keyData:nil]);
    //    #pragma clang diagnostic pop
    //}
    
}
