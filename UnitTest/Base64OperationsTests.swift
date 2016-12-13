//
//  Base64OperationsTests.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/7.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Tests for the Base64 operations.
 */

import XCTest

class Base64OperationsTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        ToolCommon.shared.debugRunOpOnMainThread = true
    }
    
    func testBase64Encode() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "cer")!)
        
        let expectedOutputString = try! String(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "pem")!, encoding: .utf8)
        
        let op = QCCBase64Encode(input: inputData)
        op.addLineBreaks = true
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertEqual(expectedOutputString, op.outputString)
    }
    
    func testBase64EncodeEmpty() {
        
        let inputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "plaintext-0", withExtension: "dat")!)
        
        let expectedOutputString = ""
        
        let op = QCCBase64Encode(input: inputData)
        op.addLineBreaks = true
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertEqual(expectedOutputString, op.outputString)
    }
    
    func testBase64Decode() {
        
        let inputString = try! String(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "pem")!, encoding: .utf8)
        
        let expectedOutputData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "cer")!)
        
        let op = QCCBase64Decode(input: inputString)
        ToolCommon.shared.synchronouslyRun(operation: op)
        XCTAssertEqual(expectedOutputData, op.outputData)
    }
    
    //- (void)testBase64Throws {
    //    #pragma clang diagnostic push
    //    #pragma clang diagnostic ignored "-Wnonnull"
    //    XCTAssertThrows((void) [[QCCBase64Encode alloc] initWithInputData:nil]);
    //    XCTAssertThrows((void) [[QCCBase64Decode alloc] initWithInputString:nil]);
    //    #pragma clang diagnostic pop
    //}
    
}
