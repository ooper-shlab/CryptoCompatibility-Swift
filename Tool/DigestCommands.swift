//
//  DigestCommands.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/9.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Commands for SHA and other digests.
 */

import Foundation

protocol DigestOperation {
    
    var outputDigest: Data? {get}
    
}
extension QCCSHADigest: DigestOperation {}

typealias DigestOpMaker = (Data)->DigestOperation

/*! Implements the `digest` command.
 */

class DigestCommand: QToolCommand {
    
    private var opMaker: DigestOpMaker?
    
    override class var commandName: String {
        return "digest"
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) -a sha1|sha2-224|sha2-256|sha2-384|sha2-512 file"
    }
    
    override class var optionFuncsWithArg: [String: (QToolCommand)->(String)->Bool] {
        return ["a": {DigestCommand.setOption_a_argument($0 as! DigestCommand)}]
    }
    
    private func setOption_a_argument(_ argument: String) -> Bool {
        
        var result = true
        switch argument {
        case "sha1":
            self.opMaker = {QCCSHADigest(algorithm: .sha1, inputData: $0)}
        case "sha2-224":
            self.opMaker = {QCCSHADigest(algorithm: .sha2_224, inputData: $0)}
        case "sha2-256":
            self.opMaker = {QCCSHADigest(algorithm: .sha2_256, inputData: $0)}
        case "sha2-384":
            self.opMaker = {QCCSHADigest(algorithm: .sha2_384, inputData: $0)}
        case "sha2-512":
            self.opMaker = {QCCSHADigest(algorithm: .sha2_512, inputData: $0)}
        default:
            result = false
        }
        
        return result
    }
    
    override func validate(optionsAndArguments: [String]) -> Bool {
        
        var success = super.validate(optionsAndArguments: optionsAndArguments)
        if success {
            if self.arguments.count != 1 {
                success = false
            } else if self.opMaker == nil {
                // Defaulting to SHA1 is reasonable.
                success = self.setOption_a_argument("sha1")
            }
        }
        return success
    }
    
    override func run() throws {
        
        let data = try Data(contentsOf: URL(fileURLWithPath: self.arguments[0]))
        
        let op = self.opMaker!(data)
        ToolCommon.shared.synchronouslyRun(operation: op as! Operation)
        fputs("\(QHex.hexString(data: op.outputDigest!))\n", stdout)
        
    }
    
}

/*! Implements the `hmac` command.
 */

class HMACCommand: QToolCommand {
    
    var keyData: Data?
    var algorithm: QCCHMACSHAAuthentication.Algorithm = .sha1
    
    override class var commandName: String {
        return "hmac"
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) -a sha1|sha2-224|sha2-256|sha2-384|sha2-512 -k keyHexStr file"
    }
    
    override class var optionFuncsWithArg: [String: (QToolCommand)->(String)->Bool] {
        return [
            "a": {HMACCommand.setOption_a_argument($0 as! HMACCommand)},
            "k": {HMACCommand.setOption_k_argument($0 as! HMACCommand)},
        ]
    }
    
    private func setOption_k_argument(_ argument: String) -> Bool {
        self.keyData = QHex.optionalData(hex: argument)
        return self.keyData != nil
    }
    
    private func setOption_a_argument(_ argument: String) -> Bool {
        
        var result = true
        switch argument {
        case "sha1":
            self.algorithm = .sha1
        case "sha2-224":
            self.algorithm = .sha2_224
        case "sha2-256":
            self.algorithm = .sha2_256
        case "sha2-384":
            self.algorithm = .sha2_384
        case "sha2-512":
            self.algorithm = .sha2_512
        default:
            result = false
        }
        
        return result
    }
    
    override func validate(optionsAndArguments: [String]) -> Bool {
        
        var success = super.validate(optionsAndArguments: optionsAndArguments)
        if self.arguments.count != 1 {
            success = false
        } else if self.keyData == nil {
            success = false
        }
        // We don't check self.algorithm because the default, SHA1, is fine.
        return success
    }
    
    override func run() throws {
        
        let data = try Data(contentsOf: URL(fileURLWithPath: self.arguments[0]))
        
        let op = QCCHMACSHAAuthentication(algorithm: self.algorithm, input: data, key: self.keyData!)
        ToolCommon.shared.synchronouslyRun(operation: op)
        fputs("\(QHex.hexString(data: op.outputHMAC!))\n", stdout)
        
    }
    
}
