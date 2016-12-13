//
//  RSACommands.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/10.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Commands for RSA-based encryption, decryption, signing, and verification.
 */

import Foundation

private func validFileArguments(_ arguments: [String]) -> Bool {
    
    var success = true
    for filePath in arguments {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: filePath, isDirectory: &isDirectory) && !isDirectory.boolValue {
            success = false
            break
        }
    }
    return success
}

private func keyOfClassWithFile(_ keyClass: String, _ keyFilePath: String) throws -> SecKey {
    var itemType: SecExternalItemType = SecExternalItemType.itemTypeUnknown
    var importedKeys: [SecKey] = []
    
    let keyFileURL = URL(fileURLWithPath: keyFilePath)
    
    let keyPEMData = try Data(contentsOf: keyFileURL)
    
    var importedItems: CFArray?
    
    let err = SecItemImport(
        keyPEMData as CFData,
        "pem" as CFString,
        nil,
        &itemType,
        [],
        nil,
        nil,
        &importedItems
    )
    if err == errSecSuccess {
        importedKeys = importedItems as! [SecKey]
    } else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil)
    }
    var success: Bool = false
    if importedKeys.count == 1 {
        switch itemType {
        case .itemTypePrivateKey:
            success = keyClass == kSecAttrKeyClassPrivate as String
        case .itemTypePublicKey:
            success = keyClass == kSecAttrKeyClassPublic as String
        default:
            success = false
        }
    }
    if !success {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(errSecUnsupportedFormat) , userInfo: nil)
    }
    
    return importedKeys[0]
}

private func publicKeyWithFile(_ publicKeyFilePath: String) throws -> SecKey {
    return try keyOfClassWithFile(kSecAttrKeyClassPublic as String, publicKeyFilePath)
}

private func privateKeyWithFile(_ privateKeyFilePath: String) throws -> SecKey {
    return try keyOfClassWithFile(kSecAttrKeyClassPrivate as String, privateKeyFilePath)
}

/*! Implements the `rsa-verify` command.
 */

class RSASHAVerifyCommand: QToolCommand {
    
    private var algorithm: QCCRSASHASignatureCompatAlgorithm = .sha1
    
    override class var commandName: String {
        return "rsa-verify"
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) -a sha1|sha2-224|sha2-256|sha2-384|sha2-512 publicKeyFile.pem signatureFile dataFile"
    }
    
    override class var optionFuncsWithArg: [String: (QToolCommand)->(String)->Bool] {
        return [
            "a": {RSASHAVerifyCommand.setOption_a_argument($0 as! RSASHAVerifyCommand)},
        ]
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
        if success {
            success = self.arguments.count == 3
        }
        if success {
            success = validFileArguments(self.arguments)
        }
        // We don't check self.algorithm because the default, SHA1, is fine.
        return success
    }
    
    override func run() throws {
        
        let publicKeyFilePath = self.arguments[0]
        let signatureData = try Data(contentsOf: URL(fileURLWithPath: self.arguments[1]))
        let fileData = try Data(contentsOf: URL(fileURLWithPath: self.arguments[2]))
        
        let publicKey = try publicKeyWithFile(publicKeyFilePath)
        
        let op = QCCRSASHAVerifyCompat(algorithm: self.algorithm, input: fileData, publicKey: publicKey, signature: signatureData)
        ToolCommon.shared.synchronouslyRun(operation: op)
        if op.error == nil {
            if op.verified {
                fputs("verified\n", stdout)
            } else {
                fputs("not verified\n", stdout)
            }
        } else {
            throw op.error!
        }
        
    }
    
}

/*! Implements the `rsa-sign` command.
 */

class RSASHASignCommand: QToolCommand {
    private var algorithm: QCCRSASHASignatureCompatAlgorithm = .sha1
    
    override class var commandName: String {
        return "rsa-sign"
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) -a sha1|sha2-224|sha2-256|sha2-384|sha2-512 privateKeyFile.pem file"
    }
    
    override class var optionFuncsWithArg: [String: (QToolCommand)->(String)->Bool] {
        return [
            "a": {RSASHASignCommand.setOption_a_argument($0 as! RSASHASignCommand)}
        ]
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
        if success {
            success = (self.arguments.count == 2)
        }
        if success {
            success = validFileArguments(self.arguments)
        }
        // We don't check self.algorithm because the default, SHA1, is fine.
        return success
    }
    
    override func run() throws {
        
        let privateKeyFilePath = self.arguments[0]
        let fileData = try Data(contentsOf: URL(fileURLWithPath: self.arguments[1]))
        
        let privateKey = try privateKeyWithFile(privateKeyFilePath)
        
        let op = QCCRSASHASignCompat(algorithm: self.algorithm, input: fileData, privateKey: privateKey)
        ToolCommon.shared.synchronouslyRun(operation: op)
        if op.error == nil {
            fputs("\(QHex.hexString(data: op.signatureData!))\n", stdout)
        } else {
            throw op.error!
        }
        
    }
    
}

/*! A base class for the `RSASmallEncryptCommand` and `RSASmallDecryptCommand` classes.
 */

class RSACryptorCommand: QToolCommand {
    
    fileprivate var padding: QCCRSASmallCryptorCompat.Padding = .pkcs1
    
    override class var optionFuncsWithArg: [String: (QToolCommand)->(String)->Bool] {
        return [
            "p": {RSACryptorCommand.setOption_p_argument($0 as! RSACryptorCommand)},
        ]
    }
    
    private func setOption_p_argument(_ argument: String) -> Bool {
        
        var result = true
        switch argument {
        case "pkcs1":
            self.padding = .pkcs1
        case "oaep":
            self.padding = .oaep
        default:
            result = false
        }
        return result
    }
    
}

/*! Implements the `rsa-small-encrypt` command.
 */

class RSASmallEncryptCommand: RSACryptorCommand {
    
    override class var commandName: String {
        return "rsa-small-encrypt"
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) [-p pkcs1|oaep] publicKeyFile.pem file"
    }
    
    override func validate(optionsAndArguments: [String]) -> Bool {
        
        var success = super.validate(optionsAndArguments: optionsAndArguments)
        if success {
            success = (self.arguments.count == 2)
        }
        if success {
            success = validFileArguments(self.arguments)
        }
        return success
    }
    
    override func run() throws {
        
        let publicKeyFilePath = self.arguments[0]
        let fileData = try Data(contentsOf: URL(fileURLWithPath: self.arguments[1]))
        
        let publicKey = try publicKeyWithFile(publicKeyFilePath)
        
        let op = QCCRSASmallCryptorCompat(toEncryptSmallInput: fileData, key: publicKey)
        op.padding = self.padding
        ToolCommon.shared.synchronouslyRun(operation: op)
        if op.error == nil {
            fputs("\(QHex.hexString(data: op.smallOutputData!))\n", stdout)
        } else {
            throw op.error!
        }
        
    }
    
}

/*! Implements the `rsa-small-decrypt` command.
 */

class RSASmallDecryptCommand: RSACryptorCommand {
    
    override class var commandName: String {
        return "rsa-small-decrypt"
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) [-p pkcs1|oaep] privateKeyFile.pem file"
    }
    
    override func validate(optionsAndArguments: [String]) -> Bool {
        
        var success = super.validate(optionsAndArguments: optionsAndArguments)
        if success {
            success = (self.arguments.count == 2)
        }
        if success {
            success = validFileArguments(self.arguments)
        }
        return success
    }
    
    override func run() throws {
        
        let privateKeyFilePath = self.arguments[0]
        let fileData = try Data(contentsOf: URL(fileURLWithPath: self.arguments[1]))
        
        let privateKey = try privateKeyWithFile(privateKeyFilePath)
        
        let op = QCCRSASmallCryptorCompat(toDecryptSmallInput: fileData, key: privateKey)
        op.padding = self.padding
        ToolCommon.shared.synchronouslyRun(operation: op)
        if op.error == nil {
            fputs("\(QHex.hexString(data: op.smallOutputData!))\n", stdout)
        } else {
            throw op.error!
        }
        
    }
    
}
