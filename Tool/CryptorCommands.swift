//
//  CryptorCommands.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/10.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Commands for symmetric encryption and decryption.
 */

import Foundation

protocol AESCryptorProtocol: class {
    init(toEncryptInput: Data, key: Data)
    init(toDecryptInput: Data, key: Data)
    var ivData: Data? {get set}
    var error: Error? {get}
    var outputData: Data? {get}
}
extension QCCAESCryptor: AESCryptorProtocol {}
extension QCCAESPadCryptor: AESCryptorProtocol {}
protocol AESBigCryptorProtocol: class {
    init(toEncryptInput: InputStream, toOutput: OutputStream, key: Data)
    init(toDecryptInput: InputStream, toOutput: OutputStream, key: Data)
    var ivData: Data? {get set}
    var error: Error? {get}
}
extension QCCAESPadBigCryptor: AESBigCryptorProtocol {}

/*! A base class for all the AES commands.
 */

class AESCryptorCommand: QToolCommand {
    
    fileprivate var keyData: Data?
    fileprivate var ivData: Data?
    fileprivate var ecbMode: Bool = false
    
    // for subclasses to implement
    
    //+ (Class)cryptorClass;
    //+ (BOOL)encrypt;
    //- (BOOL)validateArguments;
    
    fileprivate class var cryptorClass: AnyClass {
        fatalError("implementation required")
    }
    
    fileprivate class var encrypt: Bool {
        fatalError("implementation required")
    }
    
    fileprivate func validateArguments() -> Bool {
        return (self.arguments.count == 1)
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) -k keyHexStr (-e | [-i ivHexStr]) file"
    }
    
    override class var optionFuncsWithArg: [String: (QToolCommand)->(String)->Bool] {
        return [
            "k": {AESCryptorCommand.setOption_k_argument($0 as! AESCryptorCommand)},
            "i": {AESCryptorCommand.setOption_i_argument($0 as! AESCryptorCommand)},
        ]
    }
    override class var optionFuncs: [String: (QToolCommand)->()->Void] {
        return [
            "e": {AESCryptorCommand.setOption_e($0 as! AESCryptorCommand)},
        ]
    }
    
    func setOption_k_argument(_ argument: String) -> Bool {
        self.keyData = QHex.optionalData(hex: argument)
        return self.keyData != nil
    }
    
    func setOption_i_argument(_ argument: String) -> Bool {
        self.ivData = QHex.optionalData(hex: argument)
        return self.ivData != nil
    }
    
    func setOption_e() {
        self.ecbMode = true
    }
    
    override func validate(optionsAndArguments: [String]) -> Bool {
        
        var success = super.validate(optionsAndArguments: optionsAndArguments)
        if success {
            if !self.validateArguments() {
                success = false
            } else if self.keyData == nil {
                success = false
            } else if self.ecbMode && self.ivData != nil {
                success = false           // IV is incompatible with ECB
            }
        }
        return success
    }
    
    override func run() throws {
        let op: AESCryptorProtocol
        
        let fileData = try Data(contentsOf: URL(fileURLWithPath: self.arguments[0]))
        
        // We're playing fast'n'loose with types here.  The various cryptor operations
        // don't share a command base class (becasue I don't want to have them coupled together)
        // so we don't have a class we can use for "op".  Rather than write lots of pointless
        // code just to keep the compiler happy, I tell the compile that "op" is of type
        // QCCAESCryptor.  In reality it could be any of the other cryptor classes.
        
        let cryptorClass = type(of: self).cryptorClass as! AESCryptorProtocol.Type
        if type(of: self).encrypt {
            op = cryptorClass.init(toEncryptInput: fileData, key: self.keyData!)
        } else {
            op = cryptorClass.init(toDecryptInput: fileData, key: self.keyData!)
        }
        if self.ecbMode {
            op.ivData = nil
        } else if self.ivData != nil {
            op.ivData = self.ivData
        }
        ToolCommon.shared.synchronouslyRun(operation: op as! Operation)
        if op.error == nil {
            op.outputData!.withUnsafeBytes{bytes in
                _ = fwrite(bytes, op.outputData!.count, 1, stdout)
            }
        } else {
            throw op.error!
        }
        
    }
    
}

/*! Implements the `aes-encrypt` command.
 */

class AESEncryptCommand: AESCryptorCommand {
    
    override class var commandName: String {
        return "aes-encrypt"
    }
    
    override class var cryptorClass: AnyClass {
        return QCCAESCryptor.self
    }
    
    override class var encrypt: Bool {
        return true
    }
    
}

/*! Implements the `aes-decrypt` command.
 */

class AESDecryptCommand: AESCryptorCommand {
    
    override class var commandName: String {
        return "aes-decrypt"
    }
    
    override class var cryptorClass: AnyClass {
        return QCCAESCryptor.self
    }
    
    override class var encrypt: Bool {
        return false
    }
    
}

/*! Implements the `aes-pad-encrypt` command.
 */

class AESPadEncryptCommand: AESCryptorCommand {
    
    override class var commandName: String {
        return "aes-pad-encrypt"
    }
    
    override class var cryptorClass: AnyClass {
        return QCCAESPadCryptor.self
    }
    
    override class var encrypt: Bool {
        return true
    }
    
}

/*! Implements the `aes-pad-decrypt` command.
 */

class AESPadDecryptCommand: AESCryptorCommand {
    
    override class var commandName: String {
        return "aes-pad-decrypt"
    }
    
    override class var cryptorClass: AnyClass {
        return QCCAESPadCryptor.self
    }
    
    override class var encrypt: Bool {
        return false
    }
    
}

/*! A base class for the AES 'big' cryptor commands.
 */

class AESBigCryptorCommand: AESCryptorCommand {
    
    override func validateArguments() -> Bool {
        return (self.arguments.count == 2)
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) -k keyHexStr (-e | [-i ivHexStr]) inputFile outputFile"
    }
    
    override func run() throws {
        
        let inputStream = InputStream(fileAtPath: self.arguments[0])
        var success = (inputStream != nil)
        
        var outputStream: OutputStream?
        if success {
            outputStream = OutputStream(toFileAtPath: self.arguments[1], append: false)
            success = (outputStream != nil)
        }
        
        if success {
            // We're playing fast'n'loose with types here.  The various cryptor operations
            // don't share a command base class (becasue I don't want to have them coupled together)
            // so we don't have a class we can use for "op".  Rather than write lots of pointless
            // code just to keep the compiler happy, I tell the compile that "op" is of type
            // QCCAESPadBigCryptor.  In reality it could be any of the other cryptor classes.
            
            let cryptorClass = type(of: self).cryptorClass as! AESBigCryptorProtocol.Type
            let op: AESBigCryptorProtocol
            if type(of: self).encrypt {
                op = cryptorClass.init(toEncryptInput: inputStream!, toOutput: outputStream!, key: self.keyData!)
            } else {
                op = cryptorClass.init(toDecryptInput: inputStream!, toOutput: outputStream!, key: self.keyData!)
            }
            if self.ecbMode {
                op.ivData = nil
            } else if self.ivData != nil {
                op.ivData = self.ivData
            }
            ToolCommon.shared.synchronouslyRun(operation: op as! Operation)
            if op.error != nil {
                throw op.error!
            }
        }
        
    }
    
}

/*! Implements the `aes-pad-big-encrypt` command.
 */

class AESPadBigEncryptCommand: AESBigCryptorCommand {
    
    override class var commandName: String {
        return "aes-pad-big-encrypt"
    }
    
    override class var cryptorClass: AnyClass {
        return QCCAESPadBigCryptor.self
    }
    
    override class var encrypt: Bool {
        return false
    }
    
}

/*! Implements the `aes-pad-big-decrypt` command.
 */

class AESPadBigDecryptCommand: AESBigCryptorCommand {
    
    override class var commandName: String {
        return "aes-pad-big-decrypt"
    }
    
    override class var cryptorClass: AnyClass {
        return QCCAESPadBigCryptor.self
    }
    
    override class var encrypt: Bool {
        return false
    }
    
}
