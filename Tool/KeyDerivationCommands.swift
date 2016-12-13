//
//  KeyDerivationCommands.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/10.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Commands for key derivation.
 */

import Foundation

/*! Implements the `pbkdf2-key-derivation` command.
 */

class PBKDF2KeyDerivationCommand: QToolCommand {
    
    private var algorithm: QCCPBKDF2SHAKeyDerivation.Algorithm = .sha1
    private var passwordString: String?
    private var saltData: Data?
    private var rounds: Int = 0
    private var derivedKeyLength: Int = 0
    
    override class var commandName: String {
        return "pbkdf2-key-derivation"
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) -a sha1|sha2-224|sha2-256|sha2-384|sha2-512 -p passwordStr -s saltHexStr [-r rounds] [-z derivedKeyLength]"
    }
    
    override class var optionFuncsWithArg: [String: (QToolCommand)->(String)->Bool] {
        return [
            "a": {PBKDF2KeyDerivationCommand.setOption_a_argument($0 as! PBKDF2KeyDerivationCommand)},
            "p": {PBKDF2KeyDerivationCommand.setOption_p_argument($0 as! PBKDF2KeyDerivationCommand)},
            "s": {PBKDF2KeyDerivationCommand.setOption_s_argument($0 as! PBKDF2KeyDerivationCommand)},
            "r": {PBKDF2KeyDerivationCommand.setOption_r_argument($0 as! PBKDF2KeyDerivationCommand)},
            "z": {PBKDF2KeyDerivationCommand.setOption_z_argument($0 as! PBKDF2KeyDerivationCommand)},
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
    
    private func setOption_p_argument(_ argument: String) -> Bool {
        self.passwordString = argument
        return true
    }
    
    private func setOption_s_argument(_ argument: String) -> Bool {
        self.saltData = QHex.optionalData(hex: argument)
        return self.saltData != nil
    }
    
    private func setOption_r_argument(_ argument: String) -> Bool {
        self.rounds = Int(argument) ?? -1
        return self.rounds >= 0
    }
    
    private func setOption_z_argument(_ argument: String) -> Bool {
        self.derivedKeyLength = Int(argument) ?? -1
        return self.derivedKeyLength >= 0
    }
    
    override func validate(optionsAndArguments: [String]) -> Bool {
        
        var success = super.validate(optionsAndArguments: optionsAndArguments)
        if success {
            if self.arguments.count != 0 {
                success = false
            } else if self.passwordString == nil {
                success = false
            } else if self.saltData == nil {
                success = false
            }
            // We don't check self.algorithm because the default, SHA1, is fine.
        }
        return success
    }
    
    override func run() throws {
        
        let op = QCCPBKDF2SHAKeyDerivation(algorithm: self.algorithm, passwordString: self.passwordString!, saltData: self.saltData!)
        if self.rounds != 0 {
            op.rounds = self.rounds
        }
        if self.derivedKeyLength != 0 {
            op.derivedKeyLength = self.derivedKeyLength
        }
        ToolCommon.shared.synchronouslyRun(operation: op)
        if op.error == nil {
            fputs("\(QHex.hexString(data: op.derivedKeyData!))\n", stdout)
        } else {
            throw op.error!
        }
        
    }
    
}
