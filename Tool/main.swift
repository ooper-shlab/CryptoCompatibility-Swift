//
//  main.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/7.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Command line tool main.
 */

import Foundation

/*! A tool command subclass that implements the main command.
 */

class MainCommand: QComplexToolCommand {
    
    var verbose: Int = 0
    var debug: Bool = false
    
    override class var subcommandClasses: [QToolCommand.Type] {
        return [
            Base64EncodeCommand.self,
            Base64DecodeCommand.self,
            DigestCommand.self,
            HMACCommand.self,
            PBKDF2KeyDerivationCommand.self,
            AESEncryptCommand.self,
            AESDecryptCommand.self,
            AESPadEncryptCommand.self,
            AESPadDecryptCommand.self,
            AESPadBigEncryptCommand.self,
            AESPadBigDecryptCommand.self,
            RSASHAVerifyCommand.self,
            RSASHASignCommand.self,
            RSASmallEncryptCommand.self,
            RSASmallDecryptCommand.self
        ]
    }
    
    override class var commandName: String {
        return String(cString: getprogname())
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) [-v] subcommand\n" +
            "\n" +
            "Subcommands:\n" +
            "\n" +
        "\(super.commandUsage)"
    }
    
    override class var optionFuncs: [String: (QToolCommand)->()->Void] {
        return [
            "v": {MainCommand.setOption_v($0 as! MainCommand)},
            "d": {MainCommand.setOption_d($0 as! MainCommand)},
        ]
    }
    
    func setOption_v() {
        self.verbose += 1
    }
    
    func setOption_d() {
        self.debug = true
    }
    
}

var success = false

autoreleasepool {
    
    let mainCommand = MainCommand()
    
    let optionsAndArguments = QToolCommand.optionsAndArguments()
    success = !optionsAndArguments.isEmpty
    if success {
        success = mainCommand.validate(optionsAndArguments: optionsAndArguments)
    }
    
    if !success {
        fputs("usage: \(type(of: mainCommand).commandUsage)\n\n", stderr)
    } else {
        
        if mainCommand.debug {
            ToolCommon.shared.debugRunOpOnMainThread = true
        }
        do {
            try mainCommand.run()
            if mainCommand.verbose != 0 {
                fputs("Success!\n", stderr)
            }
        } catch let error as NSError {
            fputs("\(type(of: mainCommand).commandName): error: \(error.domain) / \(error.code)\n", stderr)
            success = false
        }
    }
}

exit(success ? EXIT_SUCCESS : EXIT_FAILURE)
