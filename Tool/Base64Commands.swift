//
//  Base64Commands.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/9.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Commands for Base64 encode and decode.
 */

import Foundation

/*! Implements the `base64-encode` command.
 */

class Base64EncodeCommand: QToolCommand {
    
    var addLineBreaks: Bool = false
    
    override class var commandName: String {
        return "base64-encode"
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) [-l] file"
    }
    
    override class var optionFuncs: [String: (QToolCommand)->()->Void] {
        return ["l": {Base64EncodeCommand.setOption_l($0 as! Base64EncodeCommand)}]
    }
    
    private func setOption_l() {
        self.addLineBreaks = true
    }
    
    override func validate(optionsAndArguments: [String]) -> Bool {
        
        var success = super.validate(optionsAndArguments: optionsAndArguments)
        if success && self.arguments.count != 1 {
            success = false
        }
        return success
    }
    
    override func run() throws {
        
        let fileData = try Data(contentsOf: URL(fileURLWithPath: self.arguments[0]))
        
        let op = QCCBase64Encode(input: fileData)
        op.addLineBreaks = self.addLineBreaks
        ToolCommon.shared.synchronouslyRun(operation: op)
        fputs(op.outputString, stderr)
        
    }
    
}

/*! Implements the `base64-decode` command.
 */

class Base64DecodeCommand: QToolCommand {
    
    override class var commandName: String {
        return "base64-decode"
    }
    
    override class var commandUsage: String {
        return "\(self.commandName) file"
    }
    
    override func validate(optionsAndArguments: [String]) -> Bool {
        
        var success = super.validate(optionsAndArguments: optionsAndArguments)
        if success && self.arguments.count != 1 {
            success = false
        }
        return success
    }
    
    override func run() throws {
        
        let fileString = try String(contentsOf: URL(fileURLWithPath: self.arguments[0]), encoding: .utf8)
        
        let op = QCCBase64Decode(input: fileString)
        ToolCommon.shared.synchronouslyRun(operation: op)
        if op.outputData == nil {
            throw NSError(domain: NSCocoaErrorDomain, code: NSFileReadCorruptFileError, userInfo: nil)
        } else {
            op.outputData!.withUnsafeBytes {bytes in
                _ = fwrite(bytes, op.outputData!.count, 1, stdout)
            }
        }
        
    }
    
}

