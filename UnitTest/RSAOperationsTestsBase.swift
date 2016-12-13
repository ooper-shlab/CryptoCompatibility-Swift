//
//  RSAOperationsTestsBase.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/12.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Base class for our RSA operation tests.
 */

import XCTest

class RSAOperationsTestsBase: XCTestCase {
    
    private(set) var publicKey: SecKey?
    private(set) var privateKey: SecKey?
    
    #if os(macOS)
    
    private func setUpMac() {
        var importedItems: CFArray?
        
        // public key
        
        var pemData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "public", withExtension: "pem")!)
        var err = SecItemImport(
            pemData as CFData,
            "pem" as CFString,
            nil,
            nil,
            [],
            nil,
            nil,
            &importedItems
        )
        assert(err == errSecSuccess)
        
        var importedKeys = importedItems as! [SecKeychainItem]
        assert(importedKeys.count == 1)
        self.publicKey = (importedKeys[0] as AnyObject as! SecKey)
        
        // private key
        
        pemData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "private", withExtension: "pem")!)
        err = SecItemImport(
            pemData as CFData,
            "pem" as CFString,
            nil,
            nil,
            [],
            nil,
            nil,
            &importedItems
        )
        assert(err == errSecSuccess)
        
        importedKeys = importedItems as! [SecKeychainItem]
        assert(importedKeys.count == 1)
        self.privateKey = (importedKeys[0] as AnyObject as! SecKey)
    }
    
    #endif
    
    #if os(iOS)
    
    // On the phone, we import the .p12.
    
    private func setUpPhone() {
        var trust: SecTrust?
        var trustResult: SecTrustResultType = SecTrustResultType.invalid
        
        // public key
        
        let certData = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "test", withExtension: "cer")!)
        
        let cert = SecCertificateCreateWithData(nil, certData as CFData)!
        
        let policy = SecPolicyCreateBasicX509()
        
        var err = SecTrustCreateWithCertificates(cert, policy, &trust)
        assert(err == errSecSuccess)
        
        err = SecTrustEvaluate(trust!, &trustResult)
        assert(err == errSecSuccess)
        
        self.publicKey = SecTrustCopyPublicKey(trust!)
        assert(self.publicKey != nil)
        
        // private key
        
        var imported: CFArray?
        
        let pkcs12Data = try! Data(contentsOf: Bundle(for: type(of: self)).url(forResource: "private", withExtension: "p12")!)
        
        err = SecPKCS12Import(pkcs12Data as CFData, [
            kSecImportExportPassphrase: "test"
            ] as NSDictionary as CFDictionary, &imported)
        assert(err == errSecSuccess)
        let importedArray = imported as! [Any]
        assert(importedArray.count == 1)
        let importedItem = importedArray[0] as! [String: Any]
        let identity = importedItem[kSecImportItemIdentity as String] as! SecIdentity
        
        err = SecIdentityCopyPrivateKey(identity, &self.privateKey)
        assert(err == errSecSuccess)
        assert(self.privateKey != nil)
        
    }
    
    #endif
    
    override func setUp() {
        super.setUp()
        
        #if os(macOS)
            self.setUpMac()
        #elseif os(iOS)
            self.setUpPhone()
        #else
            error; "What platform?"
        #endif
    }
    
    var hasUnifiedCrypto: Bool {
        if #available(macOS 10.12, iOS 10.0, *) {
            return true
        } else {
            return false
        }
    }
    
}
