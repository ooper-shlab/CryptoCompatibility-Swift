//
//  QCCRSASHASignature.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/7.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Implements RSA SHA signature signing and verification using the unified crypto API.
 */

import Foundation

/*! Denotes a specific SHA-based RSA signature algorithm algorithm.
 */

enum QCCRSASHASignatureAlgorithm {
    case sha1
    case sha2_224
    case sha2_256
    case sha2_384
    case sha2_512
}

@available(OSX 10.12, iOS 10.0, *)
private func secAlgorithmForAlgorithm(_ algorithm: QCCRSASHASignatureAlgorithm) -> SecKeyAlgorithm {
    switch algorithm {
    case .sha1: return .rsaSignatureMessagePKCS1v15SHA1
    case .sha2_224: return .rsaSignatureMessagePKCS1v15SHA224
    case .sha2_256: return .rsaSignatureMessagePKCS1v15SHA256
    case .sha2_384: return .rsaSignatureMessagePKCS1v15SHA384
    case .sha2_512: return .rsaSignatureMessagePKCS1v15SHA512
    }
}

//MARK - Verify

/*! Verifies an RSA SHA signature.
 *  \details This uses the unified asymmetric crypto API added in iOS 10 and macOS 10.12.
 *
 *      If your deployment target does not guarantee the availability of the unified asymmetric
 *      crypto API, use QCCRSASHAVerifyCompat instead.
 */

@available(OSX 10.12, iOS 10.0, *)
class QCCRSASHAVerify: Operation {
    
    /*! The specific SHA-based RSA signature algorithm to use.
     *  \details This is set by the init method.
     */
    
    let algorithm: QCCRSASHASignatureAlgorithm
    
    /*! The data whose signature you want to verify.
     *  \details This is set by the init method.
     */
    
    let inputData: Data
    
    /*! The public key whose associated private key was used to generate the signature.
     *  \details This is set by the init method.
     */
    
    let publicKey: SecKey
    
    /*! The signature to verify.
     *  \details This is set by the init method.
     */
    
    let signatureData: Data
    
    /*! The error, if any, resulting from verification operation.
     *  \details This is set when the operation is finished.  On success, it will be nil.  Or error,
     *      it will hold a value describing that error.
     *
     *      This will not be set if the verification fails.  Rather, this will be nil and `verified`
     *      will be false.
     */
    
    private(set) var error: Error?
    
    /*! The verification result.
     *  \details This is only meaningful when the operation has finished.  It will be `NO` if there
     *      was an error during verification (in which case `error` will be set) or the signature
     *      was simply not verified (in which case `error` will be nil).
     */
    
    private(set) var verified: Bool = false
    
    /*! Initialise the object to verify a signature.
     *  \param algorithm The specific SHA-based RSA signature algorithm to use.
     *  \param inputData The data whose signature you want to verify.  This is the original data itself, not
     *      a digest of that data.
     *  \param publicKey The public key whose associated private key was used to generate the signature.
     *  \param signatureData The signature to verify; the length of this data is tied to the key size.  For example,
     *      a 2048-bit RSA key will always generate a 256 byte signature.
     *  \returns The initialised object.
     */
    
    init(algorithm: QCCRSASHASignatureAlgorithm, input inputData: Data, publicKey: SecKey, signature signatureData:Data) {
        self.algorithm = algorithm
        self.inputData = inputData
        self.publicKey = publicKey
        self.signatureData = signatureData
        
        super.init()
        
    }
    
    private func runUsingUnified() {
        var umErrorCF: Unmanaged<CFError>? = nil
        
        // Verify the signature against our input data.  We don't need to calculate our own digest
        // because we're using a kSecKeyAlgorithmRSASignatureMessageXxx algorithm, which takes an
        // input message and generate the digest internally.
        //
        // If you /need/ to verify a digest rather than a message, check out the code for
        // QCCRSASHAVerifyCompat which shows how to do that.
        
        self.verified = SecKeyVerifySignature(
            self.publicKey,
            secAlgorithmForAlgorithm(self.algorithm),
            self.inputData as CFData,
            self.signatureData as CFData,
            &umErrorCF
        )
        
        // Deal with the results.
        
        if !self.verified {
            
            let error = umErrorCF?.takeRetainedValue() as Error? as NSError?
            if error?.domain == NSOSStatusErrorDomain && error?.code == Int(errSecVerifyFailed) {
                // An explicit verify failure is not considered an error.
                assert(self.error == nil)
            } else {
                self.error = error
            }
        }
    }
    
    override func main() {
        self.runUsingUnified()
    }
    
}

//MARK - Sign

/*! Creating an RSA SHA signature.
 *  \details This uses the unified asymmetric crypto API added in iOS 10 and macOS 10.12.
 *
 *      If your deployment target does not guarantee the availability of the unified asymmetric
 *      crypto API, use QCCRSASHASignCompat instead.
 */

@available(OSX 10.12, iOS 10.0, *)
class QCCRSASHASign: Operation {
    
    /*! The specific SHA-based RSA signature algorithm to use.
     *  \details This is set by the init method.
     */
    
    let algorithm: QCCRSASHASignatureAlgorithm
    
    /*! The data that you want to sign.
     *  \details This is set by the init method.
     */
    
    let inputData: Data
    
    /*! The private key used to generate the signature.
     *  \details This is set by the init method.
     */
    
    let privateKey: SecKey
    
    /*! The error, if any, resulting from signing operation.
     *  \details This is set when the operation is finished.  On success, it will be nil.  Or error,
     *      it will hold a value describing that error.
     */
    
    private(set) var error: Error?
    
    /*! The generated signature.
     *  \details This is only meaningful when the operation has finished without error.   The length
     *      of this data is tied to the key size.  For example, a 2048-bit RSA key will always generate
     *      a 256 byte signature.
     */
    
    private(set) var signatureData: Data?
    
    /*! Initialise the object to create a signature.
     *  \param algorithm The specific SHA-based RSA signature algorithm to use.
     *  \param inputData The data that you want to sign.  This is the original data itself, not
     *      a digest of that data.
     *  \param privateKey The private key used to generate the signature.
     *  \returns The initialised object.
     */
    
    init(algorithm: QCCRSASHASignatureAlgorithm, input inputData: Data, privateKey: SecKey) {
        self.algorithm = algorithm
        self.inputData = inputData
        self.privateKey = privateKey
        
        super.init()
        
    }
    
    private func runUsingUnified() {
        var umErrorCF: Unmanaged<CFError>? = nil
        
        // Sign the input data.   We don't need to calculate our own digest because we're using
        // a kSecKeyAlgorithmRSASignatureMessageXxx algorithm, which takes an input message
        // and generate the digest internally.
        //
        // If you /need/ to sign a digest rather than a message, check out the code for
        // QCCRSASHASignCompat which shows how to do that.
        
        let resultData = SecKeyCreateSignature(
            self.privateKey,
            secAlgorithmForAlgorithm(self.algorithm),
            self.inputData as CFData,
            &umErrorCF
            ) as Data?
        
        // Deal with the results.
        
        if resultData == nil {
            self.error = umErrorCF?.takeRetainedValue()
        } else {
            self.signatureData = resultData
        }
    }
    
    override func main() {
        self.runUsingUnified()
    }
    
}
