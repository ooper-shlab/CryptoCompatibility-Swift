//
//  QCCRSASHASignatureCompat.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/7.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Implements RSA SHA signature signing and verification in a maximally compatible way.
 */

import Foundation

/*! Denotes a specific SHA-based RSA signature algorithm algorithm.
 */

enum QCCRSASHASignatureCompatAlgorithm {
    case sha1
    case sha2_224
    case sha2_256
    case sha2_384
    case sha2_512
}

@available(OSX 10.12, iOS 10.0, *)
private func secAlgorithmForAlgorithm(_ algorithm: QCCRSASHASignatureCompatAlgorithm) -> SecKeyAlgorithm {
    switch algorithm {
    case .sha1: return .rsaSignatureDigestPKCS1v15SHA1
    case .sha2_224: return .rsaSignatureDigestPKCS1v15SHA224
    case .sha2_256: return .rsaSignatureDigestPKCS1v15SHA256
    case .sha2_384: return .rsaSignatureDigestPKCS1v15SHA384
    case .sha2_512: return .rsaSignatureDigestPKCS1v15SHA512
    }
}

private func digestForAlgorithmOverInputData(_ algorithm: QCCRSASHASignatureCompatAlgorithm, _ inputData: Data) -> Data {
    var digest: Data
    
    switch algorithm {
    case .sha1:
        digest = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
        inputData.withUnsafeBytes {bytes in
            digest.withUnsafeMutableBytes {mutableBytes in
                _ = CC_SHA1(bytes.baseAddress, CC_LONG(inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
            }
        }
    case .sha2_224:
        digest = Data(count: Int(CC_SHA224_DIGEST_LENGTH))
        inputData.withUnsafeBytes {bytes in
            digest.withUnsafeMutableBytes {mutableBytes in
                _ = CC_SHA224(bytes.baseAddress, CC_LONG(inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
            }
        }
    case .sha2_256:
        digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        inputData.withUnsafeBytes {bytes in
            digest.withUnsafeMutableBytes {mutableBytes in
                _ = CC_SHA256(bytes.baseAddress, CC_LONG(inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
            }
        }
    case .sha2_384:
        digest = Data(count: Int(CC_SHA384_DIGEST_LENGTH))
        inputData.withUnsafeBytes {bytes in
            digest.withUnsafeMutableBytes {mutableBytes in
                _ = CC_SHA384(bytes.baseAddress, CC_LONG(inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
            }
        }
    case .sha2_512:
        digest = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
        inputData.withUnsafeBytes {bytes in
            digest.withUnsafeMutableBytes {mutableBytes in
                _ = CC_SHA512(bytes.baseAddress, CC_LONG(inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
            }
        }
    }
    return digest
}

//MARK: - Verify

/*! Verifies an RSA SHA signature.
 *  \details This uses the unified asymmetric crypto API (added in iOS 10 and macOS 10.12)
 *      if it's available, otherwise it falls back to platform-specific APIs (SecKeyRawXxx
 *      on iOS-based platforms, SecTransforms on macOS).
 *
 *      If your deployment target is high enough to guarantee that the unified asymmetric crypto
 *      API is available, consider using QCCRSASHAVerify instead.
 */

class QCCRSASHAVerifyCompat: Operation {
    
    /*! The specific SHA-based RSA signature algorithm to use.
     *  \details This is set by the init method.
     */
    
    let algorithm: QCCRSASHASignatureCompatAlgorithm
    
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
    
    /*! Force the operation to use the compatibility code path.
     *  \details The default is false.  You might set this to true when testing and debugging.
     *
     *      If you set this, you must set it before queuing the operation.
     */
    
    var debugUseCompatibilityCode: Bool = false
    
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
    
    //MARK: - Verify
    
    /*! Initialise the object to verify a signature.
     *  \param algorithm The specific SHA-based RSA signature algorithm to use.
     *  \param inputData The data whose signature you want to verify.  This is the original data itself, not
     *      a digest of that data.
     *  \param publicKey The public key whose associated private key was used to generate the signature.
     *  \param signatureData The signature to verify; the length of this data is tied to the key size.  For example,
     *      a 2048-bit RSA key will always generate a 256 byte signature.
     *  \returns The initialised object.
     */
    
    init(algorithm: QCCRSASHASignatureCompatAlgorithm, input inputData: Data, publicKey: SecKey, signature signatureData: Data) {
        self.algorithm = algorithm
        self.inputData = inputData
        self.publicKey = publicKey
        self.signatureData = signatureData
        
        super.init()
        
    }
    
    @available(OSX 10.12, iOS 10.0, *)
    private func runUsingUnified() {
        var umErrorCF: Unmanaged<CFError>? = nil
        
        // First create a SHA digest of the data (this works out the right SecKeyAlgorithm at the same time).
        //
        // You can simplify this process by passing in a kSecKeyAlgorithmRSASignatureMessageXxx algorithm,
        // whereupon the system will automatically calculate the digest for you.  For an example of this,
        // see QCCRSASHAVerify.  However, in some cases it's necessary to verify a digest directly, and this
        // code shows how to do that.
        
        let digest = digestForAlgorithmOverInputData(self.algorithm, self.inputData)
        
        // Then verify it.
        
        self.verified = SecKeyVerifySignature(
            self.publicKey,
            secAlgorithmForAlgorithm(self.algorithm),
            digest as CFData,
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
    
    #if os(macOS)
    
    fileprivate static func setupTransformForAlgorithm(_ transform: SecTransform, _ algorithm: QCCRSASHASignatureCompatAlgorithm, _ errorCFPtr: UnsafeMutablePointer<Unmanaged<CFError>?>) -> Bool {
        var success: Bool
        
        if algorithm == .sha1 {
            success = SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA1, errorCFPtr)
        } else {
            success = SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA2, errorCFPtr)
            if success {
                let digestSize: Int
                
                switch algorithm {
                case .sha1: abort()
                case .sha2_224: digestSize = 224
                case .sha2_256: digestSize = 256
                case .sha2_384: digestSize = 384
                case .sha2_512: digestSize = 512
                }
                success = SecTransformSetAttribute(transform, kSecDigestLengthAttribute, digestSize as CFNumber, errorCFPtr)
            }
        }
        return success
    }
    
    private func runUsingTransforms() {
        
        var result: CFTypeRef! = nil
        var umErrorCF: Unmanaged<CFError>? = nil
        
        // Set up the transform.
        
        let transform = SecVerifyTransformCreate(self.publicKey, self.signatureData as CFData, &umErrorCF)
        var success = (transform != nil)
        
        // Note: kSecInputIsAttributeName defaults to kSecInputIsPlainText, which is what we want.
        
        if success {
            success = QCCRSASHAVerifyCompat.setupTransformForAlgorithm(transform!, self.algorithm, &umErrorCF)
        }
        
        if success {
            success = SecTransformSetAttribute(transform!, kSecTransformInputAttributeName, self.inputData as CFData, &umErrorCF)
        }
        
        // Run it.
        
        if success {
            result = SecTransformExecute(transform!, &umErrorCF)
            success = umErrorCF == nil
        }
        
        // Process the results.
        
        if success {
            assert(CFGetTypeID(result) == CFBooleanGetTypeID())
            self.verified = result as! Bool
        } else {
            assert(umErrorCF != nil)
            self.error = umErrorCF?.takeRetainedValue() as Error?
        }
        
        // Clean up.
        
    }
    
    #endif
    
    #if os(iOS)
    
    fileprivate static func secPaddingForAlgorithm(_ algorithm: QCCRSASHASignatureCompatAlgorithm) -> SecPadding {
        switch algorithm {
        case .sha1: return SecPadding.PKCS1SHA1
        case .sha2_224: return SecPadding.PKCS1SHA224
        case .sha2_256: return SecPadding.PKCS1SHA256
        case .sha2_384: return SecPadding.PKCS1SHA384
        case .sha2_512: return SecPadding.PKCS1SHA512
        }
    }
    
    private func runUsingRaw() {
        
        // First create a SHA digest of the data.
        
        let digest = digestForAlgorithmOverInputData(self.algorithm, self.inputData)
        
        // Then verify it.
        
        let err = digest.withUnsafeBytes {bytes in
            self.signatureData.withUnsafeBytes {signatureBytes in
                SecKeyRawVerify(
                    self.publicKey,
                    QCCRSASHAVerifyCompat.secPaddingForAlgorithm(self.algorithm),
                    bytes.bindMemory(to: UInt8.self).baseAddress!,
                    bytes.count,
                    signatureBytes.bindMemory(to: UInt8.self).baseAddress!,
                    signatureBytes.count
                )
            }
        }
        
        // Deal with the results.
        
        if err == errSecSuccess {
            self.verified = true
        } else if err == errSSLCrypto {
            assert(!self.verified)
        } else {
            self.error = NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil)
        }
    }
    
    #endif
    
    override func main() {
        if #available(macOS 10.12, iOS 10.0, *), !self.debugUseCompatibilityCode {
            self.runUsingUnified()
        } else {
            #if os(macOS)
                self.runUsingTransforms()
            #elseif os(iOS)
                self.runUsingRaw()
            #else
                error; "What platform?"
            #endif
        }
    }
    
}

//MARK: - Sign

/*! Creating an RSA SHA signature.
 *  \details This uses the unified asymmetric crypto API (added in iOS 10 and macOS 10.12)
 *      if it's available, otherwise it falls back to platform-specific APIs (SecKeyRawXxx
 *      on iOS-based platforms, SecTransforms on macOS).
 *
 *      If your deployment target is high enough to guarantee that the unified asymmetric crypto
 *      API is available, consider using QCCRSASHASign instead.
 */

class QCCRSASHASignCompat: Operation {
    
    /*! The specific SHA-based RSA signature algorithm to use.
     *  \details This is set by the init method.
     */
    
    let algorithm: QCCRSASHASignatureCompatAlgorithm
    
    /*! The data that you want to sign.
     *  \details This is set by the init method.
     */
    
    let inputData: Data
    
    /*! The private key used to generate the signature.
     *  \details This is set by the init method.
     */
    
    
    let privateKey: SecKey
    
    /*! Force the operation to use the compatibility code path.
     *  \details The default is false.  You might set this to true when testing and debugging.
     *
     *      If you set this, you must set it before queuing the operation.
     */
    
    var debugUseCompatibilityCode: Bool = false
    
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
    
    init(algorithm: QCCRSASHASignatureCompatAlgorithm, input inputData: Data, privateKey: SecKey) {
        self.algorithm = algorithm
        self.inputData = inputData
        self.privateKey = privateKey
        
        super.init()
        
    }
    
    @available(OSX 10.12, iOS 10.0, *)
    func runUsingUnified() {
        var umErrorCF: Unmanaged<CFError>? = nil
        
        // First create a SHA digest of the data.  This isn't strictly speaking necessary.  If you
        // use a kSecKeyAlgorithmRSASignatureMessageXxx algorithm, the system will automatically
        // calculate the digest for you.  For an example of this, see QCCRSASHASign.  However, in
        // some cases it's necessary to sign a digest directly, and this code shows how to do that.
        
        let digest = digestForAlgorithmOverInputData(self.algorithm, self.inputData)
        
        // Then sign it.
        
        let resultData = SecKeyCreateSignature(
            self.privateKey,
            secAlgorithmForAlgorithm(self.algorithm),
            digest as CFData,
            &umErrorCF)
        
        // Deal with the results.
        
        if resultData == nil {
            self.error = umErrorCF?.takeRetainedValue()
        } else {
            self.signatureData = resultData as Data?
        }
    }
    
    #if os(macOS)
    
    func runUsingTransforms() {
        var resultData: CFTypeRef? = nil
        var umErrorCF: Unmanaged<CFError>?
        
        // Set up the transform.
        
        let transform = SecSignTransformCreate(self.privateKey, &umErrorCF)
        var success = transform != nil
        
        if success {
            success = QCCRSASHAVerifyCompat.setupTransformForAlgorithm(transform!, self.algorithm, &umErrorCF)
        }
        
        if success {
            success = SecTransformSetAttribute(transform!, kSecTransformInputAttributeName, self.inputData as CFData, &umErrorCF)
        }
        
        // Run it.
        
        if success {
            resultData = SecTransformExecute(transform!, &umErrorCF)
            success = (resultData != nil)
        }
        
        // Process the results.
        
        if success {
            assert(CFGetTypeID(resultData!) == CFDataGetTypeID())
            self.signatureData = (resultData! as! Data)
        } else {
            assert(umErrorCF != nil)
            self.error = umErrorCF!.takeRetainedValue()
        }
        
        // Clean up.
        
    }
    
    #endif
    
    #if os(iOS)
    
    private func runUsingRaw() {
        
        // First create a SHA digest of the data.
        
        let digest = digestForAlgorithmOverInputData(self.algorithm, self.inputData)
        
        // Then sign it.
        
        var resultData = Data(count: SecKeyGetBlockSize(self.privateKey))
        var resultDataLength = resultData.count
        let err = digest.withUnsafeBytes {bytes in
            resultData.withUnsafeMutableBytes {mutableBytes in
                SecKeyRawSign(
                    self.privateKey,
                    QCCRSASHAVerifyCompat.secPaddingForAlgorithm(self.algorithm),
                    bytes.bindMemory(to: UInt8.self).baseAddress!,
                    bytes.count,
                    mutableBytes.bindMemory(to: UInt8.self).baseAddress!,
                    &resultDataLength)
            }
        }
        
        // Deal with the results.
        
        if err == errSecSuccess {
            assert(resultDataLength == resultData.count)
            self.signatureData = resultData
        } else {
            self.error = NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil)
        }
    }
    
    #endif
    
    override func main() {
        if #available(OSX 10.12, iOS 10.0, *), !self.debugUseCompatibilityCode {
            self.runUsingUnified()
        } else {
            #if os(macOS)
                self.runUsingTransforms()
            #elseif os(iOS)
                self.runUsingRaw()
            #else
                #error("What platform?")
            #endif
        }
    }
    
}
