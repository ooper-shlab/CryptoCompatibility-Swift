//
//  QCCRSASmallCryptor.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/9.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Implements RSA encryption and decryption using the unified crypto API.
 */

import Foundation

/*! Implements RSA encryption and decryption for small chunks of data.
 *  \details The exact definition of "small" depends on the key size and the padding in
 *      use.  The key size represents the maximum size, and from that you subtract
 *      the padding overhead (11 bytes for PKCS#1, 42 bytes for OAEP).  For example, a
 *      2048-bit key with PKCS#1 padding can encrypt 245 bytes (2048 bits -> 256 bytes - 11).
 *
 *  \warning This is for encrypting and decrypting small amounts of data, not an
 *      entire file.  The standard technique for encrypting a large file is to
 *      encrypt it with a symmetric algorithm (like AES-128), using a randomly generated
 *      key, and then encrypt that key with RSA.  However, doing that sort of thing
 *      correctly is a challenge and we recommend you use some standard encryption
 *      scheme (such as CMS).
 *
 *  \note The designated initialiser for this class is private.  In the unlikely event you
 *      need to subclass it, you will have to make that public.
 *
 *  \details This uses the unified asymmetric crypto API added in iOS 10 and macOS 10.12.
 *
 *      If your deployment target does not guarantee the availability of the unified asymmetric
 *      crypto API, use QCCRSASmallCryptorCompat instead.
 */

@available(OSX 10.12, iOS 10.0, *)
class QCCRSASmallCryptor: Operation {
    
    /*! Denotes the RSA padding to use.
     *  \details The default is `QCCRSASmallCryptorPaddingPKCS1`.
     *
     *  \note This operation only supports the traditional OAEP algorithm, as defined by
     *      PKCS#1 v2 / RFC 2437.  That is, it uses SHA1 as its hash function.  It does not
     *      support SHA2-based OAEP algorithms because it wants to present the same
     *      interface as QCCRSASmallCryptorCompat, and that class relies on legacy APIs that
     *      only support SHA1.
     */
    
    enum Padding {
        case pkcs1
        case oaep
    }
    
    /*! The data to be encrypted or decrypted.
     *  \details This is set by the init method.
     */
    
    let smallInputData: Data
    
    /*! The key with which to do the encryption (public key) or decryption (private key).
     *  \details This is set by the init method.
     */
    
    let key: SecKey
    
    /*! The padding to use.
     *  \details The default is `QCCRSASmallCryptorPaddingPKCS1`.
     *
     *      If you set this, you must set it before queuing the operation.
     */
    
    var padding: Padding
    
    /*! The error, if any, resulting from encryption or decryption operation.
     *  \details This is set when the operation is finished.  On success, it will be nil.  Or error,
     *      it will hold a value describing that error.
     */
    
    private(set) var error: Error?
    
    /*! The output data.
     *  \details This is only meaningful when the operation has finished without error.
     *      If this is an encryption operation, this will be the input data encrypted using the
     *      public key.  The output data length will match the key size so, for example, a 2048-bit
     *      key will output 256 bytes.
     *
     *      If this is a decryption operation, this will be the input data decrypted using
     *      the private key.  Its length will be strictly less than the input data length.
     */
    
    private(set) var smallOutputData: Data?
    
    private enum Operation {
        case encrypt
        case decrypt
    }
    
    private let op: Operation
    
    private init(operation op: Operation, smallInput smallInputData: Data, key: SecKey) {
        self.op = op
        self.smallInputData = smallInputData
        self.key = key
        self.padding = .pkcs1
        
        super.init()
        
    }
    
    /*! Initialise the object to encrypt data using a public key.
     *  \param smallInputData A small amount of data to encrypt; the exact limit to this length
     *      is determined by the key size and the padding as discussed above.
     *  \param key The public key used to encrypt the data.
     *  \returns The initialised object.
     */
    
    convenience init(toEncryptSmallInput smallInputData: Data, key: SecKey) {
        self.init(operation: .encrypt, smallInput: smallInputData, key: key)
    }
    
    /*! Initialise the object to decrypt data using a private key.
     *  \param smallInputData The data to decrypt; its length must match the key size, for
     *      example, for a 2048-bit key this must be 256 bytes.
     *  \param key The private key used to decrypt the data.
     *  \returns The initialised object.
     */
    
    convenience init(toDecryptSmallInput smallInputData: Data, key: SecKey) {
        self.init(operation: .decrypt, smallInput: smallInputData, key: key)
    }
    
    private func runUsingUnified() {
        var umErrorCF: Unmanaged<CFError>? = nil     // Security framework seems to be grumpy if errorCF left uninitialised
        let algorithm: SecKeyAlgorithm
        var resultData: Data? = nil
        
        // Map our padding constant appropriately.
        
        switch self.padding {
        case .pkcs1:
            algorithm = .rsaEncryptionPKCS1
        case .oaep:
            algorithm = .rsaEncryptionOAEPSHA1
        }
        
        // Do the crypto.
        
        switch self.op {
        case .encrypt:
            resultData = SecKeyCreateEncryptedData(
                self.key,
                algorithm,
                self.smallInputData as CFData,
                &umErrorCF
                ) as Data?
        case .decrypt:
            resultData = SecKeyCreateDecryptedData(
                self.key,
                algorithm,
                self.smallInputData as CFData,
                &umErrorCF
                ) as Data?
        }
        
        // Set up the result.
        
        if resultData == nil {
            self.error = umErrorCF?.takeRetainedValue() as Error?
        } else {
            self.smallOutputData = resultData
        }
    }
    
    override func main() {
        
        let smallInputDataLength = self.smallInputData.count
        let keyBlockSize = SecKeyGetBlockSize(self.key)
        
        // Check that the input data length makes sense.  In most cases these checks are
        // redundant (because the underlying crypto operation does the same checks) but
        // it's good to have them here to help with debugging.  If you get the length
        // wrong, you can set a breakpoint here and learn what's wrong.
        
        var err = errSecSuccess
        switch self.op {
        case .encrypt:
            switch self.padding {
            case .pkcs1:
                assert(keyBlockSize > 11)
                if smallInputDataLength + 11 > keyBlockSize {
                    err = errSecParam
                }
            case .oaep:
                // 42 is 2 + 2 * HashLen, where HashLen is the length of the hash
                // use by the OAEP algorithm.  We currently only support OAEP with SHA1,
                // which has a hash length of 20.
                assert(keyBlockSize > 42)
                if smallInputDataLength + 42 > keyBlockSize {
                    err = errSecParam
                }
            }
        case .decrypt:
            if smallInputDataLength != keyBlockSize {
                err = errSecParam
            }
        }
        
        // If everything is OK, call the real code.
        
        if err != errSecSuccess {
            self.error = NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil)
        } else {
            self.runUsingUnified()
        }
    }
    
}
