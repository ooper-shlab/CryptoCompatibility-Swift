//
//  QCCHMACSHAAuthentication.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/6.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Calculates an authenticated message digest for some data using the HMAC-SHA algorithm.
 */

import Foundation
extension Array {
    subscript(index: QCCHMACSHAAuthentication.Algorithm) -> Element {
        return self[index.rawValue]
    }
}

/*! Calculates an authenticated message digest for some data using the HMAC-SHA algorithm.
 */

class QCCHMACSHAAuthentication: Operation {
    
    /*! Denotes a specific SHA digest algorithm used internally by the authenticated message digest.
     *  \warning SHA1 may not secure; if you have a choice, choose SHA2-256 or better.
     */
    
    enum Algorithm: Int {
        case sha1
        case sha2_224
        case sha2_256
        case sha2_384
        case sha2_512
    }
    
    /*! The specific SHA digest algorithm to use for the authenticated message digest.
     *  \details This is set by the init method.
     */
    
    let algorithm: Algorithm
    
    /*! The data to digest.
     *  \details This is set by the init method.
     */
    
    let inputData: Data
    
    /*! The key to use for the authenticated message digest.
     *  \details This is set by the init method.
     */
    
    let keyData: Data
    
    /*! The output authenticated digest.
     *  \details This is set when the operation is finished.  The length of this data will be
     *      determined by the specific digest algorithm.  For example, if you specify the
     *      SHA2-256 algorithm (`QCCHMACSHAAuthenticationAlgorithmSHA2_256`) then the length of
     *      this data will be 32 bytes (`CC_SHA256_DIGEST_LENGTH`).
     */
    
    private(set) var outputHMAC: Data?
    
    /*! Initialise the object to digest the supplied data.
     *  \param algorithm The specific SHA digest algorithm to use for the authenticated message digest.
     *  \param inputData The data to digest; this may be empty.
     *  \param keyData The key to use for the authenticated message digest; this may be empty,
     *      although that would be very poor security.
     *  \returns The initialised object.
     */
    
    init(algorithm: Algorithm, input inputData: Data, key keyData: Data) {
        self.algorithm = algorithm
        self.inputData = inputData
        self.keyData = keyData
        
        super.init()
        
    }
    
    override func main() {
        let kDigestSize: [Int] = [
            Int(CC_SHA1_DIGEST_LENGTH),
            Int(CC_SHA224_DIGEST_LENGTH),
            Int(CC_SHA256_DIGEST_LENGTH),
            Int(CC_SHA384_DIGEST_LENGTH),
            Int(CC_SHA512_DIGEST_LENGTH)
        ]
        let kCCAlgorithm: [CCHmacAlgorithm] = [
            UInt32(kCCHmacAlgSHA1),
            UInt32(kCCHmacAlgSHA224),
            UInt32(kCCHmacAlgSHA256),
            UInt32(kCCHmacAlgSHA384),
            UInt32(kCCHmacAlgSHA512)
        ]
        
        // The output length is determined by the hash algorithm, for example, SHA1
        // implies that hmac must be CC_SHA1_DIGEST_LENGTH bytes long.
        
        var hmac = Data(count: kDigestSize[self.algorithm])
        self.keyData.withUnsafeBytes{keyBytes in
            self.inputData.withUnsafeBytes{bytes in
                hmac.withUnsafeMutableBytes{mutableBytes in
                    CCHmac(kCCAlgorithm[self.algorithm], keyBytes, self.keyData.count, bytes, self.inputData.count, mutableBytes)
                }
            }
        }
        self.outputHMAC = hmac
    }
    
}
