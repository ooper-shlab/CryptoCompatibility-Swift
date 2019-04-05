//
//  QCCSHADigest.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/6.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Calculates the SHA digest of some data.
 */

import Foundation

/*! Calculates the SHA digest of some data.
 */

class QCCSHADigest: Operation {
    
    /*! Denotes a specific SHA digest algorithm.
     *  \warning SHA1 is probably not secure; if you have a choice, choose SHA2-256
     *      or better.
     */
    
    enum Algorithm {
        case sha1
        case sha2_224
        case sha2_256
        case sha2_384
        case sha2_512
    }
    
    /*! The specific SHA digest algorithm to use.
     *  \details This is set by the init method.
     */
    
    let algorithm: Algorithm
    
    /*! The data to digest.
     *  \details This is set by the init method.
     */
    
    let inputData: Data
    
    /*! The output digest.
     *  \details This is set when the operation is finished.  The length of this data will be
     *      determined by the specific digest algorithm.  For example, if you specify the
     *      SHA2-256 algorithm (`QCCSHADigestAlgorithmSHA2_256`) then the length of this data
     *      will be 32 bytes (`CC_SHA256_DIGEST_LENGTH`).
     */
    
    private(set) var outputDigest: Data?
    
    /*! Initialise the object to digest the supplied data.
     *  \param algorithm The specific SHA digest algorithm to use.
     *  \param inputData The data to digest; this may be empty.
     *  \returns The initialised object.
     */
    
    init(algorithm: Algorithm, inputData: Data) {
        self.algorithm = algorithm
        self.inputData = inputData
        
        super.init()
        
    }
    
    override func main() {
        var digest: Data
        
        // You can ignore the result CC_SHAxxx because it never fails.
        
        switch self.algorithm {
        case .sha1:
            digest = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
            self.inputData.withUnsafeBytes{bytes in
                digest.withUnsafeMutableBytes{mutableBytes in
                    _ = CC_SHA1(bytes.baseAddress, CC_LONG(self.inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        case .sha2_224:
            digest = Data(count: Int(CC_SHA224_DIGEST_LENGTH))
            self.inputData.withUnsafeBytes{bytes in
                digest.withUnsafeMutableBytes{mutableBytes in
                    _ = CC_SHA224(bytes.baseAddress, CC_LONG(self.inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        case .sha2_256:
            digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
            self.inputData.withUnsafeBytes{bytes in
                digest.withUnsafeMutableBytes{mutableBytes in
                    _ = CC_SHA256(bytes.baseAddress, CC_LONG(self.inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        case .sha2_384:
            digest = Data(count: Int(CC_SHA384_DIGEST_LENGTH))
            self.inputData.withUnsafeBytes{bytes in
                digest.withUnsafeMutableBytes{mutableBytes in
                    _ = CC_SHA384(bytes.baseAddress, CC_LONG(self.inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        case .sha2_512:
            digest = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
            self.inputData.withUnsafeBytes{bytes in
                digest.withUnsafeMutableBytes{mutableBytes in
                    _ = CC_SHA512(bytes.baseAddress, CC_LONG(self.inputData.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        
        self.outputDigest = digest
    }
    
}
