//
//  QCCPBKDF2SHAKeyDerivation.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/6.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Derives a key from a password string using the PBKDF2 algorithm.
 */

import Foundation

/*! Derives a key from a password string using the PBKDF2 algorithm.
 *  \details One key aspect of PBKDF2 is that it takes a significant amount of time to calculate the
 *      key from the password, which helps to defeat brute force attacks.  This time is proportional
 *      to the number of 'rounds' done by PBKDF2.  To get the best security, you should set 'rounds'
 *      as high as you can such that PBKDF2 in a reasonable amount of time on your target hardware.
 *
 *      This operation facilitates this by allowing you to specify a target derivation time.  The
 *      operation will automatically set the rounds parameter so that key derivation takes that
 *      amount of time on the current hardware.  It will also return the number of rounds taken,
 *      so you can save that away along with the key and the salt.
 *
 *  \warning You should *always* set the salt to some random data and save that random data along
 *      with the key.  This a) ensures that users with the same password don't end up using the same
 *      key, and b) as a consequence of this, protects from rainbow table attacks.
 *
 *  \details To use this operation, first generate a key:
 *
 *          1. use a cryptographically sound random number generator to generate some salt data
 *
 *          2. initialise the object with the required parameters, including that random salt
 *
 *          3. set `derivationTime` to a reasonable derivation time for a typical user login
 *
 *          4. run the operation
 *
 *          5. save the salt, the actual rounds and the derived key
 *
 *      When the user tries to log in you can run the operation again:
 *
 *          1. initialise the object with the required parameters, where the password string
 *              is the string the user entered and the salt is the salt you saved with the key
 *
 *          2. set the operation's rounds to be rounds you saved with the key
 *
 *          3. run the operation
 *
 *          4. get the derived key and compare it to your saved key
 */

class QCCPBKDF2SHAKeyDerivation: Operation {
    
    /*! Denotes a specific SHA digest algorithm used internally the key derivation.
     *  \warning SHA1 may not secure; if you have a choice, choose SHA2-256 or better.
     */
    
    enum Algorithm {
        case sha1
        case sha2_224
        case sha2_256
        case sha2_384
        case sha2_512
    }
    
    /*! The specific SHA digest algorithm to use for the key derivation.
     *  \details This is set by the init method.
     */
    
    let algorithm: Algorithm
    
    /*! The password string from which to derive a key
     *  \details This is set by the init method.
     */
    
    let passwordString: String
    
    /*! Some random data to salt the key derivation.
     *  \details This is set by the init method.
     */
    
    let saltData: Data
    
    /*! The number of rounds to use for the key derivation.
     *  \details The default value is 0, which tells the operation to automatically calculate the
     *      numbers of rounds based on `derivationTime`.  That's a good choice when deriving a new
     *      key.  When checking a key you should set this to the number of rounds that were used
     *      to derive the original key.
     *
     *      If you set this, you must set it before queuing the operation.
     */
    
    var rounds: Int = 0
    
    /*! The target key derivation time.
     *  \details If `rounds` is 0, this value is used as a target key derivation time; otherwise,
     *      this value is ignored.  The default is 0.1 seconds.
     *
     *      The underlying API accepts this key derivation time as a `uint32_t` number of
     *      milliseconds.  This means that values less than 1 ms or greater than 0xFFFFFFFF
     *      milliseconds are silently clipped.
     *
     *      If you set this, you must set it before queuing the operation.
     */
    
    var derivationTime: TimeInterval = 0.1
    
    /*! The size of the derived key.
     *  \details The default is 16 bytes.
     *
     *      If you set this, you must set it before queuing the operation.
     */
    
    var derivedKeyLength: Int = 16
    
    /*! The error, if any, resulting from key derivation operation.
     *  \details This is set when the operation is finished.  On success, it will be nil.  Or error,
     *      it will hold a value describing that error.  You should expect errors to be in the
     *      `QCCPBKDF2KeyDerivationErrorDomain` error domain.
     */
    
    private(set) var error: Error?
    
    /*! The number of rounds used to derive the key.
     *  \details This is only meaningful when the operation has finished without error.   If `rounds`
     *      was non-zero, this will be equal to it.  If `rounds` was 0, this will be the actual number
     *      of rounds used to derive the key based on the target time set via `derivationTime`.
     */
    
    private(set) var actualRounds: Int = 0
    
    /*! The derived key.
     *  \details This is only meaningful when the operation has finished without error.   The length
     *      of this key will match `derivedKeyLength`.
     */
    
    private(set) var derivedKeyData: Data?
    
    /*! Initialise the object to derive a key from the specified password..
     *  \param algorithm The specific SHA digest algorithm to use for the key derivation.
     *  \param passwordString The password string from which to derive a key; may be empty.
     *  \param saltData Some random data to salt the key derivation.
     *  \returns The initialised object.
     */
    
    init(algorithm: Algorithm, passwordString: String, saltData: Data) {
        self.algorithm = algorithm
        self.passwordString = passwordString
        self.saltData = saltData
        
        super.init()
        
    }
    
    private func calculateActualRoundsForPasswordLength(_ passwordLength: Int, saltLength _saltLength: Int, ccAlgorithm: CCPseudoRandomAlgorithm) {
        
        var derivationTimeMilliseconds = self.derivationTime * 1000.0
        
        // CCCalibratePBKDF has undocumented limits on the salt length <rdar://problem/13641064>.
        
        var saltLength = _saltLength
        if saltLength == 0 {
            saltLength = 1
        } else if saltLength > 128 {
            saltLength = 128
        }
        
        // Make sure the specified time is not zero and fits into a uint32_t.
        
        if derivationTimeMilliseconds < 1.0 {
            derivationTimeMilliseconds = 1.0
        } else if derivationTimeMilliseconds > Double(UInt32.max) {
            derivationTimeMilliseconds = Double(UInt32.max)
        }
        
        // Do the key derivation.
        
        var result = CCCalibratePBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            passwordLength,
            saltLength,
            ccAlgorithm,
            self.derivedKeyLength,
            UInt32(derivationTimeMilliseconds)
        )
        
        // CCCalibratePBKDF returns undocumented error codes <rdar://problem/13641039>.
        
        if Int32(bitPattern: result) < 0 {
            // Setting actualRounds to 0 triggers an error path in our caller.
            result = 0
        }
        
        // Save the result.  This can't truncate because NSUInteger always has either the same
        // or more range than (unsigned int).
        
        self.actualRounds = Int(result)
    }
    
    override func main() {
        let ccAlgorithm: CCPseudoRandomAlgorithm
        let saltData: Data
        let saltDummy = Data.init(bytes: [0])
        
        assert(self.derivedKeyLength >= 0)
        
        var result = Data(count: self.derivedKeyLength)
        
        let passwordUTFLength = self.passwordString.utf8.count
        
        // Map our algorithm enum to Common Crypto's equivalent.
        
        switch self.algorithm {
        case .sha1:     ccAlgorithm = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        case .sha2_224: ccAlgorithm = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
        case .sha2_256: ccAlgorithm = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .sha2_384: ccAlgorithm = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        case .sha2_512: ccAlgorithm = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }
        
        // If the salt is zero bytes long then saltPtr ends up being NULL.  This causes
        // CCKeyDerivationPBKDF to fail with an error.  We fix this by passing in a
        // pointer a dummy variable in that case.
        
        let saltLength = self.saltData.count
        if saltLength == 0 {
            saltData = saltDummy
        } else {
            saltData = self.saltData
        }
        
        // If the client didn't specify the rounds, calculate one based on the derivation time.
        
        if self.rounds != 0 {
            self.actualRounds = self.rounds
        } else {
            // Note that we only pass in the values that we've already calculated; the method reads
            // various other properties.
            self.calculateActualRoundsForPasswordLength(passwordUTFLength, saltLength: saltLength, ccAlgorithm: ccAlgorithm)
        }
        
        // Check that actualRounds makes sense.
        
        var err = kCCSuccess
        if self.actualRounds == 0 {
            err = kCCParamError
        } else if self.actualRounds > Int(Int32.max) {
            err = kCCParamError
        }
        
        // Do the key derivation and save the results.
        
        if err == kCCSuccess {
            let err32 = saltData.withUnsafeBytes{(saltPtr: UnsafePointer<UInt8>) in
                result.withUnsafeMutableBytes{(mutableBytes: UnsafeMutablePointer<UInt8>) in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordString, passwordUTFLength,
                        saltPtr, saltLength,
                        ccAlgorithm,
                        UInt32(self.actualRounds),
                        mutableBytes,
                        result.count
                    )
                }
            }
            if err32 == -1 {
                // The header docs say that CCKeyDerivationPBKDF returns kCCParamError but that's not the case
                // on current systems; you get -1 instead <rdar://problem/13640477>.  We translate -1, which isn't
                // a reasonable CommonCrypto error, to kCCParamError.
                err = kCCParamError
            }
        }
        if err == kCCSuccess {
            self.derivedKeyData = result
        } else {
            self.error = NSError(domain: QCCPBKDF2KeyDerivationErrorDomain, code: err, userInfo: nil)
        }
    }
    
}

/*! The error domain for the QCCPBKDF2SHAKeyDerivation operation.
 *  \details Codes are Common Crypto error codes, that is, `kCCParamError` and its friends.
 */

let QCCPBKDF2KeyDerivationErrorDomain = "QCCPBKDF2KeyDerivationErrorDomain"
