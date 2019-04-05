//
//  QHex.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/9.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Hex dump utilities.
 */

import Foundation

/*! Hex dump utilities.
 */

class QHex {
    
    /*! Converts a buffer of bytes to a hex string.
     *  \param bytes The start of the buffer.
     *  \param length The length of the buffer.
     *  \returns A hex string, all lower case, with no spaces.
     */
    
    class func hexString(bytes: UnsafeRawPointer, length: Int) -> String {
        
        var result = ""
        result.reserveCapacity(length * 2)
        for i in 0..<length {
            result += String(format: "%02x", bytes.load(fromByteOffset: i, as: UInt8.self))
        }
        return result
    }
    
    /*! Converts a data object to a hex string.
     *  \param data The data object.
     *  \returns A hex string, all lower case, with no spaces.
     */
    
    class func hexString(data: Data) -> String {
        return data.withUnsafeBytes {bytes in
            self.hexString(bytes: bytes.baseAddress!, length: bytes.count)
        }
    }
    
    /*! Converts a hex string to a data object.
     *  \param hexString A hex string, using upper or lower case, with no spaces.
     *  \returns A data object holding the bytes described by the hex string, or
     *      nil if there was a problem parsing the string.
     */
    
    class func optionalData(hex hexString: String) -> Data? {
        
        var result: Data? = nil
        var cursor = hexString.startIndex
        let limit = hexString.endIndex
        if hexString.count % 2 == 0 {
            result = Data()
            
            while cursor != limit {
                
                let next = hexString.index(cursor, offsetBy: 2)
                guard let thisByte = UInt8(hexString[cursor..<next], radix: 16) else {
                    result = nil
                    break
                }
                result!.append(thisByte)
                cursor = next
            }
        }
        
        return result
    }
    
    /*! Converts a known good hex string to a data object.
     *  \details This is used extensively by the unit tests, where the hex strings are
     *      hard wired and thus known to be good.
     *  \param hexString A hex string, using upper or lower case, with no spaces.
     *  \returns A data object holding the bytes described by the hex string.  This
     *      will trap if the hex string can't be parsed.
     */
    
    class func data(hex hexString: String) -> Data {
        
        let result = self.optionalData(hex: hexString)!
        return result
    }
    
}
