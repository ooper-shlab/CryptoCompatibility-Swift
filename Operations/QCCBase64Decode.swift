//
//  QCCBase64Decode.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/6.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Implements Base64 decoding.
 */

import Foundation

// Decodes a Base64 string to data.  This does not do anything particularly clever
// (it does skip whitespace but, for example, it won't skip a PEM header or PEM footer).

/*! Decodes a Base64 string to data.
 *  \details This only handles plain Base64 data.  Specifically, it has not skip whitespace,
 *      nor will it deal with PEM headers and footers.
 */

class QCCBase64Decode: Operation {
    
    /*! The data to decode.
     *  \details This is set by the init method.
     */
    
    let inputString: String
    
    /*! The decode data.
     *  \details This is set when the operation is finished.  This will be nil if there was
     *      an error decoding the Base64 string.
     */
    
    private(set) var outputData: Data?
    
    /*! Initialise the object to decide the supplied string.
     *  \param inputString The data to encode; this may be empty.
     *  \returns The initialised object.
     */
    
    init(input inputString: String) {
        self.inputString = inputString
        
        super.init()
        
    }
    
    override func main() {
        self.outputData = Data(base64Encoded: self.inputString, options: .ignoreUnknownCharacters)
    }
    
}
