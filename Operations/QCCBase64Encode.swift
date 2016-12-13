//
//  QCCBase64Encode.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/6.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Implements Base64 encoding.
 */

import Foundation

/*! Encodes data as a Base64 string.
 *  \details This is a vanilla encoding; it does not do anything especially clever, like
 *      deal PEM headers and footers.
 */

class QCCBase64Encode: Operation {
    
    /*! The data to encode.
     *  \details This is set by the init method.
     */
    
    let inputData: Data
    
    /*! Determines whether line breaks are added.
     *  \details If true, UNIX style line breaks (LF) are added at column 64 as is traditional
     *      for PEM.
     */
    
    var addLineBreaks: Bool = false
    
    /*! The output Base64 string.
     *  \details This is set when the operation is finished.
     */
    
    private(set) var outputString: String? = nil
    
    /*! Initialise the object to encode the supplied data.
     *  \param inputData The data to encode; this may be empty.
     *  \returns The initialised object.
     */
    
    init(input inputData: Data) {
        self.inputData = inputData
        
        super.init()
        
    }
    
    override func main() {
        
        var options = NSData.Base64EncodingOptions.endLineWithLineFeed
        if self.addLineBreaks {
            options.formUnion(.lineLength64Characters)
        }
        var output = self.inputData.base64EncodedString(options: options)
        
        // Our old code use to always add a trailing LF unless the input was empty,
        // and our unit test relies on that, so we replicate it here.
        
        if output.characters.count > 0 && !output.hasSuffix("\n") {
            output += "\n"
        }
        self.outputString = output
    }
    
}
