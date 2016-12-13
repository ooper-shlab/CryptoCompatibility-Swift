//
//  ToolCommon.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/9.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Utilities used by various tool commands.
 */

import Foundation

/*! description
 *  \details Utilities used by various tool commands and tests.
 */

class ToolCommon {
    
    /*! Instance shared between all the tool commands and tests.
     */
    
    static let shared: ToolCommon = ToolCommon()
    
    /*! Controls the behaviour of `-synchronouslyRunOperation:`.
     */
    
    var debugRunOpOnMainThread: Bool = false
    
    let queue: OperationQueue = OperationQueue()
    
    deinit {
        fatalError()
    }
    
    /*! Runs the supplied operation synchronously.
     *  \details This has two modes.  If `debugRunOpOnMainThread` is NO, it runs
     *      the operation on a default operation queue and then waits for it to
     *      complete.  OTOH, if it's YES, it actually calls the `-main` method of the
     *      operation directly.  The later is used by the tool (when in debug mode) and
     *      the unit tests to ensure that everything runs on the main thread.
     */
    
    func synchronouslyRun(operation op: Operation) {
        if self.debugRunOpOnMainThread {
            // This is the hacky way we do it to simplify debugging.
            op.main()
        } else {
            // This is how it /should/ be done.
            self.queue.addOperation(op)
            self.queue.waitUntilAllOperationsAreFinished()
        }
    }
    
}
