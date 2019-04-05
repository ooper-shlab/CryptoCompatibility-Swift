//
//  GetOptLong.swift
//  OOPUtils
//
//  Created by OOPer in cooperation with shlab.jp, on 2014/12/16.
//  Updated for Swift 3 on 2016/12/9
//  Updated for Swift 5 on 2019/4/5
//  Copyright (c) 2014-2019 OOPer (NAGATA, Atsuyuki). All rights reserved.
//

import Foundation

open class GetoptLong {
    public typealias OptionsType = (name: String, hasArg: Bool, argIsOptional: Bool, key: String)
    public typealias ArgumentType = (value: String?, isDefault: Bool)
    enum GetoptErrorType {
        case missingArg //Cannot find an argument for the option.
        case notOption //begins with "--" or "-", but does not contain option characters.
    }
    
    private var argv: [String] = []
    
    private(set) var shortopts: [String: OptionsType] = [:]
    private(set) var longopts: [String: OptionsType] = [:]
    
    private var optargs: [String: ArgumentType] = [:]
    private var nonOptionsArgs: [String] = []
    private(set) var errors: [(arg: String, error: GetoptErrorType)] = []
    
    /// See man page of getopt for shortopts, getopt_long for longopts
    public init(shortopts: String = "", longopts: [OptionsType] = []) {
        var index = shortopts.startIndex
        while index < shortopts.endIndex {
            let key = String(shortopts[index])
            let next = shortopts.index(after: index)
            var hasArg = false
            var argIsOptional = false
            if next < shortopts.endIndex && shortopts[next] == ":" {
                index = next
                hasArg = true
                let nextToNext = shortopts.index(after: next)
                if nextToNext < shortopts.endIndex && shortopts[nextToNext] == ":" {
                    argIsOptional = true
                    index = nextToNext
                }
            }
            self.shortopts[key] = (key, hasArg, argIsOptional, key)
            
            shortopts.formIndex(after: &index)
        }
        for longopt in longopts {
            self.longopts[longopt.name] = longopt
        }
    }
    
    public func processOptions(arguments: [String] = CommandLine.arguments, startIndex: Int = 1) {
        self.argv = arguments
        var optionFinished = false
        var i = startIndex
        while i < argv.count  {
            let arg = argv[i]
            if optionFinished {
                nonOptionsArgs.append(arg)
            } else if arg == "--" {
                optionFinished = true
            } else if arg.hasPrefix("--") {
                let n = processLongOption(i, arg)
                if n >= 0 {i += n}
            } else if arg == "-" {
                nonOptionsArgs.append(arg)
            } else if arg.hasPrefix("-") {
                let n = processShortOption(i, arg)
                if n >= 0 {i += n}
            } else {
                nonOptionsArgs.append(arg)
            }
            i += 1
        }
    }
    
    private func processLongOption(_ i: Int, _ arg: String) -> Int {
        let argName = String(arg.dropFirst(2))
        if let opt = longopts[argName] {
            if opt.hasArg {
                if i + 1 < argv.count && !isOption(argv[i + 1]) {
                    optargs[opt.key] = (argv[i + 1], false)
                    return 1    //skip 1 arg
                } else {
                    errors.append((arg: arg, error: GetoptErrorType.missingArg))
                    return -1
                }
            } else {
                optargs[opt.key] = (nil, true)  //default value
            }
        } else {
            errors.append((arg: arg, error: GetoptErrorType.notOption))
        }
        return 0
    }
    
    private func isOption(_ arg: String) -> Bool {
        return arg != "-" && arg.hasPrefix("-")
    }
    
    private func processShortOption(_ i: Int, _ arg: String) -> Int {
        let argName = String(arg.dropFirst())
        //temporal restriction
        if argName.count > 1 {
            for index in argName.indices {
                let optChar = String(argName[index])
                if let opt = shortopts[optChar] {
                    if opt.hasArg {
                        if argName.index(after: index) < argName.endIndex {
                            optargs[opt.key] = (String(argName[argName.index(after: index)...]), false)
                            return 0    //skip 0 arg
                        } else if i + 1 < argv.count && !isOption(argv[i + 1]) {
                            optargs[opt.key] = (argv[i + 1], false)
                            return 1    //skip 1 arg
                        } else if opt.argIsOptional {
                            optargs[opt.key] = ("", true)
                            return 0
                        } else {
                            let error = (arg: optChar, error: GetoptErrorType.missingArg)
                            errors.append(error)
                            return -1
                        }
                    } else {
                        optargs[opt.key] = (nil, true)  //default value
                        return 0
                    }
                } else {
                    let error = (arg: optChar, error: GetoptErrorType.notOption)
                    errors.append(error)
                    return -1
                }
            }
        }
        if let opt = shortopts[argName] {
            if opt.hasArg {
                if i + 1 < argv.count && !isOption(argv[i + 1]) {
                    optargs[opt.key] = (argv[i + 1], false)
                    return 1    //skip 1 arg
                } else if opt.argIsOptional {
                    optargs[opt.key] = ("", true)
                    return 0
                } else {
                    errors.append((arg: arg, error: GetoptErrorType.missingArg))
                    return -1
                }
            } else {
                optargs[opt.key] = ("", true)  //default value
            }
        } else {
            errors.append((arg: arg, error: GetoptErrorType.notOption))
        }
        return 0
    }
    
    /// Returns args without options
    open var args: [String] {
        return self.nonOptionsArgs
    }
    
    open var options: [String: ArgumentType] {
        return self.optargs
    }
    
    /// Returns option value for key
    open func option(_ key: String) -> String? {
        if let optarg = self.options[key] {
            return optarg.value
        }
        return nil
    }
}
