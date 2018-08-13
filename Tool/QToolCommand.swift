//
//  QToolCommand.swift
//  CryptoCompatibility
//
//  Translated by OOPer in cooperation with shlab.jp, on 2016/12/7.
//
//
/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information

    Abstract:
    Command line tool infrastructure.
 */

import Foundation

// IMPORTANT: This module is based on <x-man-page://3/getopt> and, as such, is only safe to use from the main thread.
//### Swift version of this module is re-written using OOPUtils.GetoptLong. You can use this module from non-main threads, though, not thread safe.

/*! Implements a single command line tool command
 *  \details This is an abstract class intended to be subclassed in order to implement
 *      a subcommand within a command line tool.  You can subclass it directly, for a
 *      simple command, or via the QComplexToolCommand subclass for commands that themselves
 *      have subcommands.
 *
 *      To implement the simplest possible command:
 *
 *      1. subclass QToolCommand
 *
 *      2. override `+commandName` and `+commandUsagae` to describe the command
 *
 *      3. override `-runError:` to implement the command
 *
 *      To support options:
 *
 *      4. override `-commandOptions` to indicate the options you support
 ### Do not override `commandOptions` directly. Instead, override `optionFuncs` and `optionFuncsWithArg` properly.
 *
 *      5. for each option, implement either a `-setOption_X` method or a
 *          `-setOption_X_argument:` method, depending on whether the option takes an
 *          argument or not
 *
 *      Finally, if appropriate:
 *
 *      6. override `+validateOptionsAndArguments:`, have the override call super, and
 *          then, on return, check that the final options and arguments are self consistent
 *
 *  \warning This module is based on <x-man-page://3/getopt> and, as such, is only safe
 *      to use from the main thread.
 */

class QToolCommand {
    
    private(set) var arguments: [String]
    
    required init() {
        self.arguments = []     // because it's marked as non-null
    }
    
    /*! Returns the name of the command.
     *  \details You must override this method to return the name of this command.
     *
     *      The default implementation throws.
     *  \returns The name of this specific command.
     */
    
    class var commandName: String {
        fatalError("implementation required")
    }
    
    /*! Returns the command's usage.
     *  \details You must override this method to return the usage for this command.
     *
     *      The default implementation throws.
     *  \returns The usage for this specific command.
     */
    
    class var commandUsage: String {
        fatalError("implementation required")
    }
    
    /*! Called to validate the command's options and arguments
     *  \details You may override this method to customise your command's option and argument
     *      processing.  The default a) parses options as per the methods below, and b)
     *      saves the remaining arguments to the `arguments` property.  You may override this
     *      to do special processing, for example, to check the argument count, handle inter-option
     *      dependencies, or process subcommands.  It often makes sense for the override to call
     *      super.
     *  \param optionsAndArguments The options and arguments supplied to this command.
     *  \returns Return NO to indicate a usage error, or YES otherwise.
     */
    
    func validate(optionsAndArguments: [String]) -> Bool {
        
        let commandOptionsCStr = self.commandOptions
        let opt = GetoptLong(shortopts: commandOptionsCStr)
        opt.processOptions(arguments: optionsAndArguments, startIndex: 0)
        var success = opt.errors.isEmpty
        for (option, optarg) in opt.options {
            if !success {break}
            if let optargStr = optarg.value {
                success = self.setOption(option, argument: optargStr)
            } else {
                self.setOption(option)
            }
        }
        
        // Save away the remaining arguments.
        
        if success {
            self.arguments = opt.args
        }
        
        // Clean up.
        
        return success
    }
    
    /*! Returns an options and arguments array from .
     *  \details This basically involves converting each element of the array to an NSString and
     *      building these strings into an array.
     *
     *      The first item of the array is ignored, as is standard for UNIX tools.
     *
     *      \warning This will return nil if any item in the array isn't valid UTF-8.
     *  \param argc The argument count as passed to `main`.
     *  \param argv The argument strings as passed to `main`.
     *  \returns An options and arguments array which, if it's not nil, is suitable to pass
     *      to `-validateOptionsAndArguments:`.
     */
    //### We want to work with `CommandLine.arguments` rather than "the classic UNIX argc/argv pair".
    
    static func optionsAndArguments(fromCommandLineArguments arguments: [String] = CommandLine.arguments) -> [String] {
        
        return Array(arguments.dropFirst())
    }
    
    /*! Runs the command.
     *  \details You must override this method and provide an implementation of the command.
     *
     *      The default implementation throws.
     *  \important Do not do usage checking here.  Instead you should do that in
     *      `-validateOptionsAndArguments:`.
     *  \param errorPtr A standard Cocoa error argument.
     *  \returns Return YES if the command was successful, or NO to indicate an error
     *      running the command.  If you return NO and `errorPtr` is not NULL, you must set
     *      `*errorPtr` to the error.
     */
    
    func run() throws {
        fatalError("implementation required")
    }
    
    /*! Returns a `getopt`-compatible options string.
     *  \details If you do default option and argument processing per `-validateOptionsAndArguments:`,
     *      you must enable each of your options by listing it in the result of this method.  In
     *      addition, to learn about the option being set you must override one of the following
     *      methods (or implementing the methods that they dynamic dispatch to).
     *
     *      The default implementation return the empty string.
     *  \returns A `getopt`-compatible options string.
     */
    
    //### Do not override this property directly. Instead, override `optionFuncs` and `optionFuncsWithArg` properly.
    var commandOptions: String {
		return type(of: self).optionFuncs.keys.joined(separator: ":") +
            type(of: self).optionFuncsWithArg.keys.map{$0+":"}.joined()
    }
    class var optionFuncs: [String: (QToolCommand)->()->Void] {
        return [:]
    }
    class var optionFuncsWithArg: [String: (QToolCommand)->(String)->Bool] {
        return [:]
    }
    
    /*! Sets the specified no-argument option.
     *  \details The default implementation looks for method `-setOption_X` (where X is the option
     *      character) and calls that if it's available.  If that method isn't present, the
     *      implementation throws.
     *
     *      This can't trigger a usage error because each option is specifically enabled via
     *      `-commandOptions` and there's no argument that could be wrong.  Inter-option usage
     *      checking should be done in a `-validateOptionsAndArguments:` override.
     *  \param option Holds the option as it would be returned by <x-man-page://3/getopt>.
     */
    
    func setOption(_ option: String) {
        
        if let optionFunc = type(of: self).optionFuncs[option] {
            optionFunc(self)()
        } else {
            fatalError("-setOption_X method not found")
        }
    }
    
    /*! Sets the specified option to the supplied argument.
     *  \details The default implementation looks for method `-setOption_X_argument:`
     *      (where X is the option character) and calls that.  If that method isn't present,
     *      the implementation throws.
     *
     *      This can trigger a usage error because there might be a problem with the argument.
     *  \param option Holds the option as it would be returned by <x-man-page://3/getopt>.
     *  \returns Return NO to indicate a usage error, or YES otherwise.
     */
    
    func setOption(_ option: String, argument: String) -> Bool {
        
        if let optionFuncWithArg = type(of: self).optionFuncsWithArg[option] {
            return optionFuncWithArg(self)(argument)
        } else {
            fatalError("-setOption_X_argument: method not found")
        }
    }
    
}

/*! Implements a complex command line tool command
 *  \details This is an abstract class intended to be subclassed in order to implement
 *      a complex command within a command line tool, that is, a command that itself has
 *      subcommands.  Subclassing this command is very simple in the typical case:
 *      in your subclass, implement the `+subcommandClasses` method to return the list of
 *      subcommands available.
 *
 *  \warning This module is based on <x-man-page://3/getopt> and, as such, is only safe
 *      to use from the main thread.
 */

class QComplexToolCommand: QToolCommand {
    
    private var subcommand: QToolCommand?
    
    /*! Returns a list of classes, each of which is a subcommand of this command.
     *  \details To use this class you must implement this method to return a list of command
     *      classes.  Do not call super; the default implementation throws.
     *  \returns A list of QToolCommand subclasses.
     */
    
    class var subcommandClasses: [QToolCommand.Type] {
        fatalError("implementation required")
    }
    
    /*! Returns the command's usage.
     *  \details The default implementation returns the usage of each of the subcommands, separated
     *      by "\n".  It would be reasonable to override this to do more complex formatting.
     *  \returns Usage for the complex command.
     */
    
    override class var commandUsage: String {
        
        return self.subcommandClasses.map{$0.commandUsage}.joined(separator: "\n")
    }
    
    override func validate(optionsAndArguments: [String]) -> Bool {
        var subcommandArguments: [String] = []
        
        var success = super.validate(optionsAndArguments: optionsAndArguments)
        if success {
            success = (self.arguments.count != 0)      // must have enough for a subcommand
        }
        if success {
            let subcommandName = self.arguments[0]
            subcommandArguments = Array(self.arguments.dropFirst())
            
            self.subcommand = type(of: self).subcommandClasses.first {$0.commandName == subcommandName}?.init()
            success = (self.subcommand != nil)
        }
        if success {
            success = self.subcommand!.validate(optionsAndArguments: subcommandArguments)
        }
        
        return success
    }
    
    override func run() throws {
        assert(self.subcommand != nil)
        try self.subcommand!.run()
    }
    
}
