//
//  LocalAuthenticationHelper.swift
//
//  Created by Developer on 30.01.2018.
//

import Foundation
import LocalAuthentication

/**
 Important
 
 You are required to include the NSFaceIDUsageDescription key in your app's Info.plist file if your app allows biometric authentication. If that key is not present, authorization requests may fail immediately.
 */

enum BiometricType {
    case none
    case touch
    case face
}

class LocalAuthenticationHelper {

    static let biometricPermissions = "Get access for use"

    //MARK: - Main Functions
    
    class func getBiometricsAccessFor(_ reason: String, _ completion: @escaping (_ success: Bool, _ error: LAError?) -> ()) {
        getLocalAuthenticationAccess(reason, true, completion)
    }
    

    class func getAccessFor(_ reason: String, _ completion: @escaping (_ success: Bool, _ error: LAError?) -> ()) {
        getLocalAuthenticationAccess(reason, false, completion)
    }
    
    class func isFaceIdAllowed() -> Bool {
        return biometricType() == .face
    }
    
    class func isTouchIdAllowed() -> Bool {
        return biometricType() == .touch
    }
    
    class func isBiometryAllowed() -> Bool {
        return !(biometricType() == .none)
    }
    
    ///getting biometric type of current device
    class func biometricType() -> BiometricType {
        let authContext = LAContext()
        if #available(iOS 11.0, *) {
            let _ = authContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            switch(authContext.biometryType) {
            case .none:
                return .none
            case .touchID:
                return .touch
            case .faceID:
                return .face
            }
        } else {
            return authContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) ? .touch : .none
        }
    }
    
    ///check if device can usage biometric
    class func canUseBiometric() -> (success: Bool, error: Error?) {
        guard UIDevice.isSimulator == false else { return (true, nil) }
        let myContext = LAContext()
        var authError: NSError?
        if myContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) {
            return (true, nil)
        } else {
            return (false, authError)
        }
    }
    
    ///getting  error description for biometric errors
    class func getErrorDescription(error: LAError) -> String {
        if #available(iOS 11.0, *) {
            switch error.code {
            case LAError.biometryNotAvailable:
                return "This app does not supported for your device"
            case LAError.biometryNotEnrolled:
                return "Please setup your Biometric functionality"
            default:
                return error.localizedDescription
            }
        } else {
            switch error.code {
            case LAError.touchIDNotAvailable:
                return "This app does not supported for your device"
            case LAError.touchIDNotEnrolled:
                return "Please setup your TouchID functionality"
            default:
                return error.localizedDescription
            }
        }
    }
    
    ///block app if were too many failed biometry attempts and biometry is now locked
    class func blockApp(error: LAError?, from vc: BaseViewController?) -> Bool {
        
        if error != nil {
            if #available(iOS 11.0, *) {
                if error?.code == LAError.biometryLockout {
                    InformationViewController.shared.present(from: vc)
                    return true
                }
            } else {
                if error?.code == LAError.touchIDLockout {
                    InformationViewController.shared.present(from: vc)
                    return true
                }
            }
        } else {
            InformationViewController.shared.dismiss()
            return false
        }
        return false
    }
    
    //MARK: - Private
    
    fileprivate class func getLocalAuthenticationAccess(_ localizedReason: String, _ mustBiometricsUsage: Bool, _ completion: @escaping (_ success: Bool, _ error: LAError?) -> ()) {
        
        guard UIDevice.isSimulator == false else { completion(true, nil); return }
        
        let myContext = LAContext()
        if mustBiometricsUsage {
            myContext.localizedFallbackTitle = "";
        }
        
        var authError: NSError?
        
        if myContext.canEvaluatePolicy(mustBiometricsUsage ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication, error: &authError) {
            myContext.evaluatePolicy(mustBiometricsUsage ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication, localizedReason: localizedReason) { success, evaluateError in
                
                let error = evaluateError as? LAError
                if success {
                    // User authenticated successfully, take appropriate action
                    completion(success, error)
                } else {
                    // User did not authenticate successfully, look at error and take appropriate action
                    completion(success, error)
                }
            }
        } else {
            // Could not evaluate policy; look at authError and present an appropriate message to user
            completion(false, authError as? LAError)
        }
    }
}

