//
//  AESGCMEncrypter.swift
//  JOSESwift
//
//  Created by Amit Vaghela on 24/6/19.
//

import Foundation
import CryptoSwift


/// A `SymmetricEncrypter` to encrypt plaintext with an `AES` algorithm.
internal struct AESGCMEncrypter: SymmetricEncrypter {
    typealias KeyType = AES.KeyType
    
    let algorithm: SymmetricKeyAlgorithm
    let symmetricKey: KeyType?
    
    init(algorithm: SymmetricKeyAlgorithm, symmetricKey: KeyType? = nil) {
        self.algorithm = algorithm
        self.symmetricKey = symmetricKey
    }
    
    func encrypt(_ plaintext: Data, with symmetricKey: Data, additionalAuthenticatedData: Data) throws -> SymmetricEncryptionContext {
        // Generate random intitialization vector.
        let iv = try SecureRandom.generate(count: algorithm.initializationVectorLength)
        
        let encryptionKey = symmetricKey
        
        let gcm = GCM(
            iv: iv.bytes,
            additionalAuthenticatedData: additionalAuthenticatedData.bytes,
            tagLength: 16,
            mode: .detached)
        
        let aes = try CryptoSwift.AES(key: encryptionKey.bytes, blockMode: gcm, padding: .noPadding)
        
        // Encrypt the plaintext with a symmetric encryption key, a symmetric encryption algorithm and an initialization vector.
        let cipherText = try Data(aes.encrypt([UInt8](plaintext)))
        
        let authenticationTag = Data(gcm.authenticationTag!)
                
        return SymmetricEncryptionContext(
            ciphertext: cipherText,
            authenticationTag: authenticationTag,
            initializationVector: iv
        )
    }
}
