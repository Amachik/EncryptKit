import Foundation
import CommonCrypto

//PlatformID hooker

let ioregTask = Process()
ioregTask.executableURL = URL(fileURLWithPath: "/usr/sbin/ioreg")
ioregTask.arguments = ["-d2", "-c", "IOPlatformExpertDevice"]

let ioregPipe = Pipe()
ioregTask.standardOutput = ioregPipe

try ioregTask.run()
ioregTask.waitUntilExit()

let ioregData = ioregPipe.fileHandleForReading.readDataToEndOfFile()
let ioregOutput = String(data: ioregData, encoding: .utf8)!

let ioregLines = ioregOutput.components(separatedBy: "\n")
let ioregFilteredLines = ioregLines.filter { $0.contains("IOPlatformUUID") }
let ioregValues = ioregFilteredLines.map { line in
    let fields = line.components(separatedBy: "\"")
    return fields[fields.count - 2]
}

let platformIDUnstripped = ioregValues.first
let platformID = platformIDUnstripped?.replacingOccurrences(of: "-", with: "") ?? "10000000000000000000000000000001"

print(platformID)



//macAddress hooker
let ifconfigTask = Process()
ifconfigTask.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")

let ifconfigPipe = Pipe()
ifconfigTask.standardOutput = ifconfigPipe

try ifconfigTask.run()
ifconfigTask.waitUntilExit()

let ifconfigData = ifconfigPipe.fileHandleForReading.readDataToEndOfFile()
let ifconfigOutput = String(data: ifconfigData, encoding: .utf8)!

let ifconfigLines = ifconfigOutput.components(separatedBy: "\n")
let ifconfigFilteredLines = ifconfigLines.filter { $0.contains("ether") }
let ifconfigValues = ifconfigFilteredLines.map { line in
    let fields = line.components(separatedBy: " ")
    return fields[1]
}

let macAddressUnstripped = ifconfigValues.first
let macAddress = macAddressUnstripped?.replacingOccurrences(of: ":", with: "") ?? "10000000001"
print(macAddress)


//encryption  func
func encryptAES256(data: Data, key: Data, iv: Data) -> Data? {
    let cryptLength = data.count + kCCBlockSizeAES128
    var cryptData = Data(count: cryptLength)
    
    let keyLength = kCCKeySizeAES256
    let options = CCOptions(kCCOptionPKCS7Padding)
    
    var bytesLength = 0
    
    let status = cryptData.withUnsafeMutableBytes { cryptBytes in
        data.withUnsafeBytes { dataBytes in
            key.withUnsafeBytes { keyBytes in
                iv.withUnsafeBytes { ivBytes in
                    CCCrypt(CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            options,
                            keyBytes.baseAddress, keyLength,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, data.count,
                            cryptBytes.baseAddress, cryptLength,
                            &bytesLength)
                }
            }
        }
    }
    
    if status == kCCSuccess {
        cryptData.count = bytesLength
        return cryptData
    }
    return nil
}
//decryption func
func decryptAES256(data: Data, key: Data, iv: Data) -> Data? {
    let cryptLength = data.count + kCCBlockSizeAES128
    var cryptData = Data(count: cryptLength)
    
    let keyLength = kCCKeySizeAES256
    let options = CCOptions(kCCOptionPKCS7Padding)
    
    var bytesLength = 0
    
    let status = cryptData.withUnsafeMutableBytes { cryptBytes in
        data.withUnsafeBytes { dataBytes in
            key.withUnsafeBytes { keyBytes in
                iv.withUnsafeBytes { ivBytes in
                    CCCrypt(CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            options,
                            keyBytes.baseAddress, keyLength,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, data.count,
                            cryptBytes.baseAddress, cryptLength,
                            &bytesLength)
                }
            }
        }
    }
    
    if status == kCCSuccess {
        cryptData.count = bytesLength
        return cryptData
    }
    return nil
}


extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

//your vendor id
let vendorID = "00000000000000000000000000000000"

//let vendorID = UIDevice.current.identifierForVendor?.uuidString ?? "UID not Found"

let concatenatedData = macAddress + vendorID + platformID

let keyQueue = DispatchQueue(label: "keyQueue")
let dataToEncrypt = concatenatedData.data(using: .utf8)!
var key = Data(count: kCCKeySizeAES256)
var iv = Data(count: kCCBlockSizeAES128)

keyQueue.sync {
   _ = key.withUnsafeMutableBytes { keyBytes in
        SecRandomCopyBytes(kSecRandomDefault, keyBytes.count, keyBytes.baseAddress!)
    }
   _ = iv.withUnsafeMutableBytes { ivBytes in
        SecRandomCopyBytes(kSecRandomDefault, ivBytes.count, ivBytes.baseAddress!)
    }
}



let dataQueue = DispatchQueue(label: "dataQueue")

dataQueue.sync {
    let dataToEncrypt = concatenatedData.data(using: .utf8)!
    let encryptedData = encryptAES256(data: dataToEncrypt, key: key, iv: iv)!
    let decryptedData = decryptAES256(data: encryptedData, key: key, iv: iv)!
    let decryptedString = String(data: decryptedData, encoding: .utf8)
    
    let keyHex = key.map { String(format: "%02x", $0) }.joined()
    let ivHex = iv.map { String(format: "%02x", $0) }.joined()

    print("Original String: \(concatenatedData)")
    print("Encrypted Data: \(encryptedData.hexEncodedString())")

    print("Key: \(keyHex)")
   
    print("Iv:\(ivHex)")
    


}
