import SwiftUI
import IOSSecuritySuite
import Foundation
import CommonCrypto

struct ContentView: View {
    @State private var isTampered: Bool?
    @State private var tamperStatusText = ""
    let expectedProvisionHash = "2976c70b56e9ae1e2c8e8b231bf6b0cff12bbbd0a593f21846d9a004dd181be3"
    let expectedMachOHash = "6d8d460b9a4ee6c0f378e30f137cebaf2ce12bf31a2eef3729c36889158aa7fc"
    let expectedBundleId = "com.xplo8E.IOSSecurityApp"
    @State private var resultText: AttributedString = AttributedString("Tap a button to run a security check")
    
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Text("IOSSecuritySuite Checks")
                    .font(.title)
                    .padding()
                
                Text(resultText)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.gray.opacity(0.2))
                    .cornerRadius(10)
                
                  Button("Check Tamper/Intigrity ") {checkIntegrity()}
                Button("Show BundleId") {showBundleId()}
                Button("Provision file Hash") {showHashOfProvision()}
                Button("Show Binary Hash") {getBinaryHash()}
            }
            .padding()
        }
    }
    
    
    func showBundleId() {
        resultText = "App BundleId: \n"
        let ManualBundleId = Bundle.main.bundleIdentifier ?? "Invalid"
        resultText += AttributedString(ManualBundleId)
    }
    
    func showHashOfProvision() {
        
        var ManualProvisionFileHash = "Error"
        let path = Bundle.main.path(
          forResource: "embedded", ofType: "mobileprovision"
        ) ?? "Error"
        
        let nsPath = NSString(string: path)
        let provFilename = nsPath.lastPathComponent
        
        let url = URL(fileURLWithPath: path)
        
        if FileManager.default.fileExists(atPath: url.path) {
          if let data = FileManager.default.contents(atPath: url.path) {
            // Hash: SHA256
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            data.withUnsafeBytes {
              _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
            }
            
            ManualProvisionFileHash = Data(hash).hexEncodedString()
          }
        }
        resultText = AttributedString("File: " + provFilename + "\n")
        resultText += AttributedString("File Hash: \n")
        resultText += AttributedString(ManualProvisionFileHash)
    }

    func getBinaryHash() {
        let frameworkHash = IOSSecuritySuite.getMachOFileHashValue(.custom("IOSSecuritySuite")) ?? "error"
        resultText = AttributedString("IOSSecuritySuite hash: \n")
        resultText += AttributedString(frameworkHash + "\n")
        let mainBinaryhash = IOSSecuritySuite.getMachOFileHashValue(.default) ?? "error"
        resultText += AttributedString("Main Binary hash: \n")
        resultText += AttributedString(mainBinaryhash + "\n")
    }
    
    func checkIntegrity() {
        let tamperCheck = IOSSecuritySuite.amITampered([.bundleID(expectedBundleId),
                                                        .mobileProvision(expectedProvisionHash),
                                                        .machO("IOSSecuritySuite", expectedMachOHash)])
        isTampered = tamperCheck.result
        tamperStatusText = isTampered == true ? "Have been Tampered." : "Have not been Tampered."
        
        let IOSSecHashValue = IOSSecuritySuite.getMachOFileHashValue(.custom("IOSSecuritySuite")) ?? "Invalid"
        let mainBinaryHash = IOSSecuritySuite.getMachOFileHashValue(.default) ?? "Invalid"
        
        
        let tamperStatus = isTampered == true ? "Have been Tampered." : "Have not been Tampered."
        var attributedString = AttributedString(tamperStatus + "\n\n")
        attributedString.foregroundColor = isTampered == true ? .red : .green
        attributedString.font = .boldSystemFont(ofSize: 16)

        let detailsString = """
        Details:
        
        Expected IOSSec hash:
        \(expectedMachOHash)

        Frmwk hash:
        \(IOSSecHashValue)

        Expected provision hash:
        \(expectedProvisionHash)

        Actual provision hash:
        \(getProvisionHash())

        Expected BundleId:
        \(expectedBundleId)

        Actual BundleId:
        \(Bundle.main.bundleIdentifier ?? "Invalid")

        Main Binary hash:
        \(mainBinaryHash)

        """
        
        attributedString += AttributedString(detailsString)

        resultText = attributedString

    }
    
    func getProvisionHash() -> String {
        let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") ?? "Error"
        let url = URL(fileURLWithPath: path)
        
        if FileManager.default.fileExists(atPath: url.path),
           let data = FileManager.default.contents(atPath: url.path) {
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            data.withUnsafeBytes {
                _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
            }
            return Data(hash).hexEncodedString()
        }
        return "Error: Unable to calculate provision hash"
    }
}


struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
            .previewDevice("iPhone 7")
            .previewLayout(.sizeThatFits)
    }
}

extension Data {
  fileprivate func hexEncodedString() -> String {
    return map { String(format: "%02hhx", $0) }.joined()
  }
}

