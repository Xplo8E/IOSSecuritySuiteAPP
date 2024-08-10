import SwiftUI
import IOSSecuritySuite
import Foundation
import CommonCrypto

struct ContentView: View {
    @State private var isTampered: Bool?
    @State private var tamperStatusText = ""
    @State private var expectedProvisionHash: String?
    @State private var expectedMachOHash: String?
    @State private var expectedBundleId: String?
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
        .onAppear {
            Task {
                await fetchAllData()
            }
        }
    }
    
//    //            "",
//    "",
//    ""
    
    
    func fetchAllData() async {
        await fetchProvisionHash()
        await fetchMachOHash()
        await fetchBundleId()
    }
    
    func fetchProvisionHash() async {
        await fetchData(from: "https://raw.githubusercontent.com/Xplo8E/IOSSecuritySuiteAPP/master/IOSSecurityApp/Values/ProvisionHash") { result in
            self.expectedProvisionHash = result
        }
    }
    
    func fetchMachOHash() async {
        await fetchData(from: "https://raw.githubusercontent.com/Xplo8E/IOSSecuritySuiteAPP/master/IOSSecurityApp/Values/MachOHash") { result in
            self.expectedMachOHash = result
        }
    }
    
    func fetchBundleId() async {
        await fetchData(from: "https://raw.githubusercontent.com/Xplo8E/IOSSecuritySuiteAPP/master/IOSSecurityApp/BundleId") { result in
            self.expectedBundleId = result
        }
    }
    
    func fetchData(from urlString: String, completion: @escaping (String?) -> Void) async {
        guard let url = URL(string: urlString) else {
            print("Invalid URL: \(urlString)")
            completion(nil)
            return
        }
        
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            print("Response: \(response)")
            let result = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            print("Fetched data: \(result ?? "nil")")
            DispatchQueue.main.async {
                completion(result)
            }
        } catch {
            print("Error fetching data from \(urlString): \(error)")
            DispatchQueue.main.async {
                completion(nil)
            }
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
        guard let expectedProvisionHash = expectedProvisionHash,
              let expectedMachOHash = expectedMachOHash,
              let expectedBundleId = expectedBundleId else {
            print("Expected data not loaded. ProvisionHash: \(expectedProvisionHash ?? "nil"), MachOHash: \(expectedMachOHash ?? "nil"), BundleId: \(expectedBundleId ?? "nil")")
            resultText = AttributedString("Error: Server expected data not loaded")
            return
        }
        
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

