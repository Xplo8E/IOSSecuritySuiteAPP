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
    @State private var expectedMainBinaryHash: String?
    @State private var expectedIOSSecuritySuiteHash: String?
    @State private var resultText: AttributedString = AttributedString("Tap a button to run a security check")
    @State private var resultSec: String = ""
    
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
                
                Text(resultSec)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.gray.opacity(0.2))
                    .cornerRadius(10)
                
                Button("Check Tamper/Intigrity ") {checkIntegrity()}
                Button("Check Integrity of App") {checkAppIntegrity()}
                Button("Show BundleId") {showBundleId()}
                Button("Provision file Hash") {showHashOfProvision()}
                Button("Show Binary Hash") {getBinaryHash()}
//                Button("call findSection() func") {callFindSection()}
                Button("Main Binary Hash") {getMainBinHash()}
                Button("Frmwrk Hash") {getFrmwkHash()}
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
    
    func getMainBinHash() {

        let mainBinaryhash = IOSSecuritySuite.getMachOFileHashValue(.default) ?? "error"
    
        resultText = AttributedString("Main Binary hash: \n")
        resultText += AttributedString(mainBinaryhash + "\n")
    }
    
    func getFrmwkHash() {
        let frameworkHash = IOSSecuritySuite.getMachOFileHashValue(.custom("IOSSecuritySuite")) ?? "error"
        resultText = AttributedString("IOSSecuritySuite hash: \n")
        resultText += AttributedString(frameworkHash + "\n")
    }
    
    func fetchAllData() async {
            await fetchProvisionHash()
            await fetchMachOHash()
            await fetchBundleId()
            await fetchMainBinaryHash()
            
            // Print the results after all fetches are complete
            print("ProvisionHash: \(expectedProvisionHash ?? "nil"), MachOHash: \(expectedMachOHash ?? "nil"), BundleId: \(expectedBundleId ?? "nil"), MainBinaryHash: \(expectedMainBinaryHash ?? "nil")")
        }
        
        func fetchProvisionHash() async {
            await fetchData(from: "https://raw.githubusercontent.com/Xplo8E/IOSSecuritySuiteAPP/master/Values/ProvisionHash") { result in
                self.expectedProvisionHash = result
                print("Set expectedProvisionHash to: \(result ?? "nil")")
            }
        }
        
        func fetchMachOHash() async {
            await fetchData(from: "https://raw.githubusercontent.com/Xplo8E/IOSSecuritySuiteAPP/master/Values/MachOHash") { result in
                self.expectedMachOHash = result
                print("Set expectedMachOHash to: \(result ?? "nil")")
            }
        }
        
        func fetchBundleId() async {
            await fetchData(from: "https://raw.githubusercontent.com/Xplo8E/IOSSecuritySuiteAPP/master/Values/BundleId") { result in
                self.expectedBundleId = result
                print("Set expectedBundleId to: \(result ?? "nil")")
            }
        }
        
        func fetchMainBinaryHash() async {
            await fetchData(from: "https://raw.githubusercontent.com/Xplo8E/IOSSecuritySuiteAPP/master/Values/MainBinaryHash") { result in
                self.expectedMainBinaryHash = result
                print("Set expectedMainBinaryHash to: \(result ?? "nil")")
            }
        }
    
    
    func fetchData(from urlString: String, completion: @escaping (String?) -> Void) async {
        print("Attempting to fetch data from: \(urlString)")
        
        guard let url = URL(string: urlString) else {
            print("Error: Invalid URL - \(urlString)")
            completion(nil)
            return
        }
        
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData // Ignore cache and always fetch from the server

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                print("Error: Not a valid HTTP response")
                completion(nil)
                return
            }
            
            print("HTTP Status Code: \(httpResponse.statusCode)")
            print("Response Headers: \(httpResponse.allHeaderFields)")
            
            if let result = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) {
                print("Fetched data: \(result)")
                DispatchQueue.main.async {
                    completion(result)
                }
            } else {
                print("Error: Unable to decode response data")
                completion(nil)
            }
        } catch {
            print("Error fetching data from \(urlString): \(error)")
            if let urlError = error as? URLError {
                print("URL Error Code: \(urlError.code.rawValue)")
                print("URL Error Description: \(urlError.localizedDescription)")
            }
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
        print("Default case of IntegrityCheckerImageTarget: \(IntegrityCheckerImageTarget.default)")

        let frameworkHash = IOSSecuritySuite.getMachOFileHashValue(.custom("IOSSecuritySuite")) ?? "error"
        resultText = AttributedString("IOSSecuritySuite hash: \n")
        resultText += AttributedString(frameworkHash + "\n")
        let mainBinaryhash = IOSSecuritySuite.getMachOFileHashValue(.default) ?? "error"
        
        
        resultText += AttributedString("Default image hash: \n")
        resultText += AttributedString(mainBinaryhash + "\n")
        
    }
    

    
    func callFindSection() {
        // Get the MachOParse class using reflection
            // Get the MachOParse class using reflection
        print("[+] Entered callfindsection")
            guard let machOParseClass = NSClassFromString("IOSSecuritySuite.MachOParse") as? NSObject.Type else {
                print("Couldn't find MachOParse class")
                resultSec = "Couldn't find MachOParse class"
                return
            }
            
            // Create an instance of MachOParse
            let machOParse = machOParseClass.init()
            
            // Prepare arguments
            let segname = "__TEXT"
            let secname = "__text"
            
            // Get the method signature
            let selector = NSSelectorFromString("findSection:secname:")
            
            // Check if the object responds to the selector
            guard machOParse.responds(to: selector) else {
                print("Object doesn't respond to findSection:secname:")
                resultSec += "Object doesn't respond to findSection:secname:"
                return
            }
            
            // Call the method
            let result = machOParse.perform(selector, with: segname, with: secname)
            
            // Handle the result
            if let sectionInfo = result?.takeUnretainedValue() as? NSObject {
                print("Section found:")
                print("Address: \(sectionInfo.value(forKey: "addr") ?? "N/A")")
                print("Size: \((sectionInfo.value(forKey: "section") as AnyObject).value(forKeyPath: "pointee.size") ?? "N/A")")
                
                resultSec += "Section found:"
                resultSec += "Address: \(sectionInfo.value(forKey: "addr") ?? "N/A")"
                resultSec += "Size: \((sectionInfo.value(forKey: "section") as AnyObject).value(forKeyPath: "pointee.size") ?? "N/A")"
            } else {
                print("Section not found or couldn't access result")
            }
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

    func checkAppIntegrity() {
        guard let expectedMachOHash = expectedMachOHash,
              let expectedMainBinaryHash = expectedMainBinaryHash else {
            print("Expected data not loaded. MachOHash: \(expectedMachOHash ?? "nil"), MainBinaryHash: \(expectedMainBinaryHash ?? "nil")")
            resultText = AttributedString("Error: Server expected data not loaded")
            return
        }
        
        let actualIOSSecuritySuiteHash = IOSSecuritySuite.getMachOFileHashValue(.custom("IOSSecuritySuite")) ?? "Invalid"
        let actualMainBinaryHash = IOSSecuritySuite.getMachOFileHashValue(.default) ?? "Invalid"
        
        let iOSSecuritySuiteIntegrity = actualIOSSecuritySuiteHash == expectedMachOHash
        let mainBinaryIntegrity = actualMainBinaryHash == expectedMainBinaryHash
        
        let isAppIntegral = iOSSecuritySuiteIntegrity && mainBinaryIntegrity
        
        var attributedString = AttributedString(isAppIntegral ? "App integrity check passed." : "App integrity check failed.") + AttributedString("\n\n")
        attributedString.foregroundColor = isAppIntegral ? .green : .red
        attributedString.font = .boldSystemFont(ofSize: 16)

        let detailsString = """
        Details:
        
        IOSSecuritySuite Framework check: \(iOSSecuritySuiteIntegrity ? "Passed" : "Failed")
        Expected IOSSecuritySuite hash:
        \(expectedMachOHash)
        Actual IOSSecuritySuite hash:
        \(actualIOSSecuritySuiteHash)

        Main Binary check: \(mainBinaryIntegrity ? "Passed" : "Failed")
        Expected Main Binary hash:
        \(expectedMainBinaryHash)
        Actual Main Binary hash:
        \(actualMainBinaryHash)

        Overall result: \(isAppIntegral ? "Passed" : "Failed")
        """
        
        attributedString += AttributedString(detailsString)

        resultText = attributedString
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

