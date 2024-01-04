In a Hyperledger Fabric land registration proof-of-concept (PoC), it's crucial to follow secure practices. The private key used by the Sub-Registrar Officer (SRO) for signing in is generally distinct from the one used for digitally signing documents. Using separate keys enhances security by minimizing potential risks associated with key compromise or misuse. Always adhere to best practices for key management in blockchain implementations.




User
Tell me it is possible or not

ChatGPT
Yes, it is possible for the private key used by the Sub-Registrar Officer (SRO) to sign in to be used for digitally signing a document in a Hyperledger Fabric land registration proof-of-concept. However, it's recommended to use separate keys for these actions to enhance security and minimize potential risks.




User
Say how 

ChatGPT
In a Hyperledger Fabric environment for land registration, the private key used by the Sub-Registrar Officer (SRO) to sign in and the one used for digitally signing documents are typically managed through cryptographic key pairs. The Fabric CA (Certificate Authority) is responsible for issuing these keys. The SRO's enrollment process with the CA involves generating a key pair, and during this process, the SRO can obtain separate private keys for authentication (signing in) and document signing.

This separation ensures that compromising one key doesn't automatically compromise the other, enhancing the overall security of the system. The specific implementation details, including key generation and enrollment, would depend on the configuration and policies defined in your Hyperledger Fabric network.




User
No no it is possible right? That's how can I achieve in code level nodejs

ChatGPT
Yes, it is possible to achieve this at the code level using Node.js in a Hyperledger Fabric environment. Here's a high-level overview of how you might handle key generation and usage for sign-in and document signing:

Enrollment for Sign-In:

Use Hyperledger Fabric's Node SDK or Fabric-CA-client library to enroll the SRO with the Certificate Authority (CA).
This process typically involves generating a key pair (public-private key) for authentication.
Store the private key securely for sign-in purposes.
Enrollment for Document Signing:

When the SRO needs to sign a document, initiate a separate enrollment process with the CA.
Generate another key pair specifically for document signing.
Store this private key securely, separate from the sign-in private key.
Usage in Transactions:

When interacting with the Hyperledger Fabric network to submit transactions or sign documents, use the appropriate private key based on the context.
Implement logic in your Node.js code to select the correct private key for the desired action.
Here's a simplified example using the Fabric SDK for Node.js:

javascript
Copy code
const { Gateway, Wallets } = require('fabric-network');
const fs = require('fs');

async function signInAndSignDocument() {
    const gateway = new Gateway();

    try {
        // Load connection profile
        const connectionProfile = fs.readFileSync('connection.json', 'utf8');

        // Connect to the gateway
        await gateway.connect(JSON.parse(connectionProfile), { wallet, identity: 'SROUserId', discovery: { enabled: true, asLocalhost: true } });

        // Get the channel
        const network = await gateway.getNetwork('mychannel');

        // Use the appropriate private key for sign-in
        const signInPrivateKey = getSignInPrivateKey();

        // Perform sign-in operation...

        // Use the appropriate private key for document signing
        const documentSignPrivateKey = getDocumentSignPrivateKey();

        // Perform document signing operation...

    } catch (error) {
        console.error(`Error: ${error.message}`);
    } finally {
        // Disconnect from the gateway
        gateway.disconnect();
    }
}

function getSignInPrivateKey() {
    // Logic to retrieve the sign-in private key
    // Return the private key
}

function getDocumentSignPrivateKey() {
    // Logic to retrieve the document signing private key
    // Return the private key
}

// Call the function to initiate the process
signInAndSignDocument();
Ensure that your key management practices align with security best practices to safeguard private keys appropriately.




User
Write the logic for getsigninprovatekey

ChatGPT
Certainly, the getSignInPrivateKey function should retrieve the private key associated with the Sub-Registrar Officer (SRO) for sign-in purposes. Below is a simplified example; keep in mind that you should adapt this based on your actual key storage and management strategy:

javascript
Copy code
function getSignInPrivateKey() {
    // In a real-world scenario, you might fetch the private key from a secure key storage,
    // such as a hardware security module (HSM), a key management service, or a secure file.

    // For the purpose of this example, let's assume you have a file named 'sro-signin-key.pem'
    // containing the private key in PEM format. Make sure to secure this file appropriately.

    const privateKeyPath = 'sro-signin-key.pem';

    try {
        // Read the private key file
        const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
        return privateKey;
    } catch (error) {
        console.error(`Error reading sign-in private key: ${error.message}`);
        throw error;
    }
}
In a production environment, you'd likely use more secure methods for key storage and retrieval, such as interacting with a secure key management service or using hardware security modules for enhanced security. Always ensure that private keys are stored and managed securely to prevent unauthorized access.




User
Write the logic for getDocumentsignPrivatekey

ChatGPT
The getDocumentSignPrivateKey function should retrieve the private key associated with the Sub-Registrar Officer (SRO) for document signing. Similar to the sign-in private key logic, this example assumes you have a file containing the private key in PEM format. Ensure that you secure this file appropriately:

javascript
Copy code
function getDocumentSignPrivateKey() {
    // In a real-world scenario, you might fetch the private key from a secure key storage,
    // such as a hardware security module (HSM), a key management service, or a secure file.

    // For the purpose of this example, let's assume you have a file named 'sro-doc-sign-key.pem'
    // containing the private key in PEM format. Make sure to secure this file appropriately.

    const privateKeyPath = 'sro-doc-sign-key.pem';

    try {
        // Read the private key file
        const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
        return privateKey;
    } catch (error) {
        console.error(`Error reading document sign private key: ${error.message}`);
        throw error;
    }
}
Again, in a production environment, use more secure methods for key storage and retrieval. Consider best practices for key management, such as using dedicated hardware for key storage or interacting with a secure key management service. Always prioritize the security of private keys.




User
How will get the identity: srouserid

ChatGPT
The identity parameter in the gateway.connect function refers to the identity or user context you want to use when interacting with the Hyperledger Fabric network. In the context of your question, it seems like you want to connect with the identity of the Sub-Registrar Officer (SRO). Here's how you might obtain and set the identity:

Assuming you've previously enrolled the SRO and stored their identity in the wallet, you can use that identity during the connection process. Here's a simplified example:

javascript
Copy code
const { Gateway, Wallets } = require('fabric-network');
const fs = require('fs');

async function signInAndSignDocument() {
    const gateway = new Gateway();

    try {
        // Load connection profile
        const connectionProfile = fs.readFileSync('connection.json', 'utf8');

        // Connect to the gateway
        const wallet = await Wallets.newFileSystemWallet('path/to/wallet');
        const userIdentity = 'SROUserId'; // Replace with the actual user ID of the SRO

        await gateway.connect(JSON.parse(connectionProfile), { wallet, identity: userIdentity, discovery: { enabled: true, asLocalhost: true } });

        // Get the channel
        const network = await gateway.getNetwork('mychannel');

        // Continue with the rest of your logic...

    } catch (error) {
        console.error(`Error: ${error.message}`);
    } finally {
        // Disconnect from the gateway
        gateway.disconnect();
    }
}

// Call the function to initiate the process
signInAndSignDocument();
In this example, replace 'SROUserId' with the actual user ID or identity label you used when enrolling the SRO. The user identity is typically specified during the enrollment process with the Certificate Authority (CA). Ensure that the specified identity corresponds to a valid identity stored in the wallet.




User
Okay let say am going to create a poc on land registration in this how will I enroll the SRO

ChatGPT
To enroll the Sub-Registrar Officer (SRO) in a Hyperledger Fabric proof-of-concept (PoC) for land registration, you need to perform the enrollment steps using the Certificate Authority (CA). Here's a step-by-step guide:

Set Up Connection Profile:

Create a connection profile JSON file that specifies the details of your Hyperledger Fabric network, including CA information.
json
Copy code
// connection.json
{
  "name": "mychannel",
  "version": "1.0",
  "client": {
    "organization": "Org1",
    "connection": {
      "timeout": {
        "peer": {
          "endorser": "300"
        }
      }
    }
  },
  "channels": {
    "mychannel": {
      "orderers": ["orderer.example.com"],
      "peers": {
        "peer0.org1.example.com": {}
      }
    }
  }
}
Enroll SRO with CA:

Use the Fabric-CA-client library or Hyperledger Fabric SDK for Node.js to enroll the SRO with the CA.
Specify the necessary user attributes like role, affiliation, and identity label.
javascript
Copy code
const { Gateway, Wallets, X509WalletMixin } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');

async function enrollSRO() {
  const caURL = 'http://ca.org1.example.com:7054'; // Replace with your CA URL
  const ca = new FabricCAServices(caURL);

  const enrollmentID = 'sroUserId'; // Replace with a suitable enrollment ID
  const enrollmentSecret = 'sroUserSecret'; // Replace with a secure enrollment secret

  const enrollment = await ca.enroll({ enrollmentID, enrollmentSecret });

  // Create a wallet to persist the enrolled user's identity
  const wallet = await Wallets.newFileSystemWallet('path/to/wallet');

  // Create an X.509 wallet from the enrollment data
  const identityLabel = 'SROUserId'; // Specify the identity label
  const identity = X509WalletMixin.createIdentity('Org1MSP', enrollment.certificate, enrollment.key.toBytes());
  await wallet.put(identityLabel, identity);

  console.log(`Enrollment of SRO with ID ${enrollmentID} successful.`);
}

// Call the function to enroll the SRO
enrollSRO();
Use the Enrolled Identity:

The enrolled identity is stored in the wallet, and you can later use it when connecting to the network.
javascript
Copy code
const gateway = new Gateway();

try {
  // Load connection profile
  const connectionProfile = fs.readFileSync('connection.json', 'utf8');

  // Connect to the gateway using the enrolled identity
  const wallet = await Wallets.newFileSystemWallet('path/to/wallet');
  const userIdentity = 'SROUserId';

  await gateway.connect(JSON.parse(connectionProfile), { wallet, identity: userIdentity, discovery: { enabled: true, asLocalhost: true } });

  // Continue with the rest of your logic...

} catch (error) {
  console.error(`Error: ${error.message}`);
} finally {
  // Disconnect from the gateway
  gateway.disconnect();
}
Remember to replace placeholder values with your actual network configurations, CA details, enrollment IDs, and secrets. This code provides a basic template, and you might need to adapt it based on your specific network setup and requirements.




User
Create function called GettAllasset in chaincode and when I trying to call the function from my client application. It should return the some dummy pdf . That pdf should signed by the SRO private key 

ChatGPT
To achieve this in your Hyperledger Fabric chaincode, you can create a function called GetAllAssets that returns a dummy PDF file signed by the Sub-Registrar Officer's (SRO) private key. Please note that handling PDFs and digital signatures is a complex task, and this example will be simplified for demonstration purposes. Additionally, you may need to integrate external libraries for handling PDFs and cryptographic operations. Here's a basic structure to get you started:

Chaincode (Go language):

go
Copy code
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type LandRegistrationContract struct {
	contractapi.Contract
}

// Define your asset structure (you might have other fields)
type Asset struct {
	ID   string `json:"ID"`
	Type string `json:"Type"`
}

// GetAllAssets returns dummy PDF signed by SRO private key
func (c *LandRegistrationContract) GetAllAssets(ctx contractapi.TransactionContextInterface) ([]byte, error) {
	// Retrieve SRO private key (you should securely manage and load this)
	sroPrivateKey, err := loadSROPrivateKey()
	if err != nil {
		return nil, err
	}

	// Dummy PDF content
	dummyPDFContent := []byte("Dummy PDF Content")

	// Sign the PDF using SRO private key
	signedPDF, err := signPDF(dummyPDFContent, sroPrivateKey)
	if err != nil {
		return nil, err
	}

	return signedPDF, nil
}

// loadSROPrivateKey loads and returns the SRO private key from a secure storage (adapt based on your setup)
func loadSROPrivateKey() (*ecdsa.PrivateKey, error) {
	// Implement the logic to securely load the SRO private key
	// This might involve reading a PEM file or interacting with a secure key management service
	// Ensure that the private key is stored securely and not exposed in the code
	// Return the loaded private key
}

// signPDF signs the PDF content using the provided private key
func signPDF(pdfContent []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Implement the logic to sign the PDF using the private key
	// This might involve using a cryptographic library that supports PDF signing
	// Return the signed PDF content
}
Client Application:

In your client application (Node.js example):

javascript
Copy code
const { Gateway, Wallets } = require('fabric-network');
const fs = require('fs');

async function getAllAssets() {
    const gateway = new Gateway();

    try {
        // Load connection profile
        const connectionProfile = fs.readFileSync('connection.json', 'utf8');

        // Connect to the gateway using the enrolled identity
        const wallet = await Wallets.newFileSystemWallet('path/to/wallet');
        const userIdentity = 'SROUserId';

        await gateway.connect(JSON.parse(connectionProfile), { wallet, identity: userIdentity, discovery: { enabled: true, asLocalhost: true } });

        // Get the network and contract
        const network = await gateway.getNetwork('mychannel');
        const contract = network.getContract('landRegistrationContract');

        // Invoke the GetAllAssets function
        const signedPDF = await contract.submitTransaction('GetAllAssets');

        // Handle the signed PDF as needed (save to file, process, etc.)
        fs.writeFileSync('signedPDF.pdf', signedPDF);
        console.log('Signed PDF received and saved.');

    } catch (error) {
        console.error(`Error: ${error.message}`);
    } finally {
        // Disconnect from the gateway
        gateway.disconnect();
    }
}

// Call the function to invoke GetAllAssets
getAllAssets();
Ensure that you have the necessary cryptographic libraries for PDF signing, and adapt the loadSROPrivateKey and signPDF functions based on your specific use case and key management strategy.




User
You Write the logic for the two functions

ChatGPT
Creating fully functional logic for PDF signing and loading private keys in the context of Hyperledger Fabric chaincode, especially in the Go programming language, can be complex and is typically beyond the scope of a simple example. However, I'll provide you with a basic template for the two functions, keeping in mind that you might need to integrate external libraries for cryptographic and PDF handling:

go
Copy code
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type LandRegistrationContract struct {
	contractapi.Contract
}

// Define your asset structure (you might have other fields)
type Asset struct {
	ID   string `json:"ID"`
	Type string `json:"Type"`
}

// GetAllAssets returns dummy PDF signed by SRO private key
func (c *LandRegistrationContract) GetAllAssets(ctx contractapi.TransactionContextInterface) ([]byte, error) {
	// Retrieve SRO private key (you should securely manage and load this)
	sroPrivateKey, err := loadSROPrivateKey()
	if err != nil {
		return nil, err
	}

	// Dummy PDF content
	dummyPDFContent := []byte("Dummy PDF Content")

	// Sign the PDF using SRO private key
	signedPDF, err := signPDF(dummyPDFContent, sroPrivateKey)
	if err != nil {
		return nil, err
	}

	return signedPDF, nil
}

// loadSROPrivateKey loads and returns the SRO private key from a secure storage (adapt based on your setup)
func loadSROPrivateKey() (*ecdsa.PrivateKey, error) {
	// Implement the logic to securely load the SRO private key
	// This might involve reading a PEM file or interacting with a secure key management service
	// Ensure that the private key is stored securely and not exposed in the code

	// For this example, we'll generate a temporary private key
	privateKey, err := ecdsa.GenerateKey(ecdsa.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	return privateKey, nil
}

// signPDF signs the PDF content using the provided private key
func signPDF(pdfContent []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Implement the logic to sign the PDF using the private key
	// This might involve using a cryptographic library that supports PDF signing

	// For this example, we'll just return the original PDF content without signing
	return pdfContent, nil
}
Please note that:

The loadSROPrivateKey function is a placeholder, and you should replace it with your secure private key loading logic.
The signPDF function is also a placeholder, and you need to integrate a library or tool that supports PDF signing with an ECDSA private key.
For a production implementation, consider using well-established libraries like github.com/jung-kurt/gofpdf for PDF handling and a library like crypto for cryptographic operations. Additionally, ensure proper error handling and robust key management practices.




User
Write the code in nodejs

ChatGPT
Creating a complete example for signing a PDF with a private key in Node.js is more complex and involves external libraries. Below is a simplified example using the pdf-lib library for PDF handling and crypto for cryptographic operations.

First, install the required libraries:

bash
Copy code
npm install pdf-lib elliptic
Then, you can use the following example code:

javascript
Copy code
const { PDFDocument } = require('pdf-lib');
const EC = require('elliptic').ec;

async function getAllAssets() {
    // Load SRO private key (replace with your actual private key loading logic)
    const sroPrivateKey = loadSROPrivateKey();

    // Dummy PDF content
    const dummyPDFContent = 'Dummy PDF Content';

    // Sign the PDF using SRO private key
    const signedPDF = await signPDF(dummyPDFContent, sroPrivateKey);

    // Handle the signed PDF as needed (save to file, process, etc.)
    console.log('Signed PDF:', signedPDF);
}

function loadSROPrivateKey() {
    // Implement the logic to securely load the SRO private key
    // Replace this with your actual private key loading logic
    // For this example, we'll use a dummy private key
    const ec = new EC('secp256k1');
    const key = ec.genKeyPair();
    return key;
}

async function signPDF(pdfContent, privateKey) {
    try {
        // Parse the dummy PDF content
        const pdfDoc = await PDFDocument.load(pdfContent);

        // Get the first page of the PDF (you might need to adapt based on your PDF structure)
        const page = pdfDoc.getPages()[0];

        // Generate a dummy signature (replace with your actual signing logic)
        const signature = generateSignature(page.getContent());

        // Embed the signature in the PDF metadata (you might need to adapt based on your PDF structure)
        page.addAnnotation({
            ...signature,
            flags: 0x132, // Include in print and view
        });

        // Save the modified PDF
        const modifiedPDF = await pdfDoc.save();

        return modifiedPDF;
    } catch (error) {
        console.error('Error signing PDF:', error.message);
        throw error;
    }
}

function generateSignature(data) {
    // Implement the logic to generate a digital signature using the private key
    // Replace this with your actual signing logic
    // For this example, we'll use a dummy signature
    const ec = new EC('secp256k1');
    const key = ec.genKeyPair();
    const signature = key.sign(data);
    return { signature };
}

// Call the function to initiate the process
getAllAssets();
This example uses the pdf-lib library for PDF handling and elliptic for generating a dummy digital signature. You need to replace the dummy private key loading and signing logic with your actual private key management and signing implementation.

Note: In a production scenario, handling digital signatures, especially for legal documents like land registrations, requires careful consideration of security, standards, and regulations. Always consult with experts and follow best practices in cryptography and document signing.




User
Okay but how do I know this pdf is signed by sro ?

ChatGPT
Verifying the digital signature of a PDF involves using the public key corresponding to the private key used for signing. In this case, since you're dealing with the Sub-Registrar Officer's (SRO) private key, you need the SRO's public key.

Here's how you can adapt the Node.js example to include signature verification using the elliptic library:

First, install the required library:

bash
Copy code
npm install pdf-lib elliptic
Now, modify the example code:

javascript
Copy code
const { PDFDocument } = require('pdf-lib');
const EC = require('elliptic').ec;

async function getAllAssets() {
    // Load SRO key pair
    const { privateKey, publicKey } = loadSROKeyPair();

    // Dummy PDF content
    const dummyPDFContent = 'Dummy PDF Content';

    // Sign the PDF using SRO private key
    const signedPDF = await signPDF(dummyPDFContent, privateKey);

    // Verify the signature
    const isSignatureValid = await verifySignature(signedPDF, publicKey);
    console.log('Is the signature valid?', isSignatureValid);

    // Handle the signed PDF as needed (save to file, process, etc.)
    console.log('Signed PDF:', signedPDF);
}

function loadSROKeyPair() {
    // Implement the logic to securely load the SRO key pair (private key and corresponding public key)
    // Replace this with your actual key pair loading logic
    // For this example, we'll use a dummy key pair
    const ec = new EC('secp256k1');
    const keyPair = ec.genKeyPair();
    return { privateKey: keyPair.getPrivate(), publicKey: keyPair.getPublic() };
}

async function signPDF(pdfContent, privateKey) {
    try {
        // Parse the dummy PDF content
        const pdfDoc = await PDFDocument.load(pdfContent);

        // Get the first page of the PDF (you might need to adapt based on your PDF structure)
        const page = pdfDoc.getPages()[0];

        // Generate a dummy signature (replace with your actual signing logic)
        const signature = generateSignature(page.getContent(), privateKey);

        // Embed the signature in the PDF metadata (you might need to adapt based on your PDF structure)
        page.addAnnotation({
            ...signature,
            flags: 0x132, // Include in print and view
        });

        // Save the modified PDF
        const modifiedPDF = await pdfDoc.save();

        return modifiedPDF;
    } catch (error) {
        console.error('Error signing PDF:', error.message);
        throw error;
    }
}

function generateSignature(data, privateKey) {
    // Implement the logic to generate a digital signature using the private key
    // Replace this with your actual signing logic
    // For this example, we'll use a dummy signature
    const ec = new EC('secp256k1');
    const key = ec.keyFromPrivate(privateKey);
    const signature = key.sign(data);
    return { signature };
}

async function verifySignature(pdfContent, publicKey) {
    try {
        // Parse the signed PDF content
        const pdfDoc = await PDFDocument.load(pdfContent);

        // Get the first page of the PDF (you might need to adapt based on your PDF structure)
        const page = pdfDoc.getPages()[0];

        // Extract the embedded signature (you might need to adapt based on your PDF structure)
        const embeddedSignature = page.getAnnotations()[0].get('AP').get('AS').toString();

        // Verify the signature
        const ec = new EC('secp256k1');
        const key = ec.keyFromPublic(publicKey);
        const isSignatureValid = key.verify(page.getContent(), { r: embeddedSignature.slice(0, 64), s: embeddedSignature.slice(64) });

        return isSignatureValid;
    } catch (error) {
        console.error('Error verifying signature:', error.message);
        throw error;
    }
}

// Call the function to initiate the process
getAllAssets();
This modification includes a verifySignature function that verifies the signature of the signed PDF using the SRO's public key. Keep in mind that this is a basic example, and in a production scenario, you need to follow industry standards and best practices for signature verification, especially in the context of legal documents.




User
Use the SRO's public and private key from the gateway.getidentity()

ChatGPT
In a Hyperledger Fabric chaincode, you generally don't have direct access to the private key of an identity from the gateway.getIdentity() method. The private key is securely stored within the client's wallet. However, you can sign data with the private key and then verify the signature using the corresponding public key.

Here's a modified example using the private and public keys obtained from the client's wallet:

javascript
Copy code
const { PDFDocument } = require('pdf-lib');
const EC = require('elliptic').ec;
const crypto = require('crypto');

async function getAllAssets() {
    const userIdentity = 'SROUserId'; // Replace with the actual user ID
    const privateKey = await getPrivateKeyFromWallet(userIdentity);
    const publicKey = await getPublicKeyFromWallet(userIdentity);

    // Dummy PDF content
    const dummyPDFContent = 'Dummy PDF Content';

    // Sign the PDF using SRO private key
    const signedPDF = await signPDF(dummyPDFContent, privateKey);

    // Verify the signature
    const isSignatureValid = await verifySignature(signedPDF, publicKey);
    console.log('Is the signature valid?', isSignatureValid);

    // Handle the signed PDF as needed (save to file, process, etc.)
    console.log('Signed PDF:', signedPDF);
}

async function getPrivateKeyFromWallet(userIdentity) {
    // Load the private key from the wallet
    // Implement this based on your wallet structure and key management strategy
    // For example, using the Fabric Node SDK Wallet class
    const wallet = await gateway.getWallet('walletName'); // Replace with your wallet name
    const identity = await wallet.get(userIdentity);
    return identity.credentials.privateKey;
}

async function getPublicKeyFromWallet(userIdentity) {
    // Load the public key from the wallet
    // Implement this based on your wallet structure and key management strategy
    // For example, using the Fabric Node SDK Wallet class
    const wallet = await gateway.getWallet('walletName'); // Replace with your wallet name
    const identity = await wallet.get(userIdentity);
    return identity.credentials.publicKey;
}

async function signPDF(pdfContent, privateKey) {
    try {
        // Parse the dummy PDF content
        const pdfDoc = await PDFDocument.load(pdfContent);

        // Get the first page of the PDF (you might need to adapt based on your PDF structure)
        const page = pdfDoc.getPages()[0];

        // Generate a signature using the private key
        const signature = generateSignature(page.getContent(), privateKey);

        // Embed the signature in the PDF metadata (you might need to adapt based on your PDF structure)
        page.addAnnotation({
            ...signature,
            flags: 0x132, // Include in print and view
        });

        // Save the modified PDF
        const modifiedPDF = await pdfDoc.save();

        return modifiedPDF;
    } catch (error) {
        console.error('Error signing PDF:', error.message);
        throw error;
    }
}

function generateSignature(data, privateKey) {
    // Sign the data using the private key
    const sign = crypto.createSign('sha256');
    sign.update(data);
    return sign.sign(privateKey, 'hex');
}

async function verifySignature(pdfContent, publicKey) {
    try {
        // Parse the signed PDF content
        const pdfDoc = await PDFDocument.load(pdfContent);

        // Get the first page of the PDF (you might need to adapt based on your PDF structure)
        const page = pdfDoc.getPages()[0];

        // Extract the embedded signature (you might need to adapt based on your PDF structure)
        const embeddedSignature = page.getAnnotations()[0].get('AP').get('AS').toString('hex');

        // Verify the signature
        const verify = crypto.createVerify('sha256');
        verify.update(page.getContent());

        // Convert the public key to the required format for verification
        const formattedPublicKey = `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`;

        const isSignatureValid = verify.verify(formattedPublicKey, embeddedSignature, 'hex');
        return isSignatureValid;
    } catch (error) {
        console.error('Error verifying signature:', error.message);
        throw error;
    }
}

// Call the function to initiate the process
getAllAssets();
