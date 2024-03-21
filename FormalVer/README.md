---
runme:
  id: 01HSG4YD6587CJS2CAMFZ1MF3D
  version: v3
---

# VC-Based Solid Authentication Protocol with separation between Apps and Users

The VC-Based Solid Authentication Protocol with separation between Apps and User: The issuance of the VC is done following traditional SSI protocol where users directly contact issuer for asking new credentials. The verification is slightly different since we put an application in the authentication loop in order to "delegate" the access. It is possible to check the output of our protocol [here](log/log.txt)

![MSC of ...](/FormalVer/msc/msc_https_verification_vc.png)

# Results

| Property  | Holds | Note |
| ------------- | ------------- | ------------- |
| Secret rule_fromVerifier | Yes  | The Verifiable Presentation Request sent from the Verifier remains secret, cannot be produced if the user is not the real user. |
| Secret vp_fromProver | Yes  | The Verifiable Presentation sent by the Prover (User) remains secret. |
| Secret access_token_fromVerifier | Yes  | The token given to the App to access resources remains secret. |
| Authentication Verifier  | Yes  | The app is able to authenticate the verifier. |
| Authentication App  | Yes  | The verifier is able to authenticate the app. |
| Authentication User  | Yes  | The app is able to authenticate the user. |
