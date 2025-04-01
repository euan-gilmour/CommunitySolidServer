# Community Solid Server

## Disclaimer

This is a fork the [original modified Community Solid Server](https://github.com/ben3101/CommunitySolidServer) for the VC-based authentication protocol. The only think files that have changed are the files within the .data directory.

## Usage

To use the server with the mobile wallet app, you will need to modify the contents of the .data directory to add a resource to a Pod whose access control policy is configured for the DID that you intend to use. The simplest way to do this is to directly modify the file .data/my-pod/test-resource.txt.acr. Change the value of acp:agent to the DID that you intend to use in the wallet application. test-resource.txt is the default resource for my-demo-app to request.

To start the server, run:

`npm install`

Followed by:

`npm run vc-protocol-server`

The server will start on localhost:3000

---


