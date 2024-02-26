import { VpChecker } from '../../../src/authentication/VpChecker';
import type { HttpRequest } from '../../../src/server/HttpRequest';
import {decodeJWT} from 'did-jwt';
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt} from 'did-jwt-vc'
import { ES256KSigner, hexToBytes } from 'did-jwt';
import { BadRequestHttpError } from '../../../src';

describe('A VpChecker', (): void => {
    const vpChecker = new VpChecker();

    //variables used in VC creation
    const appName = 'my-demo-app';
    const userID = 'did:web:ben3101.solidcommunity.net';
    const issuerID = 'did:web:issuer123.solidcommunity.net';

    //expiration and issuance date testing
    const today = Math.ceil((Date.now() / 1000));
    const fiveMinsFromNow = today + (5*60);
    const tenYearsFromNow = today + 315569260;

    //issuer
    const VcIssuerKey = '2143c4bd995378ce36bacfcfda2e39610f2809e349b4d25e7b7d2b5f1d82e6ae';
    const VcSigner = ES256KSigner(hexToBytes(VcIssuerKey));

    const vcIssuer = {
        did: issuerID,
        signer: VcSigner
    }
    //Payload
    let vcPayload = {
        sub: userID,
        nbf: today,
        exp: tenYearsFromNow,
        vc: {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            type: ["VerifiableCredential", "UniversityDegreeCredential"],
            credentialSubject: {
                degree: {
                type: "BachelorDegree",
                name: "Bachelor of Science"
                }
            }
        }
    }

    //variables used in VP creation
    //holder
    const VpSignerKey = 'a17cb543a7fbf5493a9754c977826925a346964c5b292e9da31bb6940f698313';
    const VpSigner = ES256KSigner(hexToBytes(VpSignerKey));
    const holder = {
        did: userID,
        signer: VpSigner
    }

    beforeEach((): void => {
        jest.clearAllMocks();
        //reset the VC payload
        vcPayload = {
            sub: userID,
            nbf: today,
            exp: tenYearsFromNow,
            vc: {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                type: ["VerifiableCredential", "UniversityDegreeCredential"],
                credentialSubject: {
                    degree: {
                    type: "BachelorDegree",
                    name: "Bachelor of Science"
                    }
                }
            }
        }
      });

    describe('on a request without VP header', (): void => {
        const request = {
            method: 'GET',
            headers: {

            },
        } as any as HttpRequest;
        it('throws an error.', async(): Promise<void> => {
            const result = vpChecker.handleSafe(request);
            await expect(result).rejects.toThrow(BadRequestHttpError);
            await expect(result).rejects.toThrow('No VP header specified.');
        });
    });

    describe('on a VP not containing nonce', (): void => {
        it('returns undefined nonce.', async(): Promise<void> => {
            const vc = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
            const vpPayload = {
                vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vc],
                },
                exp: fiveMinsFromNow,
                domain: 'exampledomain.com',
                appName: appName
            };
            const vp = await createVerifiablePresentationJwt(vpPayload, holder);
            const request = {
                method: 'GET',
                headers: {
                    vp: vp
                },
            } as any as HttpRequest;
            const result = await vpChecker.extractNonceAndDomain(request);
            expect(result).toEqual({nonce: undefined, domain: 'exampledomain.com'});
        });
    });

    describe('on a VP not containing domain', (): void => {
        it('returns undefined domain.', async(): Promise<void> => {
            const vc = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
            const vpPayload = {
                vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vc],
                },
                exp: fiveMinsFromNow,
                nonce: '123456abcdef=+',
                appName: appName
            }
            const vp = await createVerifiablePresentationJwt(vpPayload, holder);
            const request = {
                method: 'GET',
                headers: {
                    vp: vp
                },
            } as any as HttpRequest;
            const result = await vpChecker.extractNonceAndDomain(request);
            expect(result).toEqual({nonce: '123456abcdef=+', domain: undefined});
        });
    });

    describe('on a VP that has expired', (): void => {
        it('throws an error.', async(): Promise<void> => {
            let fiveMinsAgo = Math.ceil((Date.now()/1000) - (5*60));
            const vc = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
            const vpPayload = {
                vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vc],
                },
                exp: fiveMinsAgo,
                nonce: '123456abc=+',
                domain: 'exampledomain.com',
                appName: appName
            }
            const vp = await createVerifiablePresentationJwt(vpPayload, holder);
            const request = {
                method: 'GET',
                headers: {
                    vp: vp
                },
            } as any as HttpRequest;
            const result = vpChecker.handle(request);
            await expect(result).rejects.toThrow(BadRequestHttpError);
            await expect(result).rejects.toThrow("Error verifying WebID via VP:");
        });
    });

    describe('on an invalid VP JWT', (): void => {
        it('throws an error.', async(): Promise<void> => {
            const vc = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
            const vpPayload = {
                vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vc],
                },
                nonce: '123456abc=+',
                domain: 'exampledomain.com',
                appName: appName
            }
            let vp = await createVerifiablePresentationJwt(vpPayload, holder);
            vp+='randomcharschlbakcjfabu2334=-ifdcd';
            const request = {
                method: 'GET',
                headers: {
                    vp: vp
                },
            } as any as HttpRequest;
            const result = vpChecker.handle(request);
            await expect(result).rejects.toThrow(BadRequestHttpError);
            await expect(result).rejects.toThrow("Error verifying WebID via VP:");
            await expect(result).rejects.toThrow(`invalid_argument: Incorrect format JWT`);
        });
    });

    describe("on a VP that has not been signed with the holder's private key", (): void => {
        it('throws an error.', async(): Promise<void> => {
            const vc = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
            const WrongVpSignerKey = 'a17cb543a7fbf5493a9754c977826925a346964c5b292e9da31bb6940f698399';//last 2 chars replaced with 9s
            const WrongVpSigner = ES256KSigner(hexToBytes(WrongVpSignerKey));
            const WrongHolder = {
            did: userID,
            signer: WrongVpSigner
            }
            const vpPayload = {
                vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vc],
                },
                nonce: '123456abc=+',
                domain: 'exampledomain.com',
                appName: appName
            }
            const vp = await createVerifiablePresentationJwt(vpPayload, WrongHolder);
            const request = {
                method: 'GET',
                headers: {
                    vp: vp
                },
            } as any as HttpRequest;
            const result = vpChecker.handle(request);
            await expect(result).rejects.toThrow(BadRequestHttpError);
            await expect(result).rejects.toThrow("Error verifying WebID via VP:");
            await expect(result).rejects.toThrow(`invalid_signature: no matching public key found`);
        });
    });

    describe('on a request with appropriate VP', (): void => {
        it('returns the expected credentials', async(): Promise<void> => {
            const vc = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
            const vpPayload = {
                vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vc],
                },
                exp: fiveMinsFromNow,
                domain: 'exampledomain.com',
                appName: appName
            };
            const vp = await createVerifiablePresentationJwt(vpPayload, holder);
            const request = {
                method: 'GET',
                headers: {
                    vp: vp
                },
            } as any as HttpRequest;
            const result = await vpChecker.handleSafe(request);
            expect(result).toEqual({agent:{ webId: userID }, client: { clientId: appName }, issuer: { url: issuerID }});
        });
    });

    describe('on a VC that has an nbf date after today', (): void => {
        it('throws an error.', async(): Promise<void> => {
            let tomorrow = Math.ceil((Date.now()/1000) + (24*60*60));
            vcPayload.nbf = tomorrow;
            const vc = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
            const vpPayload = {
                vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vc],
                },
                nonce: '123456abc=+',
                domain: 'exampledomain.com',
                appName: appName
            }
            const vp = await createVerifiablePresentationJwt(vpPayload, holder);
            const request = {
                method: 'GET',
                headers: {
                    vp: vp
                },
            } as any as HttpRequest;
            const result = vpChecker.handle(request);
            await expect(result).rejects.toThrow(BadRequestHttpError);
            await expect(result).rejects.toThrow("Error verifying WebID via VP:");
            await expect(result).rejects.toThrow(`invalid_jwt: JWT not valid before nbf: ${tomorrow}`);  
        });
    });

    describe('on a VC that has an exp date before today', (): void => {
        it('throws an error.', async(): Promise<void> => {
            let yesterday = Math.ceil((Date.now()/1000) - (24*60*60));
            vcPayload.exp = yesterday;
            const vc = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
            const vpPayload = {
                vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vc],
                },
                nonce: '123456abc=+',
                domain: 'exampledomain.com',
                appName: appName
            }
            const vp = await createVerifiablePresentationJwt(vpPayload, holder);
            const request = {
                method: 'GET',
                headers: {
                    vp: vp
                },
            } as any as HttpRequest;
            const result = vpChecker.handle(request);
            await expect(result).rejects.toThrow(BadRequestHttpError);
            await expect(result).rejects.toThrow("Error verifying WebID via VP:");
            await expect(result).rejects.toThrow(`invalid_jwt: JWT has expired: exp: ${yesterday} < now`);
        });
    });

    describe("on a VC that has not been signed with the issuer's private key", (): void => {
        it('throws an error.', async(): Promise<void> => {
            const WrongVcIssuerKey = '2143c4bd995378ce36bacfcfda2e39610f2809e349b4d25e7b7d2b5f1d82e6ea';//swap last 2 chars
            const WrongVcSigner = ES256KSigner(hexToBytes(WrongVcIssuerKey));
            const WrongVcIssuer = {
                did: issuerID,
                signer: WrongVcSigner
            }
            const vc = await createVerifiableCredentialJwt(vcPayload, WrongVcIssuer);
            const vpPayload = {
                vp: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vc],
                },
                nonce: '123456abc=+',
                domain: 'exampledomain.com',
                appName: appName
            }
            const vp = await createVerifiablePresentationJwt(vpPayload, holder);
            const request = {
                method: 'GET',
                headers: {
                    vp: vp
                },
            } as any as HttpRequest;
            const result = vpChecker.handle(request);
            await expect(result).rejects.toThrow(BadRequestHttpError);
            await expect(result).rejects.toThrow("Error verifying WebID via VP:");
            await expect(result).rejects.toThrow(`invalid_signature: no matching public key found`);
        });
    });
});