import { BadRequestHttpError } from '../../../src';
import type { RequestParser } from '../../../src/http/input/RequestParser';
import type { Operation } from '../../../src/http/Operation';
import { ErrorHandler } from '../../../src/http/output/error/ErrorHandler';
import { ResponseDescription } from '../../../src/http/output/response/ResponseDescription';
import type { ResponseWriter } from '../../../src/http/output/ResponseWriter';
import { BasicRepresentation } from '../../../src/http/representation/BasicRepresentation';
import type { HttpRequest } from '../../../src/server/HttpRequest';
import type { HttpResponse } from '../../../src/server/HttpResponse';
import { VcAuthorizingHttpHandler } from '../../../src/server/VcAuthorizingHttpHandler';
import { VcHttpHandler } from '../../../src/server/VcHttpHandler';
import { readJsonStream } from '../../../src/util/StreamUtil';

describe('A VcHttpHandler', (): void => {
  const response: HttpResponse = {} as any;
  let body = new BasicRepresentation(JSON.stringify({user: 'test_user',app: 'test_app',vcissuer: 'test_vcissuer'}), 'application/ld+json');
  const operation: Operation = { method: 'POST', target: { path: 'http://localhost:3000/my-pod/test-folder/test-resource.txt' }, preferences: {}, body:body };
  const errorResponse = new ResponseDescription(400);
  let requestParser: jest.Mocked<RequestParser>;
  let errorHandler: jest.Mocked<ErrorHandler>;
  let responseWriter: jest.Mocked<ResponseWriter>;
  let source: jest.Mocked<VcAuthorizingHttpHandler>;
  let handler: VcHttpHandler;

  beforeEach(async(): Promise<void> => {
    requestParser = { handleSafe: jest.fn().mockResolvedValue(operation) } as any;
    errorHandler = { handleSafe: jest.fn().mockResolvedValue(errorResponse) } as any;
    responseWriter = { handleSafe: jest.fn() } as any;    

    source = {
      handleSafe: jest.fn(),
      checkAcr: jest.fn(),
      extractNonceAndDomain: jest.fn(),
      handle: jest.fn()
    } as any;

    handler = new VcHttpHandler(
      { requestParser, errorHandler, responseWriter, operationHandler: source },
    );
  });

  describe('when a request does not have a vc or vp header', (): void => {
        it('throws an error.', async(): Promise<void> => {
            const request = {
                method: 'POST',
                headers: {

                },
            } as any as HttpRequest;
            await expect(handler.canHandle({request, response})).rejects.toThrow("Required headers missing: 'VC' or 'VP'.");
        });
    });

    describe('when a request has a vc header', (): void => {
        const request = {
            method: 'POST',
            headers: {
                'vc': 'true'
            },
        } as any as HttpRequest;
        it('attempts to handle the request.', async(): Promise<void> => {
            expect(handler.canHandle({request, response})).toReturn;
        });
        it('throws an error if it does not have user/app/issuer indicated in the body.', async(): Promise<void> => {
            const result = handler.handleRequest(request, response, body);
            await expect(result).rejects.toThrow("Request not recognised");
        });
    });

    describe('when a request has a vp header', (): void => {
        it('attempts to handle the request.', async(): Promise<void> => {
            const request = {
                method: 'POST',
                headers: {
                    'vp': 'true'
                },
            } as any as HttpRequest;
            expect(handler.canHandle({request, response})).toReturn;
        });
    });

    describe('when handleRequest throws an error', (): void => {
        it('calls handleError', async(): Promise<void> => {
            const request = {
                method: 'GET',
                headers: {
                    'vp': 'testjwt'
                },
            } as any as HttpRequest;
            let operation: Operation = { method: 'GET', target: { path: 'http://localhost:3000/my-pod/test-folder/test-resource.txt' }, preferences: {}, body };
            requestParser.handleSafe.mockResolvedValue(operation);
            source.extractNonceAndDomain.mockResolvedValue({nonce:'invalid', domain:'invalid'});
            expect(handler.handleRequest(request, response, body)).rejects.toThrow('Invalid Nonce and Domain.');
            const handleErrorSpy = jest.spyOn(VcHttpHandler.prototype as any, 'handleError');
            await handler.handle({request, response});
            expect(handleErrorSpy).toHaveBeenCalledTimes(1);
        });
    });

    describe('when a request has a vc header and specifies incorrect user/app/issuer in the body', (): void => {
        const request = {
            method: 'POST',
            headers: {
                "vc": "true"
            },
        } as any as HttpRequest;
        request.url = 'www.example.com/test-resource';
        let body =  {user: 'test_user',app: 'test_app',vcissuer: 'test_vcissuer'};

        it('determines that it is an initial request', async(): Promise<void> => {
            expect(handler.isInitialRequest(body)).toEqual(true);
        });

        it('throws an error when the user/app/issuer combination is invalid.', async(): Promise<void> => {
            source.checkAcr.mockResolvedValueOnce(false);
            expect(handler.handleRequest(request, response, body)).rejects.toThrow('Invalid user - app - issuer combination.');
          });
    });

    describe('when a request has a vc header and specifies valid user/app/issuer in the body', (): void => {
        const request = {
            method: 'POST',
            headers: {
                "vc": "true"
            },
        } as any as HttpRequest;
        request.url = 'www.example.com/test-resource';
        let body =  {user: 'test_user',app: 'test_app',vcissuer: 'test_vcissuer'};

        it('responds with a 401 HTTP response and creates an appropriate VP Request when user/issuer/app is valid', async(): Promise<void> => {
            source.checkAcr.mockResolvedValueOnce(true);
            let result: ResponseDescription = await handler.handleRequest(request, response, body);
            expect(result.statusCode).toEqual(401);

            let stream: any = result.data;
            let obj = await readJsonStream(stream);
            let VPR = obj.VerifiablePresentation;
            let nonce = VPR.challenge;
            let domain = VPR.domain;
            let appName = VPR.appName;
            let iss = VPR.query.credentialQuery.issuer.id;
            let usr = VPR.query.credentialQuery.credentialSubject.id;
            
            expect(nonce).toBeDefined();
            expect(handler['nonceDomainMap'].get(nonce)).toEqual(domain);
            expect(appName).toEqual(body.app);
            expect(domain).toEqual(request.url);
            expect(iss).toEqual(body.vcissuer);
            expect(usr).toEqual(body.user);
        });
    });

    describe('when a secondary request does not contain a valid nonce', (): void => {
        const request = {
            method: 'GET',
            headers: {
                "vp": "testvpjwt"
            },
        } as any as HttpRequest;
        request.url = 'www.example.com/test-resource';

        it('determines that it is a secondary request', async(): Promise<void> => {
            expect(handler.isSecondaryRequest(request)).toEqual(true);
        });

        it('detects that the nonce and domain are not valid, throws error', async(): Promise<void> => {
            source.extractNonceAndDomain.mockResolvedValue({nonce: 'invalidnonce', domain: 'www.example.com/test-resource'});
            const result = handler.handleRequest(request, response, body);
            await expect(result).rejects.toThrow("Invalid Nonce and Domain.");
        });
    });

    describe('when a secondary request does not contain a valid domain', (): void => {
        const request = {
            method: 'GET',
            headers: {
                "vp": "testvpjwt"
            },
        } as any as HttpRequest;
        request.url = 'www.example.com/test-resource';

        it('determines that it is a secondary request', async(): Promise<void> => {
            expect(handler.isSecondaryRequest(request)).toEqual(true);
        });

        it('detects that the nonce and domain are not valid, throws error', async(): Promise<void> => {
            source.extractNonceAndDomain.mockResolvedValue({nonce: 'validnonce', domain: 'differentdomain.com'});
            handler['nonceDomainMap'].set('validnonce','www.example.com/test-resource');
            const result = handler.handleRequest(request, response, body);
            await expect(result).rejects.toThrow("Invalid Nonce and Domain.");
        });
    });

    describe('when a secondary request does not contain a nonce or domain', (): void => {
        const request = {
            method: 'GET',
            headers: {
                "vp": "testvpjwt"
            },
        } as any as HttpRequest;
        request.url = 'www.example.com/test-resource';

        it('determines that it is a secondary request', async(): Promise<void> => {
            expect(handler.isSecondaryRequest(request)).toEqual(true);
        });

        it('throws error if nonce and domain are undefined', async(): Promise<void> => {
            source.extractNonceAndDomain.mockResolvedValue({nonce:undefined, domain:undefined});
            handler['nonceDomainMap'].set('validnonce','www.example.com/test-resource');
            const result = handler.handleRequest(request, response, body);
            await expect(result).rejects.toThrow("Invalid Nonce and Domain.");
        });

        it('throws error if there was an error extracting the nonce and domain', async(): Promise<void> => {
            source.extractNonceAndDomain.mockRejectedValue(new Error('Error Extracting Nonce/Domain'));
            handler['nonceDomainMap'].set('validnonce','www.example.com/test-resource');
            const result = handler.handleRequest(request, response, body);
            await expect(result).rejects.toThrow("Invalid Nonce and Domain.");
        });
    });

    describe('when a secondary request does not contain a valid VP', (): void => {
        const request = {
            method: 'GET',
            headers: {
                "vp": "invalidvpjwt"
            },
        } as any as HttpRequest;

        it('throws error after it cannot verify the VP', async(): Promise<void> => {
            source.handle.mockRejectedValue(new BadRequestHttpError('Error verifying WebID via VP:'));
            const result = handler.handleSecondRequest(request, response);
            await expect(result).rejects.toThrow('Error verifying WebID via VP:');
        });
    });

    describe('when a secondary request is authorised', (): void => {
        const request = {
            method: 'GET',
            headers: {
                "vp": "validjwt"
            },
        } as any as HttpRequest;
        let res: ResponseDescription = new ResponseDescription(200);

        it('uses the result from the VcAuthorizingHandler', async(): Promise<void> => {
            handler['nonceDomainMap'].set('validnonce','validdomain.com');
            source.extractNonceAndDomain.mockResolvedValue({nonce:'validnonce', domain:'validdomain.com'});
            source.handle.mockResolvedValue(res);
            const result = await handler.handleRequest(request, response);
            expect(result).toEqual(res);
        });
    });

    describe('when a secondary request is not authorised', (): void => {
        const request = {
            method: 'GET',
            headers: {
                "vp": "validjwt"
            },
        } as any as HttpRequest;
        let res: ResponseDescription = new ResponseDescription(200);

        it('throws an error', async(): Promise<void> => {
            handler['nonceDomainMap'].set('validnonce','validdomain.com');
            source.extractNonceAndDomain.mockResolvedValue({nonce:'validnonce', domain:'validdomain.com'});
            source.handle.mockRejectedValue(new Error('Authorisation Error'));
            const result = handler.handleRequest(request, response);
            await expect(result).rejects.toThrow('Authorisation Error');
        });
    });
 
});