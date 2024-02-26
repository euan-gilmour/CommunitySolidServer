import type { RequestParser } from '../../../src/http/input/RequestParser';
import type { Operation } from '../../../src/http/Operation';
import { ErrorHandler } from '../../../src/http/output/error/ErrorHandler';
import { ResponseDescription } from '../../../src/http/output/response/ResponseDescription';
import type { ResponseWriter } from '../../../src/http/output/ResponseWriter';
import { BasicRepresentation } from '../../../src/http/representation/BasicRepresentation';
import { RepresentationMetadata } from '../../../src/http/representation/RepresentationMetadata';
import type { HttpRequest } from '../../../src/server/HttpRequest';
import type { HttpResponse } from '../../../src/server/HttpResponse';
import { VcAuthorizingHttpHandler } from '../../../src/server/VcAuthorizingHttpHandler';
import { VcHttpHandler } from '../../../src/server/VcHttpHandler';
import { HttpError } from '../../../src/util/errors/HttpError';
import { readJsonStream } from '../../../src/util/StreamUtil';

describe('A VcHttpHandler', (): void => {
  const response: HttpResponse = {} as any;
  //const body = new BasicRepresentation();
  let body = new BasicRepresentation(JSON.stringify({user: 'test_user',app: 'test_app',vcissuer: 'test_vcissuer'}), 'application/ld+json');
  const operation: Operation = { method: 'POST', target: { path: 'http://localhost:3000/my-pod/test-folder/test-resource.txt' }, preferences: {}, body };
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
      checkAcr: jest.fn()
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
        it('attempts to handle the request.', async(): Promise<void> => {
            const request = {
                method: 'POST',
                headers: {
                    'vc': 'true'
                },
            } as any as HttpRequest;
            expect(handler.canHandle).toReturn;
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
            expect(handler.canHandle).toReturn;
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

        it('Determines that it is an initial request', async(): Promise<void> => {
            expect(handler.isInitialRequest(body)).toEqual(true);
        });

        it('throws an error', async(): Promise<void> => {
            source.checkAcr.mockResolvedValue(false);
            const result = handler.handleRequest(request, response, body);
            await expect(result).rejects.toThrow("Invalid user - app - issuer combination.");
        });
    });

    describe('when a request has a vc header and specifies correct user/app/issuer in the body', (): void => {
        const request = {
            method: 'POST',
            headers: {
                "vc": "true"
            },
        } as any as HttpRequest;
        request.url = 'www.example.com/test-resource';
        let body =  {user: 'test_user',app: 'test_app',vcissuer: 'test_vcissuer'};

        it('Determines that it is an initial request', async(): Promise<void> => {
            expect(handler.isInitialRequest(body)).toEqual(true);
        });

        it('Responds with a 401 HTTP response and creates an appropriate VP Request', async(): Promise<void> => {
            source.checkAcr.mockResolvedValue(true);
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
            expect(appName).toEqual(body.app);
            expect(domain).toEqual(request.url);
            expect(iss).toEqual(body.vcissuer);
            expect(usr).toEqual(body.user);
        });
    });

    
});