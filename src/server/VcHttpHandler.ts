import type { RequestParser } from '../http/input/RequestParser';
import type { ErrorHandler } from '../http/output/error/ErrorHandler';
import { ResponseDescription } from '../http/output/response/ResponseDescription';
import type { ResponseWriter } from '../http/output/ResponseWriter';
import { getLoggerFor } from '../logging/LogUtil';
import { assertError } from '../util/errors/ErrorUtil';
import { HttpError } from '../util/errors/HttpError';
import type { HttpHandlerInput } from './HttpHandler';
import { HttpHandler } from './HttpHandler';
import type { HttpRequest } from './HttpRequest';
import type { HttpResponse } from './HttpResponse';
import type { OperationHttpHandler } from './OperationHttpHandler';
import { BasicRepresentation } from '../http/representation/BasicRepresentation';
import { VcAuthorizingHttpHandler } from './VcAuthorizingHttpHandler';
import { readJsonStream } from '../util/StreamUtil';
import { Operation } from '../http/Operation';

export interface VcHttpHandlerArgs {
  /**
   * Parses the incoming requests.
   */
  requestParser: RequestParser;
  /**
   * Converts errors to a serializable format.
   */
  errorHandler: ErrorHandler;
  /**
   * Writes out the response of the operation.
   */
  responseWriter: ResponseWriter;
  /**
   * Handler to send the operation to.
   */
  operationHandler: VcAuthorizingHttpHandler;

}

/**
 * Detects HTTP requests that intend to follow a VC-based authentication and authorization protocol
 * Parses requests and sends the resulting {@link Operation} to the wrapped {@link OperationHttpHandler}.
 * Errors are caught and handled by the {@link ErrorHandler}.
 * In case the {@link OperationHttpHandler} returns a result it will be sent to the {@link ResponseWriter}.
 */

/**
 * Initial message:
 * 1) Request is received for a resource:
 *  -it has 'VC' in its header - indicating this will be vc based protocol
 *  -body contains user and vc issuer
 * 2) Check acp policy for matching user and vc issuer, using call to checkAcr method on VcAuthorizingHttpHandler
 *  -generate nonce and domain, and save them in map
 *  -generate VP request, include nonce and domain and respond with it in a 401 message
 * 
 * Second message:
 * 1) Request is received with 'VP' in its header - indicates verifiable presentation
 *  -check nonce and domain are valid compared with saved values
 *  -pass data to VcAuthorizingHttpHandler to try to authorize
 *    -VpChecker should be called from there to verify VP and extract issuer and user credentials from it
 *    -perform steps for it to be authorized
 */
export class VcHttpHandler extends HttpHandler {
  private readonly logger = getLoggerFor(this);

  private readonly requestParser: RequestParser;
  private readonly errorHandler: ErrorHandler;
  private readonly responseWriter: ResponseWriter;

  private readonly operationHandler: VcAuthorizingHttpHandler;
  private nonceDomainMap: Map<any, any>;//nonce: domain

  public constructor(args: VcHttpHandlerArgs) {
    super();
    this.requestParser = args.requestParser;
    this.errorHandler = args.errorHandler;
    this.responseWriter = args.responseWriter;
    this.operationHandler = args.operationHandler;
    this.nonceDomainMap = new Map<any, any>();
  }

  public async handle({ request, response }: HttpHandlerInput): Promise<void> {
    let result: ResponseDescription;
    let body: NodeJS.Dict<any>;

    //extract body from http request
    const operation = await this.requestParser.handleSafe(request);
    try{
      body = await readJsonStream(operation.body.data);
    }catch(error: unknown){
      body = {};
      result = await this.handleError(error, request);
    }

    try {
      result = await this.handleRequest(request, response, body);
    } catch (error: unknown) {
      result = await this.handleError(error, request);
    }

    if (result) {
      this.logger.info('Sending Response...');
      return await this.responseWriter.handleSafe({ response, result });
    }
  }

  //This handler will only respond to requests that have:
  //-a 'vc' header (Initial Request)
  //-a 'vp' header (Secondary Request/Verifiable Presentation) 
  public async canHandle({ request, response }: HttpHandlerInput): Promise<void> {
    if((request.headers['vc'] !== undefined) || 
    (request.headers['vp'] !== undefined)){
      return;
    }else{
      throw new Error("Required headers missing: 'VC' or 'VP'.");
    }
  }

  /**
   * Interprets the request and generates a response description that can be used by the ResponseWriter to respond
   */
  protected async handleRequest(request: HttpRequest, response: HttpResponse, body: NodeJS.Dict<any>):
  Promise<ResponseDescription> {
    const operation = await this.requestParser.handleSafe(request);

    //handle if it is the initial request
    if(this.isInitialRequest(body)){
      this.logger.info('Detected Initial Request');
      //check the vc headers are valid for the requested resource
      if(await this.validUserAppIssuer(request, body)){
        return await this.handleInitialRequest(request, body);
      }else{
        throw new Error('Invalid user - app - issuer combination.');
      }
      //handle if it is the secondary request - proceed with authorization checks to verify VP
    }else if(this.isSecondaryRequest(request)){
      this.logger.info('Detected Secondary Request');
      if(await this.validNonceAndDomain(request)){
        return await this.handleSecondRequest(request, response);
      }else{
        throw new Error('Invalid Nonce and Domain.');
      }
    }

    const result = await this.operationHandler.handleSafe({ operation, request, response });
    //result gets returned and written into response outputted
    this.logger.verbose(`Parsed ${operation.method} operation on ${operation.target.path}`);
    return result;
  }

  /**
   * Handles the error output correctly based on the preferences.
   */
  protected async handleError(error: unknown, request: HttpRequest): Promise<ResponseDescription> {
    assertError(error);
    const result = await this.errorHandler.handleSafe({ error, request });
    if (HttpError.isInstance(error) && result.metadata) {
      const quads = error.generateMetadata(result.metadata.identifier);
      result.metadata.addQuads(quads);
    }
    return result;
  }

  //checks ACP policy to see if user, app, issuer combination match requested resource's access rules
  public async validUserAppIssuer(request: HttpRequest, body: NodeJS.Dict<any>) : Promise<boolean>{
    //this should check acr file and it return true the permissions match
    const operation = await this.requestParser.handleSafe(request);
    const isValid : boolean = await this.operationHandler.checkAcr(operation, body);
    if(isValid){
      this.logger.info("Valid User/App/Issuer combination");
    }else{
      this.logger.info("Invalid User/App/Issuer combination");
    }
    return isValid;
  }

  //initial request will contain header with vc issuer, app, user
  public isInitialRequest(body: NodeJS.Dict<any>) : boolean{
    return (body['vcissuer'] !== undefined && 
    body['app'] !== undefined && 
    body['user'] !== undefined);
  }

  //the secondary request will contain a VP in the header
  public isSecondaryRequest(request: HttpRequest) : boolean{
    return request.headers['vp']!==undefined;
  }

  //deal with the initial request and respond with a VP request
  public async handleInitialRequest(request: HttpRequest, body: NodeJS.Dict<any>) : Promise<ResponseDescription>{
    const crypto = require('crypto');
    const nonce = crypto.randomBytes(16).toString('base64');
    this.logger.info(`Generated Nonce: ${nonce}`);
    const uri = request.url;
    //store nonce and domain in the map
    this.nonceDomainMap.set(nonce, uri);

    let result : ResponseDescription = new ResponseDescription(401);

    //TODO - proper way to generate VP Request
    //just a placeholder based on examples such as https://w3c-ccg.github.io/vp-request-spec/#browser-credential-handler-api-chapi
    let VPrequest = {
      "VerifiablePresentation": {
        "query": {
          "type": "QueryByExample",
          "credentialQuery": {
            "reason": "We need you to prove your eligibility.",
            "example": {
              "@context": [
                "https://www.w3.org/2018/credentials/v1",
              ],
              "type": "BachelorDegree"
            }
          }
        },
        "challenge": nonce,
        "domain": uri
      },
    };
    const representation = new BasicRepresentation(JSON.stringify(VPrequest), 'application/ld+json');
    result.data = representation.data;
    return result;
  }

  /**
   * VP checking code
   */

  public async handleSecondRequest(request: HttpRequest, response: HttpResponse): Promise<ResponseDescription>{
    //verify VP
      const operation = await this.requestParser.handleSafe(request);
      try{
        let result = this.operationHandler.handle({operation, request, response});
        const {nonce} = await this.operationHandler.extractNonceAndDomain(request);
        this.nonceDomainMap.delete(nonce);
        return result;
      }catch(error: unknown){
        throw new Error('Verifiable Presentation could not be verified. Access denied.');
      }
  }

  //if the nonce matches a saved nonce, check the domain also matches
  public async validNonceAndDomain(request: HttpRequest) : Promise<boolean>{
    this.logger.info('Checking Nonce and Domain...')
    const {nonce, domain} = await this.operationHandler.extractNonceAndDomain(request);
    console.log(`VP Nonce: ${nonce}, Domain: ${domain}`);
    if(this.nonceDomainMap.has(nonce)){
      return domain === this.nonceDomainMap.get(nonce);
    }
    return false;
  }

}
