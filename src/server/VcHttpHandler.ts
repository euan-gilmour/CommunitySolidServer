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
 * Initial message:
 * 1) Request is received for a resource:
 *  -It has 'VC' in its header - indicating this will be vc based protocol
 *  -Body contains user and vc issuer
 * 2) Check acp policy for matching user and vc issuer, using call to checkAcr method on VcAuthorizingHttpHandler
 *  -Generate nonce and domain, and save them in map
 *  -Generate VP request, include nonce and domain and respond with it in a 401 message
 * 
 * Second message:
 * 1) Request is received with 'VP' in its header - indicates verifiable presentation
 *  -Check nonce and domain are valid compared with saved values
 *  -Pass data to VcAuthorizingHttpHandler to try to authorize
 *    -VpChecker should be called from there to verify VP and extract issuer and user credentials from it
 *    -Perform steps for it to be authorized
 *  -Return response
 */
export class VcHttpHandler extends HttpHandler {
  private readonly logger = getLoggerFor(this);

  private readonly requestParser: RequestParser;
  private readonly errorHandler: ErrorHandler;
  private readonly responseWriter: ResponseWriter;

  private readonly operationHandler: VcAuthorizingHttpHandler;
  private nonceDomainMap: Map<any, any>;

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
    let body: NodeJS.Dict<any> = {};

    //Extract body from http request
    const operation = await this.requestParser.handleSafe(request);
    try{
      if(operation.body.data !== undefined){
        body = await readJsonStream(operation.body.data);
      }
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
  //-'vc' header (Initial Request)
  //-'vp' header (Secondary Request/Verifiable Presentation) 
  public async canHandle({ request, response }: HttpHandlerInput): Promise<void> {
    if((request.headers['vc'] === undefined) && 
    (request.headers['vp'] === undefined)){
      throw new Error("Required headers missing: 'VC' or 'VP'.");      
    }
  }

  /**
   * Interprets the request and generates a response description that can be used by the ResponseWriter to respond
   */
  public async handleRequest(request: HttpRequest, response: HttpResponse, body?: NodeJS.Dict<any>):
  Promise<ResponseDescription> {
    const operation = await this.requestParser.handleSafe(request);

    //Handle if it is the initial request
    if((request.headers['vc'] !== undefined) && body && (this.isInitialRequest(body))){
      this.logger.info('Detected Initial Request');
      if(await this.validUserAppIssuer(request, body)){
        return await this.handleInitialRequest(request, body);
      }else{
        throw new Error('Invalid user - app - issuer combination.');
      }
    //Handle if it is the secondary request - proceed with authorization checks to verify VP
    }else if(this.isSecondaryRequest(request)){
      this.logger.info('Detected Secondary Request');
      if(await this.validNonceAndDomain(request)){
        try{
          return await this.handleSecondRequest(request, response);
        }catch(error){
          throw error;
        }
      }else{
        this.logger.info('Invalid Nonce and Domain');
        throw new Error('Invalid Nonce and Domain.');
      }
    }else{
      throw new Error('Request not recognised');
    }
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

  //Checks ACP policy to see if user, app, issuer combination match requested resource's access rules
  public async validUserAppIssuer(request: HttpRequest, body: NodeJS.Dict<any>) : Promise<boolean>{
    const operation = await this.requestParser.handleSafe(request);
    const isValid : boolean = await this.operationHandler.checkAcr(operation, body);
    if(isValid){
      this.logger.info("Valid User/App/Issuer combination");
    }else{
      this.logger.info("Invalid User/App/Issuer combination");
    }
    return isValid;
  }

  //Initial request body will indicate vc issuer, app, user
  public isInitialRequest(body: NodeJS.Dict<any>) : boolean{
    return (body['vcissuer'] !== undefined && 
    body['app'] !== undefined && 
    body['user'] !== undefined);
  }

  //The secondary request will contain a VP in the header
  public isSecondaryRequest(request: HttpRequest) : boolean{
    return request.headers['vp']!==undefined;
  }

  //Deal with the initial request and respond with a VP Request
  public async handleInitialRequest(request: HttpRequest, body: NodeJS.Dict<any>) : Promise<ResponseDescription>{
    const crypto = require('crypto');
    const nonce = crypto.randomBytes(16).toString('base64');
    this.logger.info(`Generated Nonce: ${nonce}`);
    const uri = request.url;
    //Store nonce and domain in the map
    this.nonceDomainMap.set(nonce, uri);
    let result : ResponseDescription = new ResponseDescription(401);
    let VPrequest = {
      "VerifiablePresentation": {
        "query": {
          "type": "QueryByExample",
          "credentialQuery": {
            "reason": "We need you to prove your eligibility.",
            "credentialSubject":{
              "id": body['user'],
            },
            "issuer":{
              "id": body['vcissuer'],
            }
          }
        },
        "challenge": nonce,
        "domain": uri,
        "appName": body['app']
      },
    };
    const representation = new BasicRepresentation(JSON.stringify(VPrequest), 'application/ld+json');
    result.data = representation.data;
    return result;
  }

  public async handleSecondRequest(request: HttpRequest, response: HttpResponse): Promise<ResponseDescription>{
      const operation = await this.requestParser.handleSafe(request);
      try{
        let result = await this.operationHandler.handle({operation, request, response});
        const {nonce} = await this.operationHandler.extractNonceAndDomain(request);
        this.nonceDomainMap.delete(nonce);
        return result;
      }catch(error: unknown){
        throw error;
      }
  }

  public async validNonceAndDomain(request: HttpRequest) : Promise<boolean>{
    this.logger.info('Checking Nonce and Domain...');
    try{
      const obj = await this.operationHandler.extractNonceAndDomain(request);
      let nonce = obj.nonce;
      let domain = obj.domain;
      if(nonce !== undefined && this.nonceDomainMap.has(nonce)){
        return domain === this.nonceDomainMap.get(nonce);
      }else{
        return false;
      }
    }catch(error){
      return false;
    }
  }
}
