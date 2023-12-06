//import type { RequestMethod } from '@solid/access-token-verifier';
//import { createSolidTokenVerifier } from '@solid/access-token-verifier';
//import type { TargetExtractor } from '../http/input/identifier/TargetExtractor';
import { getLoggerFor } from '../logging/LogUtil';
import type { HttpRequest } from '../server/HttpRequest';
import { BadRequestHttpError } from '../util/errors/BadRequestHttpError';
import { NotImplementedHttpError } from '../util/errors/NotImplementedHttpError';
//import { matchesAuthorizationScheme } from '../util/HeaderUtil';
import type { Credentials } from './Credentials';
import { CredentialsExtractor } from './CredentialsExtractor';


/**
 * Credentials extractor that extracts User, App and Issuer from HTTP request.
 * 
 * 
 */
export class VcExtractor extends CredentialsExtractor {
  protected readonly logger = getLoggerFor(this);

  public constructor() {
    super();
  }

  public async canHandle({ headers }: HttpRequest): Promise<void> {  
    if(headers['vcissuer'] && headers['user'] && headers['app']){
      //this.logger.info(`Found VC Issuer header in HTTP request : ${headers['vcissuer']}`);
    }else{
      //this.logger.info("Did not find VC Issuer header in HTTP request");
      throw new NotImplementedHttpError('No VC issuer specified in the request header.');
    }
  }

  public async handle(request: HttpRequest): Promise<Credentials> {
    try {
      const issuer: any = request.headers['vcissuer']; //issuer of the relevant vc the user holds
      const webId: any = request.headers['user']; //user sending request
      const clientId: any = request.headers['app']; //name of application
      const credentials : Credentials = {
        agent: {webId: webId},
        issuer: {url: issuer}
      };
      if (clientId) {
        credentials.client = { clientId };
      }
      //this.logger.info(`Retrieved credentials in VC based request. WebID: ${webId}, 
      //client ID: ${clientId}, issuer: ${issuer}`);
      
      return credentials;
    } catch (error: unknown) {
      const message = `Error retrieving credentials via VC based request: ${(error as Error).message}`;
      this.logger.warn(message);
      throw new BadRequestHttpError(message, { cause: error });
    }
  }
}


//(old code from DPoPWebIdExtractor)
/*
export class VcExtractor extends CredentialsExtractor {
  private readonly originalUrlExtractor: TargetExtractor;
  private readonly verify = createSolidTokenVerifier();
  protected readonly logger = getLoggerFor(this);

  /**
   * @param originalUrlExtractor - Reconstructs the original URL as requested by the client
   */
  /*
  public constructor(originalUrlExtractor: TargetExtractor) {
    super();
    this.originalUrlExtractor = originalUrlExtractor;
  }

  public async canHandle({ headers }: HttpRequest): Promise<void> {
    const { authorization } = headers;
    if (!matchesAuthorizationScheme('DPoP', authorization)) {
      throw new NotImplementedHttpError('No DPoP-bound Authorization header specified.');
    }
  }

  public async handle(request: HttpRequest): Promise<Credentials> {
    const { headers: { authorization, dpop }, method } = request;
    if (!dpop) {
      throw new BadRequestHttpError('No DPoP header specified.');
    }

    // Reconstruct the original URL as requested by the client,
    // since this is the one it used to authorize the request
    const originalUrl = await this.originalUrlExtractor.handleSafe({ request });

    // Validate the Authorization and DPoP header headers
    // and extract the WebID provided by the client
    try {
      const { webid: webId, client_id: clientId, iss: issuer } = await this.verify(
        authorization!,
        {
          header: dpop as string,
          method: method as RequestMethod,
          url: originalUrl.path,
        },
      );
      this.logger.info(`Verified WebID via DPoP-bound access token. WebID: ${webId
      }, client ID: ${clientId}, issuer: ${issuer}`);
      const credentials: Credentials = { agent: { webId }, issuer: { url: issuer }};
      if (clientId) {
        credentials.client = { clientId };
      }
      return credentials;
    } catch (error: unknown) {
      const message = `Error verifying WebID via DPoP-bound access token: ${(error as Error).message}`;
      this.logger.warn(message);
      throw new BadRequestHttpError(message, { cause: error });
    }
  }
}*/
