import { getLoggerFor } from '../logging/LogUtil';
import type { HttpRequest } from '../server/HttpRequest';
import { BadRequestHttpError } from '../util/errors/BadRequestHttpError';
import { NotImplementedHttpError } from '../util/errors/NotImplementedHttpError';
import { matchesAuthorizationScheme } from '../util/HeaderUtil';
import type { Credentials } from './Credentials';
import { CredentialsExtractor } from './CredentialsExtractor';
import { Resolver } from 'did-resolver';
import { getResolver } from 'web-did-resolver';
import { verifyCredential, verifyPresentation } from 'did-jwt-vc';
import {decodeJWT} from 'did-jwt';

export class VpChecker extends CredentialsExtractor {
  protected readonly logger = getLoggerFor(this);

  public constructor() {
    super();
  }

  public async canHandle({ headers }: HttpRequest): Promise<void> {
    if(headers['vp'] === undefined){
      throw new NotImplementedHttpError('No VP header specified.');
    }
  }

  public async handle(request: HttpRequest): Promise<Credentials> {
    const { headers: { authorization }} = request;

    try {
      const { webid: webId, client_id: clientId, iss: issuer } = await this.verify(request);
      this.logger.info(`Verified credentials via VP. WebID: ${webId
      }, client ID: ${clientId}, issuer: ${issuer}`);
      const credentials: Credentials = { agent: { webId }, issuer: { url: issuer }};
      if (clientId) {
        credentials.client = { clientId };
      }
      return credentials;
    } catch (error: unknown) {
      const message = `Error verifying WebID via VP: ${(error as Error).message}`;
      this.logger.warn(message);
      throw new BadRequestHttpError(message, { cause: error });
    }
  }

  public async extractNonceAndDomain(request: HttpRequest): Promise<any>{
    //this.logger.info('Extracting nonce and domain...');
    let VP = request.headers['vp']?.toString();
    if(VP){
      let payload = decodeJWT(VP).payload;
      let nonce = payload.nonce;
      let domain = payload.domain;
      //this.logger.info(`Nonce: ${nonce}, Domain: ${domain}`);
      return {nonce: nonce, domain: domain};
    }
    return null;
  }

  //verify the vp - should be received as a jwt contained within the header
  //if valid, extract the issuer and user and return as credentials. Else throw error
  public async verify(request: HttpRequest){
    this.logger.info('Verifying VP...');
    const vpJwt: any = request.headers['vp'];
    const resolver = new Resolver(getResolver());

    const verifiedVP = await verifyPresentation(vpJwt, resolver)
    //console.log(verifiedVP)
    //check VP is valid
    const validVP = verifiedVP.verified;

    //check expiry date of VP here because the library doesn't seem to do it properly.
    let now = Math.ceil(Date.now()/1000);
    if(verifiedVP.payload.exp !== undefined && verifiedVP.payload.exp < now){
      this.logger.warn(`VP expired. Time now: ${now}, Expiry Date: ${verifiedVP.payload.exp}`);
      throw new Error(`Error: VP has Expired`);
    }

    this.logger.info('Verified? : '+validVP)

    if(!validVP){
      this.logger.warn('Invalid VP');
      throw new Error(`Error: Invalid VP`);
    }
    console.log(verifiedVP.payload);

    this.logger.info('Verifying VC...');
    //extract the VC from the JWT VP payload and check it is valid
    const vcJwt = verifiedVP.payload.vp.verifiableCredential[0];
    const verifiedVC = await verifyCredential(vcJwt, resolver);
    const validVC = verifiedVC.verified;
    this.logger.info('Verified? : '+validVC);
    if(!validVC){
      this.logger.warn('Invalid VC');
      throw new Error(`Error: Invalid VC`);
    }
    console.log(verifiedVC.payload);

    let clientId: any;
    let payload = decodeJWT(vpJwt).payload;
    if(payload.appName){
      clientId = payload.appName;
    }
    
    //the agent is the holder of the VP?
    //const webid = verifiedVP.verifiablePresentation.holder;

    //the agent is the subject of the VC?
    const webid: any = verifiedVC.payload.sub;

    //the issuer is the issuer of the VC
    const iss: any = verifiedVC.payload.iss;
    return { webid: webid, client_id: clientId, iss: iss };
  }
}
