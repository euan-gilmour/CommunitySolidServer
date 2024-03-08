import { getLoggerFor } from '../logging/LogUtil';
import type { HttpRequest } from '../server/HttpRequest';
import { BadRequestHttpError } from '../util/errors/BadRequestHttpError';
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
      throw new BadRequestHttpError('No VP header specified.');
    }
  }

  public async handle(request: HttpRequest): Promise<Credentials> {
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
    let VP = request.headers['vp']?.toString();
    if(VP){
      try{
        let payload = decodeJWT(VP).payload;
        let nonce = payload.nonce;
        let domain = payload.domain;
        return {nonce: nonce, domain: domain};
      }catch(error){
        throw new Error('Cannot decode VP JWT.');
      }
    }
  }

  //Verify the vp - should be received as a jwt contained within the header
  //If valid, extract the issuer and user and return as credentials. Else throw error
  public async verify(request: HttpRequest){
    this.logger.info('Verifying VP...');
    const vpJwt: any = request.headers['vp'];
    const resolver = new Resolver(getResolver());

    //Check expiry date of VP
    let now = Math.ceil(Date.now()/1000);
    let VpPayload = decodeJWT(vpJwt).payload;
    if(VpPayload.exp !== undefined && VpPayload.exp < now){
      this.logger.warn(`VP expired. Time now: ${now}, Expiry Date: ${VpPayload.exp}`);
      throw new Error(`VP has expired.`);
    }

    const verifiedVP = await verifyPresentation(vpJwt, resolver);
    //Check VP is valid
    const validVP = verifiedVP.verified;
    this.logger.info('Verified? : '+validVP)
    console.log(verifiedVP.payload);

    this.logger.info('Verifying VC...');
    //Extract the VC from the JWT VP payload and check it is valid
    const vcJwt = verifiedVP.payload.vp.verifiableCredential[0];
    const verifiedVC = await verifyCredential(vcJwt, resolver);
    const validVC = verifiedVC.verified;
    this.logger.info('Verified? : '+validVC);
    console.log(verifiedVC.payload);

    let clientId: any;
    if(VpPayload.appName){
      clientId = VpPayload.appName;
    }
    //The agent is the subject of the VC
    const webid: any = verifiedVC.payload.sub;
    //The issuer is the issuer of the VC
    const iss: any = verifiedVC.payload.iss;
    return { webid: webid, client_id: clientId, iss: iss };
  }
}
