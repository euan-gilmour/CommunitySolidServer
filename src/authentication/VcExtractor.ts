import { getLoggerFor } from '../logging/LogUtil';
import type { Credentials } from './Credentials';


/**
 * Simple Credentials extractor that can extract User, App and Issuer from body of HTTP request.
 */
export class VcExtractor {
  protected readonly logger = getLoggerFor(this);

  public constructor() {

  }

  public async getCredentials(body: NodeJS.Dict<any>): Promise<Credentials>{
    const issuer: any = body['vcissuer']; //issuer of the relevant vc the user holds
    const webId: any = body['user']; //user sending request
    const clientId: any = body['app']; //name of application
    const credentials : Credentials = {
      agent: {webId: webId},
      issuer: {url: issuer}
    };
    if (clientId) {
      credentials.client = { clientId };
    }
    return credentials;
  }
}
