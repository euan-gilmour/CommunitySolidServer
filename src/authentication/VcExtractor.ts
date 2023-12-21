import { getLoggerFor } from '../logging/LogUtil';
import { HttpRequest } from '../server/HttpRequest';
import { BadRequestHttpError } from '../util/errors/BadRequestHttpError';
import type { Credentials } from './Credentials';


/**
 * Credentials extractor that extracts User, App and Issuer from HTTP request.
 */
export class VcExtractor {
  protected readonly logger = getLoggerFor(this);

  public constructor() {
    //super();
  }

  //get credentials if called from WacAllowHttpHandler
  // public async handle(request: HttpRequest): Promise<Credentials>{
  //   let accessToken: any = request.headers['accessToken'];
  //   let credentials: any = accessToken['credentials'];

  //   return credentials;
  // }

  public async getCredentials(body: NodeJS.Dict<any>): Promise<Credentials>{
    try {
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
    }catch (error: unknown) {
      const message = `Error retrieving credentials via VC based request: ${(error as Error).message}`;
      this.logger.warn(message);
      throw new BadRequestHttpError(message, { cause: error });
    }
  }
}
