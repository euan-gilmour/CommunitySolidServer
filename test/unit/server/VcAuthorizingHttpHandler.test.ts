import type { Authorizer } from '../../../src/authorization/Authorizer';
import type { PermissionReader } from '../../../src/authorization/PermissionReader';
import type { ModesExtractor } from '../../../src/authorization/permissions/ModesExtractor';
import type { AccessMap, PermissionMap } from '../../../src/authorization/permissions/Permissions';
import { AccessMode } from '../../../src/authorization/permissions/Permissions';
import type { Operation } from '../../../src/http/Operation';
import { BasicRepresentation } from '../../../src/http/representation/BasicRepresentation';
import { VcAuthorizingHttpHandler } from '../../../src/server/VcAuthorizingHttpHandler';
import type { HttpRequest } from '../../../src/server/HttpRequest';
import type { HttpResponse } from '../../../src/server/HttpResponse';
import type { OperationHttpHandler } from '../../../src/server/OperationHttpHandler';
import { IdentifierMap, IdentifierSetMultiMap } from '../../../src/util/map/IdentifierMap';
import { VcExtractor } from '../../../src/authentication/VcExtractor';
import { VpChecker } from '../../../src/authentication/VpChecker';

describe('A VcAuthorizingHttpHandler', (): void => {
  const credentials = { };
  const target = { path: 'http://example.com/foo' };
  const requestedModes: AccessMap = new IdentifierSetMultiMap<AccessMode>([[ target, AccessMode.read ]]);
  const availablePermissions: PermissionMap = new IdentifierMap(
    [[ target, { read: true }]],
  );
  const request: HttpRequest = {} as any;
  const response: HttpResponse = {} as any;
  let operation: Operation;
  let credentialsExtractor: jest.Mocked<VcExtractor>;
  let vpChecker: jest.Mocked<VpChecker>;
  let modesExtractor: jest.Mocked<ModesExtractor>;
  let permissionReader: jest.Mocked<PermissionReader>;
  let authorizer: jest.Mocked<Authorizer>;
  let source: jest.Mocked<OperationHttpHandler>;
  let handler: VcAuthorizingHttpHandler;

  beforeEach(async(): Promise<void> => {
    operation = {
      target,
      method: 'GET',
      preferences: {},
      body: new BasicRepresentation(),
    };

    credentialsExtractor = {
      getCredentials: jest.fn().mockResolvedValue(credentials),
    } as any;
    vpChecker = {
      handleSafe: jest.fn().mockResolvedValue(credentials),
      handle: jest.fn().mockResolvedValue(credentials),
      extractNonceAndDomain:jest.fn(),
    } as any;
    modesExtractor = {
      handleSafe: jest.fn().mockResolvedValue(requestedModes),
    } as any;
    permissionReader = {
      handleSafe: jest.fn().mockResolvedValue(availablePermissions),
    } as any;
    authorizer = {
      handleSafe: jest.fn(),
    } as any;
    source = {
      handleSafe: jest.fn(),
    } as any;

    handler = new VcAuthorizingHttpHandler(
      { credentialsExtractor, vpChecker, modesExtractor, permissionReader, authorizer, operationHandler: source },
    );
  });

  it('errors if authorisation fails due to VpChecker error.', async(): Promise<void> => {
    const error = Error('Error verifying WebID via VP')
    vpChecker.handle.mockRejectedValue(error);
    await expect(handler.handle({ request, response, operation })).rejects.toThrow(error);
    expect(source.handleSafe).toHaveBeenCalledTimes(0);
  });

  it('errors if authorisation fails due to authorizer error.', async(): Promise<void> => {
    const error = Error('Authorisation error')
    authorizer.handleSafe.mockRejectedValue(error);
    await expect(handler.handle({ request, response, operation })).rejects.toThrow(error);
    expect(source.handleSafe).toHaveBeenCalledTimes(0);
  });

  describe('successful authorisation after verifying VP', (): void => {
    it('goes through all the steps for authorisation', async(): Promise<void> => {
      await expect(handler.handle({ request, response, operation })).resolves.toBeUndefined();
      expect(vpChecker.handle).toHaveBeenCalledTimes(1);
      expect(vpChecker.handle).lastCalledWith(request);
      expect(modesExtractor.handleSafe).toHaveBeenCalledTimes(1);
      expect(modesExtractor.handleSafe).toHaveBeenLastCalledWith(operation);
      expect(permissionReader.handleSafe).toHaveBeenCalledTimes(1);
      expect(permissionReader.handleSafe).toHaveBeenLastCalledWith({ credentials, requestedModes });
      expect(authorizer.handleSafe).toHaveBeenCalledTimes(1);
      expect(authorizer.handleSafe).toHaveBeenLastCalledWith({ credentials, requestedModes, availablePermissions });
      expect(source.handleSafe).toHaveBeenCalledTimes(1);
      expect(source.handleSafe).toHaveBeenLastCalledWith({ request, response, operation });
    });
  });

  describe('when retrieving credentials from VcExtractor', (): void => {
    let body =  {};
    it('gets credentials object', async(): Promise<void> => {
      let result = await handler.getCredentials(body);
      expect(result).toEqual(credentials);
    });
  });

  describe('when retrieving nonce and domain from VpChecker', (): void => {
    it('gets nonce and domain if they were returned by VpChecker', async(): Promise<void> => {
      let nonceAndDomain = {nonce:'examplenonce', domain:'domain.com'};
      vpChecker.extractNonceAndDomain.mockResolvedValueOnce(nonceAndDomain);
      let result = await handler.extractNonceAndDomain(request);
      expect(result).toEqual(nonceAndDomain);
    });
    it('throws an error if an error was thrown by VpChecker', async(): Promise<void> => {
      let err = new Error('error')
      vpChecker.extractNonceAndDomain.mockRejectedValueOnce(err);
      let result = handler.extractNonceAndDomain(request);
      await expect(result).rejects.toThrow('error');
    });
  });

  describe('when checking permissions and requested modes match', (): void => {
    let body = {};
    let modes: AccessMap = new IdentifierSetMultiMap<AccessMode>([[ target, AccessMode.read ]]);
    let permissions: PermissionMap = new IdentifierMap(
      [[ target, { read: true }]],
    );
    it('returns true when they match', async(): Promise<void> => {   
        modesExtractor.handleSafe.mockResolvedValueOnce(modes); 
        permissionReader.handleSafe.mockResolvedValueOnce(permissions);  
        const result = await handler.checkAcr(operation, body);
        expect(result).toEqual(true);
    });
    it('returns false when they do not match', async(): Promise<void> => { 
      modesExtractor.handleSafe.mockResolvedValueOnce(new IdentifierSetMultiMap<AccessMode>([[ target, AccessMode.read ]]));   
      permissionReader.handleSafe.mockResolvedValueOnce(new IdentifierMap(
        [[ target, {}]],
      ));  
      const result = await handler.checkAcr(operation, body);
      expect(result).toEqual(false);
    });
  });

});
