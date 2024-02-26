import { VcExtractor } from '../../../src/authentication/VcExtractor';

describe('A VcExtractor', (): void => {
    const vcExtractor = new VcExtractor();
    beforeEach((): void => {
        jest.clearAllMocks();
      });

    describe('on a request with an empty body', (): void => {
        const requestBody = {

        } as any as NodeJS.Dict<any>;

        it('returns empty credentials', async(): Promise<void> => {
            const result = await vcExtractor.getCredentials(requestBody);
            expect(result).toEqual({ agent: { webId: undefined }, issuer: { url: undefined }});
        });
    });

    describe('on a request with a user, issuer and app specified in the body', (): void => {
        const requestBody = {
            vcissuer: 'did:web:bob.solidcommunity.net',
            user: 'did:web:alice.solidcommunity.net',
            app: 'exampleApp'
        } as any as NodeJS.Dict<any>;

        it('returns the expected credentials', async(): Promise<void> => {
            const result = await vcExtractor.getCredentials(requestBody);
            expect(result).toEqual({ agent: { webId: 'did:web:alice.solidcommunity.net' }, issuer: { url: 'did:web:bob.solidcommunity.net' }, client: { clientId: 'exampleApp' }});
        });
    });
});
