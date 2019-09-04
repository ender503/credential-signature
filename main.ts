import { createDocumentLoader, verifyRsaSignature } from "@tangleid/jsonld";

type PublicKeyMeta = {
  id: string;
  type: string;
  controller: string;
  publicKeyPem: string;
};

const verifySignature = async (credential: any, publicKey: PublicKeyMeta) => {
  const did = credential.credentialSubject.id;
  const didDocument = {
    '@context': 'https://w3id.org/security/v2',
    id: publicKey.controller,
    publicKey: [publicKey],
    assertionMethod: [publicKey.id],
  };

  const documentLoader = createDocumentLoader({
    [did]: didDocument,
    [publicKey.id]: { '@context': 'https://w3id.org/security/v2', ...publicKey },
  });

  return verifyRsaSignature(credential, { documentLoader });
};

const main = async () => {
  const credential = {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://schema.org'],
    type: ['VerifiableCredential'],
    issuer: 'did:tangle:5hn4kcwDbDw1CTCj9dox1hZyfUgLNSPyWs6ZTGtTh8Z4gY9ZopihpT83nVQ6DBue4LchuKhJg',
    issuanceDate: '2019-08-01T00:00:00.000Z',
    credentialSubject: {
      id: 'did:tangle:MoWYKbBfezWbsTkYAngUu523F8YQgHfARhWWsTFSN2U45eAMpsSx3DnrV4SyZHCFuyDqjvQdg7',
      publicKey: [
        {
          id: 'did:tangle:MoWYKbBfezWbsTkYAngUu523F8YQgHfARhWWsTFSN2U45eAMpsSx3DnrV4SyZHCFuyDqjvQdg7#keys-1',
          type: 'RsaVerificationKey2018',
          controller: 'did:tangle:MoWYKbBfezWbsTkYAngUu523F8YQgHfARhWWsTFSN2U45eAMpsSx3DnrV4SyZHCFuyDqjvQdg7',
          publicKeyPem:
            '-----BEGIN PUBLIC KEY-----\r\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJX4QF+KpxfXcSJgNfYL\r\n2E+mg2RLCyw4kNfDaWqIb3y48jmxStYGin8Imi35yx0lT7IxKbTtygXVfXR0DAyE\r\ns9KBgAhFv5eMs0YOkGPUVZnbC+mBxA8WbsKTZVoLhx2lNWcZkLNaDiOwqe0+SlT1\r\ninWRCM2b9db+fWWu01tZvnDfNWYi2HluLr6kbYe5I8YU/+c2MM2rG+yPzMKtMz6v\r\nmFHd++AHd56Sl4ge39yMM6x6E9ZS6Flf4CEUq/gw3gyAgtwIhSgvrcc2CORe+0SP\r\nSM3VGtCQq1pBcoRqnCvhmWtfrCFR1/7vln1hnlE0a4A3+m6LexXeXUYZaNT61rhf\r\nyQIDAQAB\r\n-----END PUBLIC KEY-----\r\n',
        },
      ],
    },
    proof: {
      type: 'RsaSignature2018',
      created: '2019-09-03T14:12:56Z',
      'https://w3id.org/security#jws':
        'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..Tm_OzhAfQpTdVR7irxy-6YQpboeIaUomKIAwVp602jhmSXHUlPYqy9hIU1bqFZVvcHLd-AHZUxTB5t0MKx9mljV7muEJBqsUqFzAIrn35G_xPzFy9qiQqq69BCwqdzERXFzLA9blleG0e55nrrvLEgmxUl_t4oqlum-dF89TXwj6G39rbZxG3nvZHrD7L7XLrWAId6G-hABbfMZ7BAL7LxE52N1AQL_nL52VQdTW6OmXkrQplt2M2xbG2fv7UgIbZq8odXoMgZwITibvRAO8wONsoIYJc_-YDHmU9h2wuKcdo-7hraIZY2nJnMz41UKuZCTfKvmo7Z73eS-hdXTsmg',
      'https://w3id.org/security#proofPurpose': { id: 'https://w3id.org/security#assertionMethod' },
      'https://w3id.org/security#verificationMethod': {
        id: 'did:tangle:MoWYKbBfezWbsTkYAngUu523F8YQgHfARhWWsTFSN2U45eAMpsSx3DnrV4SyZHCFuyDqjvQdg7#keys-1',
      },
    },
  };

  const { credentialSubject, proof } = credential;

  const publicKeyId = proof['https://w3id.org/security#verificationMethod'].id;

  const publicKey: PublicKeyMeta | undefined = credentialSubject.publicKey.find((publicKey: PublicKeyMeta) => {
    return publicKey.id === publicKeyId;
  });
  if (!publicKey) {
    throw new Error('Public Key not found.');
  }

  const verified = await verifySignature(credential, publicKey);
  console.log(`verified: ${verified}`);
}

main();
