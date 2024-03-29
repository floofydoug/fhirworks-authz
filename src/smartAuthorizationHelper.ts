/*
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *  SPDX-License-Identifier: Apache-2.0
 */
import { FhirVersion, UnauthorizedError } from 'fhir-works-on-aws-interface';
import jwksClient, { JwksClient, Headers } from 'jwks-rsa';
import { decode, verify } from 'jsonwebtoken';
import axios from 'axios';
import { get } from 'lodash';
import resourceReferencesMatrixV4 from './schema/fhirResourceReferencesMatrix.v4.0.1.json';
import resourceReferencesMatrixV3 from './schema/fhirResourceReferencesMatrix.v3.0.1.json';
import { AccessModifier, FhirResource, IntrospectionOptions } from './smartConfig';
import { convertScopeToSmartScope } from './smartScopeHelper';

import getComponentLogger from './loggerBuilder';

const logger = getComponentLogger();

export const FHIR_USER_REGEX =
    /^(?<hostname>(http|https):\/\/([A-Za-z0-9\-\\.:%$_/])+)\/(?<resourceType>Person|Practitioner|RelatedPerson|Patient)\/(?<id>[A-Za-z0-9\-.]+)$/;
export const FHIR_RESOURCE_REGEX =
    /^((?<hostname>(http|https):\/\/([A-Za-z0-9\-\\.:%$_/])+)\/)?(?<resourceType>[A-Z][a-zA-Z]+)\/(?<id>[A-Za-z0-9\-.]+)$/;

const GENERIC_ERR_MESSAGE = 'Invalid access token';

export function getFhirUser(fhirUserValue: string): FhirResource {
    const match = fhirUserValue.match(FHIR_USER_REGEX);
    if (match) {
        const { hostname, resourceType, id } = match.groups!;
        return { hostname, resourceType, id };
    }
    throw new UnauthorizedError("Requester's identity is in the incorrect format");
}
export function getFhirResource(resourceValue: string, defaultHostname: string): FhirResource {
    const match = resourceValue.match(FHIR_RESOURCE_REGEX);
    logger.error(`defaultHostName: ${defaultHostname}`);
    logger.error(`resourceValue: ${resourceValue}`);
    logger.error(`match: ${match}`);

    if (match) {
        const { resourceType, id } = match.groups!;
        const hostname = match.groups!.hostname ?? defaultHostname;
        return { hostname, resourceType, id };
    }
    throw new UnauthorizedError('Resource is in the incorrect format');
}

function isRequestorReferenced(
    requestorIds: string[],
    requestorResourceType: string,
    sourceResource: any,
    fhirVersion: FhirVersion,
): boolean {
    const sourceResourceType = sourceResource.resourceType;
    let matrix: any;
    if (fhirVersion === '4.0.1') {
        matrix = resourceReferencesMatrixV4;
    } else if (fhirVersion === '3.0.1') {
        matrix = resourceReferencesMatrixV3;
    } else {
        throw new Error('Unsupported FHIR version detected');
    }
    let possiblePaths: string[] = [];
    if (matrix[sourceResourceType] && matrix[sourceResourceType][requestorResourceType]) {
        possiblePaths = matrix[sourceResourceType][requestorResourceType];
    }

    // The paths within the FHIR resources may contain arrays so we must check if array at every level
    return possiblePaths.some((path) => {
        const pathComponents: string[] = path.split('.');
        let tempResource = sourceResource;
        let rootQueue = [];
        let nextQueue = [tempResource[pathComponents[0]]];
        for (let i = 1; i < pathComponents.length; i += 1) {
            rootQueue = nextQueue;
            nextQueue = [];

            while (rootQueue.length > 0) {
                tempResource = rootQueue.shift();
                if (tempResource) {
                    if (Array.isArray(tempResource)) {
                        // eslint-disable-next-line no-loop-func
                        tempResource.forEach((x) => {
                            nextQueue.push(x[pathComponents[i]]);
                        });
                    } else {
                        nextQueue.push(tempResource[pathComponents[i]]);
                    }
                }
            }
        }
        return nextQueue.flat().some((x) => {
            return x && x.reference && requestorIds.includes(x.reference);
        });
    });
}

export function hasReferenceToResource(
    requestorId: FhirResource,
    sourceResource: any,
    apiUrl: string,
    fhirVersion: FhirVersion,
): boolean {
    const hostname = get(requestorId, 'hostname', '');
    const resourceType = get(requestorId, 'resourceType', 'Patient');
    const id = get(requestorId, 'id', '');
    console.log('checking the hostname in reference to resource', hostname, resourceType, id, apiUrl);
    if (hostname !== apiUrl) {
        console.log('this is the apiUrl in has reference to Resource', apiUrl);
        // If requester is not from this FHIR Server they must be a fully qualified reference
        return isRequestorReferenced([`${hostname}/${resourceType}/${id}`], resourceType, sourceResource, fhirVersion);
    }

    return (
        (resourceType === sourceResource.resourceType && id === sourceResource.id) ||
        isRequestorReferenced(
            [`${resourceType}/${id}`, `${hostname}/${resourceType}/${id}`],
            resourceType,
            sourceResource,
            fhirVersion,
        )
    );
}

export function isFhirUserAdmin(fhirUser: FhirResource, adminAccessTypes: string[], apiUrl: string): boolean {
    logger.error(`inside isFhirUserAdmin, ${JSON.stringify(fhirUser)}`);
    logger.error(`apiUrl: ${apiUrl}`);

    return apiUrl === fhirUser.hostname && adminAccessTypes.includes(fhirUser.resourceType);
}

/**
 * @param scopes: this should be scope set from the `verifyAccessToken` method
 * @param resourceType: the type of the resource the request is trying to access
 * @param accessModifier: the type of access the request is asking for
 * @returns if there is a usable system scope for this request
 */
export function hasSystemAccess(scopes: string[], resourceType: string, accessModifier: AccessModifier): boolean {
    return scopes.some((scope: string) => {
        try {
            const clinicalSmartScope = convertScopeToSmartScope(scope);

            return (
                clinicalSmartScope.scopeType === 'system' &&
                (clinicalSmartScope.resourceType === '*' || clinicalSmartScope.resourceType === resourceType) &&
                (clinicalSmartScope.accessType === '*' || clinicalSmartScope.accessType === accessModifier)
            );
        } catch (e) {
            // Error occurs from `convertScopeToSmartScope` if scope was invalid
            logger.debug((e as any).message);
            return false;
        }
    });
}

export function hasAccessToResource(
    fhirUserObject: FhirResource,
    patientLaunchContext: FhirResource,
    sourceResource: any,
    usableScopes: string[],
    adminAccessTypes: string[],
    apiUrl: string,
    fhirVersion: FhirVersion,
    accessModifier: AccessModifier,
): boolean {
    console.log('this is fhirUSEROBJECT inside hasAccessToResource', JSON.stringify(fhirUserObject));
    console.log('patientLaunchContext', patientLaunchContext);
    console.log('usableScopes', usableScopes);
    console.log('sourceResource.resourceType', sourceResource);
    console.log('accessModifier', accessModifier);

    return (
        hasSystemAccess(usableScopes, sourceResource.resourceType, accessModifier) ||
        (fhirUserObject &&
            (isFhirUserAdmin(fhirUserObject, adminAccessTypes, apiUrl) ||
                hasReferenceToResource(fhirUserObject, sourceResource, apiUrl, fhirVersion))) ||
        (patientLaunchContext && hasReferenceToResource(patientLaunchContext, sourceResource, apiUrl, fhirVersion))
    );
}
export function getJwksClient(jwksUri: string, headers?: Headers): JwksClient {
    console.log(
        `these are the jwks parameters, ${JSON.stringify({
            cache: true,
            cacheMaxEntries: 5,
            cacheMaxAge: 600000,
            rateLimit: true,
            jwksRequestsPerMinute: 10,
            requestHeaders: headers,
            jwksUri,
        })}`,
    );
    return jwksClient({
        cache: true,
        cacheMaxEntries: 5,
        cacheMaxAge: 600000,
        rateLimit: true,
        jwksRequestsPerMinute: 10,
        requestHeaders: headers,
        jwksUri,
    });
}

export function decodeJwtToken(token: string, expectedAudValue: string | RegExp | string[], expectedIssValue: string) {
    const decodedAccessToken = decode(token, { complete: true });
    if (decodedAccessToken === null || typeof decodedAccessToken === 'string') {
        logger.error('access_token could not be decoded into an object');
        throw new UnauthorizedError(GENERIC_ERR_MESSAGE);
    }

    const { aud = '', tenant = '' } = decodedAccessToken.payload;

    let audArray: string[] = [];
    if (aud) {
        if (typeof aud === 'string') {
            audArray = [aud];
        } else {
            audArray = aud;
        }
    }

    const audMatch: boolean = audArray.some((audience: string) => {
        console.log('this is about ot run audMatch', `${audience}/${tenant}`);

        logger.error(`expected: ${expectedAudValue}, but got ${audience}`);

        return (
            (typeof expectedAudValue === 'string' && expectedAudValue === `${audience}`) ||
            (expectedAudValue instanceof RegExp && expectedAudValue.test(`${audience}/${tenant}`))
        );
    });
    if (!audMatch) {
        throw new UnauthorizedError(GENERIC_ERR_MESSAGE);
    }
    console.log('IS AUDMATCH TRUTHY', audMatch);
    console.log('this is the decoded AccessToken', decodedAccessToken);

    const formattedAccessToken = { ...decodedAccessToken };
    // formattedAccessToken.payload.iss = removeTrailingSlash(get(decodedAccessToken, 'payload.iss', ''));
    formattedAccessToken.payload.iss = expectedIssValue;
    // console.log('this is formattedAccessTokenNow', formattedAccessToken);
    return formattedAccessToken;
}

export async function verifyJwtToken(
    token: string,
    expectedAudValue: string | RegExp | string[],
    expectedIssValue: string,
    client: JwksClient,
) {
    const decodedAccessToken = decodeJwtToken(token, expectedAudValue, expectedIssValue);
    logger.info(`this is expected aud: ${expectedAudValue}`);
    logger.info(`this is expectedIssValue: ${expectedIssValue}`);
    logger.info(`HELLO decodedAccessToken: ${JSON.stringify(decodedAccessToken)}`);
    const { kid } = decodedAccessToken.header;
    logger.info(`kid ${kid}`);
    if (!kid) {
        logger.error('JWT verification failed. JWT "kid" attribute is required in the header');
        throw new UnauthorizedError(GENERIC_ERR_MESSAGE);
    }

    try {
        const key = await client.getSigningKeyAsync(kid);
        logger.info(`Inside verifyJwtToken. Key: ${JSON.stringify(key)}`);
        const publicKey = key.getPublicKey();
        logger.info(`this is publicKey:  ${publicKey}`);
        return verify(token, publicKey, { audience: expectedAudValue, issuer: expectedIssValue });
    } catch (e) {
        logger.error(`custom error in verifyJwt ${JSON.stringify(e)}`);
        logger.error((e as any).message);
        throw new UnauthorizedError(GENERIC_ERR_MESSAGE);
    }
}

export async function introspectJwtToken(
    token: string,
    expectedAudValue: string | RegExp | string[],
    expectedIssValue: string,
    introspectionOptions: IntrospectionOptions,
) {
    // used to verify if `iss` or `aud` is valid
    const decodedTokenPayload = decodeJwtToken(token, expectedAudValue, expectedIssValue).payload;
    const { introspectUrl, clientId, clientSecret } = introspectionOptions;
    console.log('introspectUrl', introspectUrl);
    // setup basic authentication
    const username = clientId;
    const password = clientSecret;
    const auth = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

    try {
        const response = await axios.post(introspectUrl, `token=${token}`, {
            headers: {
                'content-type': 'application/x-www-form-urlencoded',
                accept: 'application/json',
                authorization: auth,
                'cache-control': 'no-cache',
            },
        });
        if (!response.data.active) {
            logger.error(`response ${response}`);
            logger.error('response data active not available');
            throw new UnauthorizedError(GENERIC_ERR_MESSAGE);
        }
        return decodedTokenPayload;
    } catch (e) {
        logger.error('generic introspection error');
        logger.error(e);
        if (axios.isAxiosError(e)) {
            if (e.response) {
                logger.error(`Status received from introspection call: ${e.response.status}`);
                logger.error(e.response.data);
            }
        } else {
            logger.error((e as any).message);
        }
        throw new UnauthorizedError(GENERIC_ERR_MESSAGE);
    }
}
