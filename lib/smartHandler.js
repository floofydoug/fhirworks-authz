"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SMARTHandler = void 0;
/*
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *  SPDX-License-Identifier: Apache-2.0
 */
const fhir_works_on_aws_interface_1 = require("fhir-works-on-aws-interface");
const lodash_1 = require("lodash");
const smartScopeHelper_1 = require("./smartScopeHelper");
const smartAuthorizationHelper_1 = require("./smartAuthorizationHelper");
const loggerBuilder_1 = __importDefault(require("./loggerBuilder"));
const logger = (0, loggerBuilder_1.default)();
// eslint-disable-next-line import/prefer-default-export
class SMARTHandler {
    /**
     * @param apiUrl: URL of this FHIR service. Will be used to determine if a requestor is from this FHIR server or not
     * when the request does not include a fhirServiceBaseUrl
     * @param adminAccessTypes: a fhirUser from these resourceTypes they will be able to READ & WRITE without having to meet the reference criteria
     * @param bulkDataAccessTypes: a fhirUser from these resourceTypes they will be able to do bulk data operations
     */
    constructor(config, apiUrl, fhirVersion, adminAccessTypes = ['Practitioner'], bulkDataAccessTypes = ['Practitioner'], isUserScopeAllowedForSystemExport = false) {
        this.version = 1.0;
        if (config.version !== this.version) {
            throw Error('Authorization configuration version does not match handler version');
        }
        this.config = config;
        this.apiUrl = apiUrl;
        this.fhirVersion = fhirVersion;
        this.adminAccessTypes = adminAccessTypes;
        this.bulkDataAccessTypes = bulkDataAccessTypes;
        this.isUserScopeAllowedForSystemExport = isUserScopeAllowedForSystemExport;
        if (this.config.jwksEndpoint && !this.config.tokenIntrospection) {
            this.jwksClient = (0, smartAuthorizationHelper_1.getJwksClient)(this.config.jwksEndpoint, this.config.jwksHeaders);
        }
    }
    async verifyAccessToken(request) {
        var _a, _b;
        let decodedToken;
        if (this.config.tokenIntrospection) {
            logger.error(`did we get into introspection? ${JSON.stringify(this.config)}`);
            decodedToken = await (0, smartAuthorizationHelper_1.introspectJwtToken)(request.accessToken, this.config.expectedAudValue, this.config.expectedIssValue, this.config.tokenIntrospection);
        }
        else if (this.jwksClient) {
            logger.error(`or do we fall into jwksClient? ${JSON.stringify(this.config)}`);
            decodedToken = await (0, smartAuthorizationHelper_1.verifyJwtToken)(request.accessToken, this.config.expectedAudValue, this.config.expectedIssValue, this.jwksClient);
        }
        else {
            throw Error(`Authorization configuration not properly set up. Either 'tokenIntrospection' or 'jwksEndpoint' must be present`);
        }
        logger.error(`THIS IS decodedToken after falling into jwksclient: ${JSON.stringify(decodedToken)}`);
        const fhirUserClaim = (0, lodash_1.get)(decodedToken, this.config.fhirUserClaimPath);
        const patientContextClaim = (0, lodash_1.get)(decodedToken, `${this.config.launchContextPathPrefix}patient`);
        // const fhirUserClaimStartIndex = decodedToken[this.config.scopeKey].indexOf(this.config.fhirUserClaimPath);
        // const patientContextClaimStartIndex = decodedToken[this.config.scopeKey].indexOf(`${this.config.launchContextPathPrefix}patient`);
        const fhirServiceBaseUrl = (_a = request.fhirServiceBaseUrl) !== null && _a !== void 0 ? _a : this.apiUrl;
        // get just the scopes that apply to this request
        logger.error(`SCOPE KEY, ${this.config.scopeKey}`);
        const scopes = (0, smartScopeHelper_1.getScopes)(decodedToken[this.config.scopeKey]);
        // scopes.forEach( scope => {
        //     if(scope.substring(''))
        // })
        logger.error(`SCOPES BEFORE ${JSON.stringify(scopes)}`);
        const usableScopes = (0, smartScopeHelper_1.filterOutUnusableScope)(scopes, this.config.scopeRule, request.operation, this.isUserScopeAllowedForSystemExport, request.resourceType, request.bulkDataAuth, patientContextClaim, fhirUserClaim);
        logger.error(`this.config.scopeRule${JSON.stringify(this.config.scopeRule)}`);
        logger.error(`this.isUserScopeAllowedForSystemExport ${this.isUserScopeAllowedForSystemExport}`);
        logger.error(`fhirUserClaimfhirUserClaim ${JSON.stringify(fhirUserClaim)}`);
        logger.error(`patientContextClaim ${patientContextClaim}`);
        logger.error(`usable scopes ${JSON.stringify(usableScopes)}`);
        if (!usableScopes.length) {
            logger.error('User supplied scopes are insufficient', JSON.stringify({
                usableScopes,
                operation: request.operation,
                resourceType: request.resourceType,
            }));
            throw new fhir_works_on_aws_interface_1.UnauthorizedError('access_token does not have permission for requested operation');
        }
        const userIdentity = (0, fhir_works_on_aws_interface_1.clone)(decodedToken);
        if (request.bulkDataAuth) {
            if (!userIdentity.sub) {
                logger.error('A JWT token is without a `sub` claim; we cannot process the bulk action without one.');
                throw new fhir_works_on_aws_interface_1.UnauthorizedError('User does not have permission for requested operation');
            }
            if (!usableScopes.some((scope) => scope.startsWith('system'))) {
                // if requestor is relying on the "user" scope we need to verify they are coming from the correct endpoint & resourceType
                const fhirUser = (0, smartAuthorizationHelper_1.getFhirUser)(fhirUserClaim);
                if (fhirUser.hostname !== fhirServiceBaseUrl ||
                    !this.bulkDataAccessTypes.includes(fhirUser.resourceType)) {
                    throw new fhir_works_on_aws_interface_1.UnauthorizedError('User does not have permission for requested operation');
                }
            }
        }
        if (fhirUserClaim) {
            console.log('we are trying to find the user');
            userIdentity.fhirUserObject = (0, smartAuthorizationHelper_1.getFhirUser)(fhirUserClaim);
        }
        if (patientContextClaim && usableScopes.some((scope) => scope.startsWith('patient/'))) {
            logger.error(`do we fall into this tet for scopes and patientContext`);
            userIdentity.patientLaunchContext = (0, smartAuthorizationHelper_1.getFhirResource)(patientContextClaim, fhirServiceBaseUrl);
        }
        console.log('THE WWHOLE REQUEST', JSON.stringify(request));
        const requestTenant = (_b = request.fhirServiceBaseUrl) === null || _b === void 0 ? void 0 : _b.split('/tenant/').pop();
        if (requestTenant !== (0, lodash_1.get)(decodedToken, 'tenant')) {
            // verifying the user is a part of the tenant they are querying for.
            console.log("tenants do not match");
            throw new fhir_works_on_aws_interface_1.UnauthorizedError('User requested an incorrect tenant for the tenant they are currently assigned.');
        }
        userIdentity.scopes = scopes;
        userIdentity.usableScopes = usableScopes;
        return userIdentity;
    }
    // eslint-disable-next-line class-methods-use-this, @typescript-eslint/no-unused-vars
    async isAccessBulkDataJobAllowed(request) {
        if (request.userIdentity.sub !== request.jobOwnerId) {
            throw new fhir_works_on_aws_interface_1.UnauthorizedError('User does not have permission to access this Bulk Data Export job');
        }
    }
    async getSearchFilterBasedOnIdentity(request) {
        var _a;
        const references = new Set();
        const ids = new Set();
        const { fhirUserObject, patientLaunchContext, usableScopes } = request.userIdentity;
        const fhirServiceBaseUrl = (_a = request.fhirServiceBaseUrl) !== null && _a !== void 0 ? _a : this.apiUrl;
        if ((0, smartAuthorizationHelper_1.hasSystemAccess)(usableScopes, '', 'read')) {
            return [];
        }
        if (fhirUserObject) {
            const { hostname, resourceType, id } = fhirUserObject;
            if ((0, smartAuthorizationHelper_1.isFhirUserAdmin)(fhirUserObject, this.adminAccessTypes, fhirServiceBaseUrl)) {
                // if an admin do not add limiting search filters
                return [];
            }
            references.add(`${hostname}/${resourceType}/${id}`);
            if (hostname === fhirServiceBaseUrl) {
                references.add(`${resourceType}/${id}`);
            }
            if (request.resourceType && request.resourceType === resourceType) {
                ids.add(id);
            }
        }
        if (patientLaunchContext) {
            const { hostname, resourceType, id } = patientLaunchContext;
            references.add(`${hostname}/${resourceType}/${id}`);
            if (hostname === fhirServiceBaseUrl) {
                references.add(`${resourceType}/${id}`);
            }
            if (request.resourceType && request.resourceType === resourceType) {
                ids.add(id);
            }
        }
        // Create a SearchFilter to limit access to only resources that are referring to the requesting user and/or context
        const filters = [];
        if (references.size > 0) {
            filters.push({
                key: '_references',
                value: [...references],
                comparisonOperator: '==',
                logicalOperator: 'OR',
            });
        }
        if (ids.size > 0) {
            filters.push({
                key: 'id',
                value: [...ids],
                comparisonOperator: '==',
                logicalOperator: 'OR',
            });
        }
        return filters;
    }
    async isBundleRequestAuthorized(request) {
        const { scopes, fhirUserObject, patientLaunchContext } = request.userIdentity;
        const usableScopes = scopes.filter((scope) => (patientLaunchContext && scope.startsWith('patient/')) ||
            (fhirUserObject && scope.startsWith('user/')) ||
            scope.startsWith('system/'));
        logger.error(`inside isBundleRequest Authorized: ${usableScopes}`);
        // Are the scopes the request have good enough for every entry in the bundle?
        request.requests.forEach((req) => {
            if (!usableScopes.some((scope) => (0, smartScopeHelper_1.isScopeSufficient)(scope, this.config.scopeRule, req.operation, this.isUserScopeAllowedForSystemExport, req.resourceType))) {
                logger.error('User supplied scopes are insufficient', {
                    usableScopes,
                    operation: req.operation,
                    resourceType: req.resourceType,
                });
                throw new fhir_works_on_aws_interface_1.UnauthorizedError('An entry within the Bundle is not authorized');
            }
        });
        // Ensure the requestor has access to write this request
        const authWritePromises = request.requests.map((req) => {
            logger.error(`this is the req inside of authWritePromises, ${JSON.stringify(req)}`);
            if (['create', 'update', 'patch', 'delete'].includes(req.operation)) {
                return this.isWriteRequestAuthorized({
                    userIdentity: { ...request.userIdentity, usableScopes },
                    operation: req.operation,
                    resourceBody: req.resource,
                    fhirServiceBaseUrl: request.fhirServiceBaseUrl,
                });
            }
            return Promise.resolve();
        });
        try {
            await Promise.all(authWritePromises);
        }
        catch (e) {
            throw new fhir_works_on_aws_interface_1.UnauthorizedError('An entry within the Bundle is not authorized');
        }
    }
    async getAllowedResourceTypesForOperation(request) {
        let allowedResources = [];
        const allResourceTypes = this.fhirVersion === '4.0.1' ? fhir_works_on_aws_interface_1.BASE_R4_RESOURCES : fhir_works_on_aws_interface_1.BASE_STU3_RESOURCES;
        for (let i = 0; i < request.userIdentity.scopes.length; i += 1) {
            const scope = request.userIdentity.scopes[i];
            try {
                // We only get allowedResourceTypes for ClinicalSmartScope
                const clinicalSmartScope = (0, smartScopeHelper_1.convertScopeToSmartScope)(scope);
                const validOperations = (0, smartScopeHelper_1.getValidOperationsForScopeTypeAndAccessType)(clinicalSmartScope.scopeType, clinicalSmartScope.accessType, this.config.scopeRule);
                if (validOperations.includes(request.operation)) {
                    const scopeResourceType = clinicalSmartScope.resourceType;
                    if (scopeResourceType === '*') {
                        return allResourceTypes;
                    }
                    if (allResourceTypes.includes(scopeResourceType)) {
                        allowedResources = allowedResources.concat(scopeResourceType);
                    }
                }
            }
            catch (e) {
                // Caused by trying to convert non-SmartScope to SmartScope, for example converting scope 'openid' or 'profile'
                logger.debug(e.message);
            }
        }
        allowedResources = [...new Set(allowedResources)];
        return allowedResources;
    }
    async authorizeAndFilterReadResponse(request) {
        var _a, _b;
        const { fhirUserObject, patientLaunchContext, usableScopes, scopes } = request.userIdentity;
        console.log('hey hey hey, this is inside authorizeAndFilterReadResponse', JSON.stringify(request.userIdentity));
        const fhirServiceBaseUrl = (_a = request.fhirServiceBaseUrl) !== null && _a !== void 0 ? _a : this.apiUrl;
        const { operation, readResponse } = request;
        // If request is a search iterate over every response object
        // Must use all scopes, since a search may return more resourceTypes than just found in usableScopes
        if (smartScopeHelper_1.SEARCH_OPERATIONS.includes(operation)) {
            const entries = ((_b = readResponse.entry) !== null && _b !== void 0 ? _b : []).filter((entry) => 
            // Are the scopes the request have good enough for this entry?
            scopes.some((scope) => (0, smartScopeHelper_1.isScopeSufficient)(scope, this.config.scopeRule, operation, this.isUserScopeAllowedForSystemExport, entry.resource.resourceType)) && // Does the user have permissions for this entry?
                (0, smartAuthorizationHelper_1.hasAccessToResource)(fhirUserObject, patientLaunchContext, entry.resource, scopes, this.adminAccessTypes, fhirServiceBaseUrl, this.fhirVersion, 'read'));
            let numTotal = readResponse.total;
            if (!numTotal) {
                numTotal = entries.length;
            }
            else {
                numTotal -= readResponse.entry.length - entries.length;
            }
            return { ...readResponse, entry: entries, total: numTotal };
        }
        // If request is != search treat the readResponse as just a resource
        if ((0, smartAuthorizationHelper_1.hasAccessToResource)(fhirUserObject, patientLaunchContext, readResponse, usableScopes, this.adminAccessTypes, fhirServiceBaseUrl, this.fhirVersion, 'read')) {
            return readResponse;
        }
        throw new fhir_works_on_aws_interface_1.UnauthorizedError('User does not have permission for requested resource');
    }
    async isWriteRequestAuthorized(request) {
        var _a;
        const { fhirUserObject, patientLaunchContext, usableScopes } = request.userIdentity;
        const fhirServiceBaseUrl = (_a = request.fhirServiceBaseUrl) !== null && _a !== void 0 ? _a : this.apiUrl;
        logger.error(`this is inside line 411, ${JSON.stringify(fhirUserObject)}`);
        logger.error(`this is the request, ${JSON.stringify(request)}`);
        if ((0, smartAuthorizationHelper_1.hasAccessToResource)(fhirUserObject, patientLaunchContext, request.resourceBody, usableScopes, this.adminAccessTypes, fhirServiceBaseUrl, this.fhirVersion, 'write')) {
            return;
        }
        throw new fhir_works_on_aws_interface_1.UnauthorizedError('User does not have permission for requested operation');
    }
}
exports.SMARTHandler = SMARTHandler;
//# sourceMappingURL=smartHandler.js.map