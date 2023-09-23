import { Context, Next } from "koa"
import {
    BaseAuthOptions,
    ForbiddenException,
    initBaseAuth,
    RequriedOrgInfo,
    UnauthorizedException,
    UnexpectedException,
    UserAndOrgMemberInfo,
    User,
} from "@propelauth/node"
import { RequiredOrgInfo } from "@propelauth/node/dist/auth"

export interface AuthOptions extends BaseAuthOptions {
    debugMode?: boolean
}

export function initAuth(opts: AuthOptions) {
    const auth = initBaseAuth(opts)
    const debugMode = opts.debugMode || false

    // Create middlewares
    const requireUser = createUserExtractingMiddleware({
        validateAccessTokenAndGetUser: auth.validateAccessTokenAndGetUser,
        requireCredentials: true,
        debugMode,
    })
    const optionalUser = createUserExtractingMiddleware({
        validateAccessTokenAndGetUser: auth.validateAccessTokenAndGetUser,
        requireCredentials: false,
        debugMode,
    })
    const requireOrgMember = createRequireOrgMemberMiddleware(auth.validateAccessTokenAndGetUserWithOrgInfo, debugMode)
    const requireOrgMemberWithMinimumRole = createRequireOrgMemberMiddlewareWithMinimumRole(
        auth.validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole,
        debugMode
    )
    const requireOrgMemberWithExactRole = createRequireOrgMemberMiddlewareWithExactRole(
        auth.validateAccessTokenAndGetUserWithOrgInfoWithExactRole,
        debugMode
    )
    const requireOrgMemberWithPermission = createRequireOrgMemberMiddlewareWithPermission(
        auth.validateAccessTokenAndGetUserWithOrgInfoWithPermission,
        debugMode
    )
    const requireOrgMemberWithAllPermissions = createRequireOrgMemberMiddlewareWithAllPermissions(
        auth.validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions,
        debugMode
    )

    return {
        requireUser,
        optionalUser,
        requireOrgMember,
        requireOrgMemberWithMinimumRole,
        requireOrgMemberWithExactRole,
        requireOrgMemberWithPermission,
        requireOrgMemberWithAllPermissions,
        fetchUserMetadataByUserId: auth.fetchUserMetadataByUserId,
        fetchUserMetadataByEmail: auth.fetchUserMetadataByEmail,
        fetchUserMetadataByUsername: auth.fetchUserMetadataByUsername,
        fetchBatchUserMetadataByUserIds: auth.fetchBatchUserMetadataByUserIds,
        fetchBatchUserMetadataByEmails: auth.fetchBatchUserMetadataByEmails,
        fetchBatchUserMetadataByUsernames: auth.fetchBatchUserMetadataByUsernames,
        fetchOrg: auth.fetchOrg,
        fetchOrgByQuery: auth.fetchOrgByQuery,
        fetchUsersByQuery: auth.fetchUsersByQuery,
        fetchUsersInOrg: auth.fetchUsersInOrg,
        createUser: auth.createUser,
        updateUserMetadata: auth.updateUserMetadata,
        updateUserEmail: auth.updateUserEmail,
        updateUserPassword: auth.updateUserPassword,
        createMagicLink: auth.createMagicLink,
        createAccessToken: auth.createAccessToken,
        migrateUserFromExternalSource: auth.migrateUserFromExternalSource,
        disableUser2fa: auth.disableUser2fa,
        createOrg: auth.createOrg,
        addUserToOrg: auth.addUserToOrg,
        deleteUser: auth.deleteUser,
        disableUser: auth.disableUser,
        enableUser: auth.enableUser,
        enableUserCanCreateOrgs: auth.enableUserCanCreateOrgs,
        disableUserCanCreateOrgs: auth.disableUserCanCreateOrgs,
        changeUserRoleInOrg: auth.changeUserRoleInOrg,
        removeUserFromOrg: auth.removeUserFromOrg,
        updateOrg: auth.updateOrg,
        deleteOrg: auth.deleteOrg,
        allowOrgToSetupSamlConnection: auth.allowOrgToSetupSamlConnection,
        disallowOrgToSetupSamlConnection: auth.disallowOrgToSetupSamlConnection,
        fetchApiKey: auth.fetchApiKey,
        fetchCurrentApiKeys: auth.fetchCurrentApiKeys,
        fetchArchivedApiKeys: auth.fetchArchivedApiKeys,
        createApiKey: auth.createApiKey,
        updateApiKey: auth.updateApiKey,
        deleteApiKey: auth.deleteApiKey,
        validateApiKey: auth.validateApiKey,
        validatePersonalApiKey: auth.validatePersonalApiKey,
        validateOrgApiKey: auth.validateOrgApiKey,
    }
}

function createUserExtractingMiddleware({
    validateAccessTokenAndGetUser,
    requireCredentials,
    debugMode,
}: CreateRequestHandlerArgs) {
    return async function (ctx: Context, next: Next) {
        try {
            ctx.state.user = await validateAccessTokenAndGetUser(ctx.request.header.authorization)
            await next()
        } catch (e: any) {
            if (e instanceof UnauthorizedException) {
                handleUnauthorizedException({ exception: e, requireCredentials, ctx, next, debugMode })
            } else if (e instanceof UnexpectedException) {
                handleUnexpectedException(e, ctx, debugMode)
            } else {
                throw e
            }
        }
    }
}

function createRequireOrgMemberMiddleware(
    validateAccessTokenAndGetUserWithOrgInfo: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo
    ) => Promise<UserAndOrgMemberInfo>,
    debugMode: boolean
) {
    return function requireOrgMember(args?: RequireOrgMemberArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader, requiredOrgInfo)
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function createRequireOrgMemberMiddlewareWithMinimumRole(
    validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo,
        minimumRole: string
    ) => Promise<UserAndOrgMemberInfo>,
    debugMode: boolean
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithMinimumRoleArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(
                    authorizationHeader,
                    requiredOrgInfo,
                    args.minimumRequiredRole
                )
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function createRequireOrgMemberMiddlewareWithExactRole(
    validateAccessTokenAndGetUserWithOrgInfoWithExactRole: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo,
        role: string
    ) => Promise<UserAndOrgMemberInfo>,
    debugMode: boolean
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithExactRoleArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfoWithExactRole(
                    authorizationHeader,
                    requiredOrgInfo,
                    args.role
                )
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function createRequireOrgMemberMiddlewareWithPermission(
    validateAccessTokenAndGetUserWithOrgInfoWithPermission: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo,
        permission: string
    ) => Promise<UserAndOrgMemberInfo>,
    debugMode: boolean
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithPermissionArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfoWithPermission(
                    authorizationHeader,
                    requiredOrgInfo,
                    args.permission
                )
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function createRequireOrgMemberMiddlewareWithAllPermissions(
    validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo,
        permissions: string[]
    ) => Promise<UserAndOrgMemberInfo>,
    debugMode: boolean
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithAllPermissionsArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(
                    authorizationHeader,
                    requiredOrgInfo,
                    args.permissions
                )
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function requireOrgMemberGenericMiddleware(
    validateAccessTokenAndGetUserWithOrgInfo: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo
    ) => Promise<UserAndOrgMemberInfo>,
    debugMode: boolean,
    orgIdExtractor?: (ctx: Context) => string,
    orgNameExtractor?: (ctx: Context) => string
) {
    return async function (ctx: Context, next: Next) {
        let requiredOrgInfo: RequiredOrgInfo
        if (orgIdExtractor || orgNameExtractor) {
            const requiredOrgId = orgIdExtractor ? orgIdExtractor(ctx) : undefined
            const requiredOrgName = orgNameExtractor ? orgNameExtractor(ctx) : undefined
            requiredOrgInfo = {
                orgId: requiredOrgId,
                orgName: requiredOrgName,
            }
        } else {
            requiredOrgInfo = {
                orgId: defaultOrgIdExtractor(ctx),
                orgName: undefined,
            }
        }

        try {
            const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfo(
                ctx.request.header.authorization,
                requiredOrgInfo
            )
            ctx.state.user = userAndOrgMemberInfo.user
            ctx.state.org = userAndOrgMemberInfo.orgMemberInfo
            await next()
        } catch (e: any) {
            if (e instanceof UnauthorizedException) {
                handleUnauthorizedException({ exception: e, requireCredentials: true, ctx, next, debugMode })
            } else if (e instanceof ForbiddenException) {
                handleForbiddenExceptionWithRequiredCredentials(e, ctx, debugMode)
            } else if (e instanceof UnexpectedException) {
                handleUnexpectedException(e, ctx, debugMode)
            } else {
                handleUnexpectedException(
                    new UnexpectedException("An unexpected exception has occurred"),
                    ctx,
                    debugMode
                )
            }
        }
    }
}

// With an unauthorized exception, we only reject the request if credentials are required
async function handleUnauthorizedException({
    exception,
    requireCredentials,
    ctx,
    next,
    debugMode,
}: HandleUnauthorizedExceptionArgs) {
    if (requireCredentials && debugMode) {
        ctx.status = exception.status
        ctx.body = exception.message
    } else if (requireCredentials) {
        ctx.status = exception.status
    } else {
        await next()
    }
}

// With a forbidden exception, we will always reject the request
function handleForbiddenExceptionWithRequiredCredentials(
    exception: ForbiddenException,
    ctx: Context,
    debugMode: boolean
) {
    if (debugMode) {
        ctx.status = exception.status
        ctx.body = exception.message
    } else {
        ctx.status = exception.status
    }
}

// With an unexpected exception, we will always reject the request
function handleUnexpectedException(exception: UnexpectedException, ctx: Context, debugMode: boolean) {
    if (debugMode) {
        ctx.status = exception.status
        ctx.body = exception.message
    } else {
        ctx.status = exception.status
    }
}

interface CreateRequestHandlerArgs {
    validateAccessTokenAndGetUser: (authorizationHeader?: string) => Promise<User>
    requireCredentials: boolean
    debugMode: boolean
}

interface HandleUnauthorizedExceptionArgs {
    exception: UnauthorizedException
    requireCredentials: boolean
    ctx: Context
    next: Next
    debugMode: boolean
}

export interface RequireOrgMemberArgs {
    orgIdExtractor?: (ctx: Context) => string
    orgNameExtractor?: (ctx: Context) => string
}

export interface RequireOrgMemberWithMinimumRoleArgs {
    orgIdExtractor?: (ctx: Context) => string
    orgNameExtractor?: (ctx: Context) => string
    minimumRequiredRole: string
}

export interface RequireOrgMemberWithExactRoleArgs {
    orgIdExtractor?: (ctx: Context) => string
    orgNameExtractor?: (ctx: Context) => string
    role: string
}

export interface RequireOrgMemberWithPermissionArgs {
    orgIdExtractor?: (ctx: Context) => string
    orgNameExtractor?: (ctx: Context) => string
    permission: string
}

export interface RequireOrgMemberWithAllPermissionsArgs {
    orgIdExtractor?: (ctx: Context) => string
    orgNameExtractor?: (ctx: Context) => string
    permissions: string[]
}

function defaultOrgIdExtractor(ctx: Context) {
    return ctx.params.orgId
}
