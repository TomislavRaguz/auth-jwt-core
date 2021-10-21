import { SignOptions } from 'jsonwebtoken';
export declare const HTTP_METHODS: readonly ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"];
export declare const SAFE_METHODS: readonly ["GET", "HEAD", "OPTIONS", "TRACE"];
export declare const UNSAFE_METHODS: readonly ["POST", "PUT", "PATCH", "DELETE", "CONNECT"];
export declare class JWTAuth<DataParams, JWTData> {
    secret: string;
    getJWTData: getJWTData<DataParams, JWTData>;
    dataRefreshIntervalInSeconds: number;
    cookieConfig?: {
        useCookie: true;
        cookieOptions: CookieOptions;
    };
    JWTSignOptions: SignOptions;
    tokenMaxAgeInSeconds: number | undefined;
    CSRFProtection: {
        customHeader?: {
            headerName: string;
            methodList: ReadonlyArray<typeof HTTP_METHODS[number]>;
        };
        originCheck?: {
            domains: Array<string>;
            allowWithoutDomain: boolean;
            methodList: ReadonlyArray<typeof HTTP_METHODS[number]>;
        };
        token?: {
            generateToken: () => string;
            addToJWT: boolean;
            methodList: ReadonlyArray<typeof HTTP_METHODS[number]>;
        };
    };
    constructor(props: JWTAuthProps<DataParams, JWTData>);
    verify(AuthorizationHeader: string, forceDataRefresh?: boolean): Promise<JWTPayload<DataParams, JWTData>>;
    generate(dataParams: DataParams, options?: JWTOptions): Promise<{
        JWTPayload: {
            data: JWTData;
            oiat: number;
            exp: number;
            iat: number;
            maxAge: number;
            dataParams: DataParams;
        };
        JWT: string;
    }>;
}
export interface AuthJWT<DataParams, ExpandedData> {
    _memoizedData: ExpandedData | null | undefined;
    getData: (forceDataRefresh?: boolean) => Promise<ExpandedData | null>;
    generate: (dataParams: DataParams, options?: JWTOptions) => Promise<{
        JWTPayload: JWTPayload<DataParams, ExpandedData>;
        data: ExpandedData;
        JWT: string;
    }>;
    refreshData: () => Promise<ExpandedData | null>;
    remove: () => void;
    checkCSRF: () => Promise<Array<string>>;
}
interface JWTPayload<DataParams, JWTData> {
    dataParams: DataParams;
    data: JWTData;
    iat: number;
    exp: number;
    oiat: number;
    maxAge: number;
}
export interface JWTOptions {
    maxAge?: number;
    oiat?: number;
}
declare type getJWTData<DataParams, JWTData> = (dataParams: DataParams, oiat: number) => Promise<JWTData>;
export interface CookieOptions {
    httpOnly?: boolean;
    sameSite?: "strict" | "lax" | "none";
    secure?: boolean;
    domain?: string;
    path?: string;
}
interface CookieConfig {
    useCookie: boolean;
    cookieOptions?: CookieOptions;
    CSRFProtection?: {
        customHeader?: {
            active?: boolean;
            checkSafeMethods?: boolean;
            checkMethodList?: ReadonlyArray<typeof HTTP_METHODS[number]>;
            headerName?: string;
        };
        originCheck?: {
            active?: boolean;
            checkSafeMethods?: boolean;
            checkMethodList?: ReadonlyArray<typeof HTTP_METHODS[number]>;
            domains: Array<string>;
            allowWithoutDomain: boolean;
        };
        tokenConfig?: {
            active?: boolean;
            checkSafeMethods?: boolean;
            checkMethodList?: ReadonlyArray<typeof HTTP_METHODS[number]>;
            generateToken?: () => string;
            addToJWT?: boolean;
        };
        IGNORE_CSRF_WARNING?: boolean;
    };
}
interface JWTAuthProps<DataParams, JWTData> {
    ignoreVulnerabilities?: boolean;
    secret: string;
    getJWTData: getJWTData<DataParams, JWTData>;
    cookieConfig?: CookieConfig;
    JWTSignOptions?: SignOptions;
    dataRefreshIntervalInSeconds?: number;
    tokenMaxAgeInSeconds?: number;
}
export {};
