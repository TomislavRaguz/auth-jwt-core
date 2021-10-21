import jwt, { SignOptions } from 'jsonwebtoken';

const { NODE_ENV } = process.env;

/*
  Origin Header
  Referer Header
  csrf
  ajax only
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
  CSRF tokens in GET requests are potentially leaked at several locations, such as the browser history, log files, network appliances that log the first line of an HTTP request, \
  and Referer headers if the protected site links to an external site.
*/

export const HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"] as const
export const SAFE_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE"] as const
export const UNSAFE_METHODS = ["POST", "PUT", "PATCH", "DELETE", "CONNECT"] as const

export class JWTAuth<DataParams, JWTData> {
  secret: string;
  getJWTData: getJWTData<DataParams, JWTData>
  dataRefreshIntervalInSeconds: number
  cookieConfig?: {
    useCookie: true
    cookieOptions: CookieOptions
  }
  JWTSignOptions: SignOptions
  tokenMaxAgeInSeconds: number | undefined
  CSRFProtection: {
    customHeader?: {
      headerName: string
      methodList: ReadonlyArray<typeof HTTP_METHODS[number]>
    }
    originCheck?: {
      domains: Array<string>
      allowWithoutDomain: boolean
      methodList: ReadonlyArray<typeof HTTP_METHODS[number]>
    }
    token?: {
      generateToken: () => string
      addToJWT: boolean
      methodList: ReadonlyArray<typeof HTTP_METHODS[number]>
    }
  }
  constructor(props: JWTAuthProps<DataParams, JWTData>){
    this.secret = props.secret;
    this.getJWTData = props.getJWTData;

    this.cookieConfig = undefined;
    if(props.cookieConfig && props.cookieConfig.useCookie) {
      const cookieOptions = {
        httpOnly: true,
        sameSite: "lax" as "lax",
        secure: NODE_ENV === 'production',
        ...props.cookieConfig.cookieOptions
      }
      this.cookieConfig = {
        useCookie: true,
        cookieOptions,
      }
      
      const vulnerabilities: Array<string> = [];
      this.CSRFProtection = {}
      const { customHeader, originCheck, tokenConfig } = props.cookieConfig.CSRFProtection || {};
      if(customHeader) {
        const methodList = customHeader.checkMethodList || customHeader.checkSafeMethods ? HTTP_METHODS : UNSAFE_METHODS
        this.CSRFProtection.customHeader = {
          headerName: customHeader.headerName || "X-Requested-With",
          methodList
        }
      }
      if(originCheck) {
        const methodList = originCheck.checkMethodList || originCheck.checkSafeMethods ? HTTP_METHODS : UNSAFE_METHODS
        this.CSRFProtection.originCheck = {
          domains: originCheck.domains,
          allowWithoutDomain: originCheck.allowWithoutDomain,
          methodList
        }
      }
      if(tokenConfig) {
        const methodList = tokenConfig.checkMethodList || tokenConfig.checkSafeMethods ? HTTP_METHODS : UNSAFE_METHODS
        this.CSRFProtection.token = {
          generateToken: tokenConfig.generateToken || (() => Math.random().toString(36).slice(2)),
          addToJWT: tokenConfig.addToJWT ?? true,
          methodList
        }
      }
      if (!Object.keys(this.CSRFProtection).length) {
        vulnerabilities.push("No CSRF defense active.")
      }

      if(!props.ignoreVulnerabilities) {
        if(vulnerabilities.length) {
          if(NODE_ENV !== "production") {
            console.log("AuthJWT configuration vulnerabilities:", vulnerabilities)
          } else {
            console.log("Running NODE_ENV production with vulnerabilities")
            console.log("AuthJWT configuration vulnerabilities:", vulnerabilities)
            throw Error("Stopping API due to vulnerabilities. To disable this check pass ignoreVulnerabilities to the AuthJWT instance.")
          }
        }
      }
    }
    
    this.JWTSignOptions =  props.JWTSignOptions || {};
    this.dataRefreshIntervalInSeconds = props.dataRefreshIntervalInSeconds || 15 * 60;
    this.tokenMaxAgeInSeconds = props.tokenMaxAgeInSeconds;
  }

  verify (AuthorizationHeader: string, forceDataRefresh?: boolean): Promise<JWTPayload<DataParams, JWTData>> {
    const [bearer, JWTString] = AuthorizationHeader.split(' ');
    if(bearer !== 'Bearer'){
      throw new Error('Authorization header should contain Bearer <token>')
    }
    const { tokenMaxAgeInSeconds } = this;
    return new Promise((resolve, reject) => {
      jwt.verify(JWTString, this.secret, { ignoreExpiration: true }, function(err: jwt.VerifyErrors, decoded: JWTPayload<DataParams, JWTData>) {
        if (err) {
          reject(err)
        } else if(tokenMaxAgeInSeconds && decoded.oiat*1000 < (+new Date() - tokenMaxAgeInSeconds)) {
          reject({
            name: "TokenIssuedTooLongAgo",
            message: "original issue too long ago"
          })
        } else if(decoded.exp*1000 < +new Date() || forceDataRefresh) {
          //had to change this error to include decoded data
          reject({
            name: 'TokenExpiredError',
            message: 'jwt expired',
            expiredAt: decoded.exp,
            payload: decoded
          })
        } else {
          resolve(decoded)
        }
      })
    })
  }

  async generate (dataParams: DataParams, options?: JWTOptions) {
    if(!options) options = {}
    const iat = Math.floor(Date.now() / 1000);
    const oiat = options.oiat || iat
    const maxAge = options.maxAge ?? this.dataRefreshIntervalInSeconds;
    const JWTData = await this.getJWTData(dataParams, oiat)
    const JWTPayload = { data: JWTData, oiat, exp: iat + maxAge, iat, maxAge, dataParams }
    const JWTString = jwt.sign(JWTPayload, this.secret, this.JWTSignOptions)
    return {
      JWTPayload,
      JWT: JWTString
    }
  }
}

export interface AuthJWT<DataParams, ExpandedData> {
  _memoizedData: ExpandedData | null | undefined
  getData: (forceDataRefresh?: boolean) => Promise<ExpandedData | null>
  generate: (dataParams: DataParams, options?: JWTOptions) => Promise<{
    JWTPayload: JWTPayload<DataParams, ExpandedData>
    data: ExpandedData
    JWT: string
  }>
  refreshData: () => Promise<ExpandedData | null>
  remove: () => void
  checkCSRF: () => Promise<Array<string>>
}
interface JWTPayload<DataParams, JWTData> {
  dataParams: DataParams
  data: JWTData
  iat: number //isuing time
  exp: number //inbuilt expriation time
  oiat: number //original issuing time
  maxAge: number
}
export interface JWTOptions {
  maxAge?: number,
  oiat?: number
}
type getJWTData<DataParams, JWTData> = (dataParams: DataParams, oiat: number) => Promise<JWTData>

export interface CookieOptions {
  httpOnly?: boolean
  sameSite?: "strict" | "lax" | "none" 
  secure?: boolean
  domain?: string
  path?: string
}

interface CookieConfig {
  useCookie: boolean
  cookieOptions?: CookieOptions
  CSRFProtection?: {
    customHeader?: { 
      active?: boolean
      checkSafeMethods?: boolean
      checkMethodList?: ReadonlyArray<typeof HTTP_METHODS[number]>
      headerName?: string
    }
    originCheck?: { 
      active?: boolean,
      checkSafeMethods?: boolean
      checkMethodList?: ReadonlyArray<typeof HTTP_METHODS[number]>
      domains: Array<string>,
      allowWithoutDomain: boolean 
    } 
    tokenConfig?: {
      active?: boolean
      checkSafeMethods?: boolean
      checkMethodList?: ReadonlyArray<typeof HTTP_METHODS[number]>
      generateToken?: () => string
      addToJWT?: boolean
    }
    IGNORE_CSRF_WARNING?: boolean
  }
}

interface JWTAuthProps<DataParams, JWTData> {
  ignoreVulnerabilities?: boolean,
  secret: string, 
  getJWTData: getJWTData<DataParams, JWTData>
  cookieConfig?: CookieConfig
  JWTSignOptions?: SignOptions
  dataRefreshIntervalInSeconds?: number
  tokenMaxAgeInSeconds?: number
}

