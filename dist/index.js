"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWTAuth = exports.UNSAFE_METHODS = exports.SAFE_METHODS = exports.HTTP_METHODS = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
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
exports.HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"];
exports.SAFE_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE"];
exports.UNSAFE_METHODS = ["POST", "PUT", "PATCH", "DELETE", "CONNECT"];
class JWTAuth {
    constructor(props) {
        this.secret = props.secret;
        this.getJWTData = props.getJWTData;
        this.cookieConfig = undefined;
        if (props.cookieConfig && props.cookieConfig.useCookie) {
            const cookieOptions = {
                httpOnly: true,
                sameSite: "lax",
                secure: NODE_ENV === 'production',
                ...props.cookieConfig.cookieOptions
            };
            this.cookieConfig = {
                useCookie: true,
                cookieOptions,
            };
            const vulnerabilities = [];
            this.CSRFProtection = {};
            const { customHeader, originCheck, tokenConfig } = props.cookieConfig.CSRFProtection || {};
            if (customHeader) {
                const methodList = customHeader.checkMethodList || customHeader.checkSafeMethods ? exports.HTTP_METHODS : exports.UNSAFE_METHODS;
                this.CSRFProtection.customHeader = {
                    headerName: customHeader.headerName || "X-Requested-With",
                    methodList
                };
            }
            if (originCheck) {
                const methodList = originCheck.checkMethodList || originCheck.checkSafeMethods ? exports.HTTP_METHODS : exports.UNSAFE_METHODS;
                this.CSRFProtection.originCheck = {
                    domains: originCheck.domains,
                    allowWithoutDomain: originCheck.allowWithoutDomain,
                    methodList
                };
            }
            if (tokenConfig) {
                const methodList = tokenConfig.checkMethodList || tokenConfig.checkSafeMethods ? exports.HTTP_METHODS : exports.UNSAFE_METHODS;
                this.CSRFProtection.token = {
                    generateToken: tokenConfig.generateToken || (() => Math.random().toString(36).slice(2)),
                    addToJWT: tokenConfig.addToJWT ?? true,
                    methodList
                };
            }
            if (!Object.keys(this.CSRFProtection).length) {
                vulnerabilities.push("No CSRF defense active.");
            }
            if (!props.ignoreVulnerabilities) {
                if (vulnerabilities.length) {
                    if (NODE_ENV !== "production") {
                        console.log("AuthJWT configuration vulnerabilities:", vulnerabilities);
                    }
                    else {
                        console.log("Running NODE_ENV production with vulnerabilities");
                        console.log("AuthJWT configuration vulnerabilities:", vulnerabilities);
                        throw Error("Stopping API due to vulnerabilities. To disable this check pass ignoreVulnerabilities to the AuthJWT instance.");
                    }
                }
            }
        }
        this.JWTSignOptions = props.JWTSignOptions || {};
        this.dataRefreshIntervalInSeconds = props.dataRefreshIntervalInSeconds || 15 * 60;
        this.tokenMaxAgeInSeconds = props.tokenMaxAgeInSeconds;
    }
    verify(AuthorizationHeader, forceDataRefresh) {
        const [bearer, JWTString] = AuthorizationHeader.split(' ');
        if (bearer !== 'Bearer') {
            throw new Error('Authorization header should contain Bearer <token>');
        }
        const { tokenMaxAgeInSeconds } = this;
        return new Promise((resolve, reject) => {
            jsonwebtoken_1.default.verify(JWTString, this.secret, { ignoreExpiration: true }, function (err, decoded) {
                if (err) {
                    reject(err);
                }
                else if (tokenMaxAgeInSeconds && decoded.oiat * 1000 < (+new Date() - tokenMaxAgeInSeconds)) {
                    reject({
                        name: "TokenIssuedTooLongAgo",
                        message: "original issue too long ago"
                    });
                }
                else if (decoded.exp * 1000 < +new Date() || forceDataRefresh) {
                    //had to change this error to include decoded data
                    reject({
                        name: 'TokenExpiredError',
                        message: 'jwt expired',
                        expiredAt: decoded.exp,
                        payload: decoded
                    });
                }
                else {
                    resolve(decoded);
                }
            });
        });
    }
    async generate(dataParams, options) {
        if (!options)
            options = {};
        const iat = Math.floor(Date.now() / 1000);
        const oiat = options.oiat || iat;
        const maxAge = options.maxAge ?? this.dataRefreshIntervalInSeconds;
        const JWTData = await this.getJWTData(dataParams, oiat);
        const JWTPayload = { data: JWTData, oiat, exp: iat + maxAge, iat, maxAge, dataParams };
        const JWTString = jsonwebtoken_1.default.sign(JWTPayload, this.secret, this.JWTSignOptions);
        return {
            JWTPayload,
            JWT: JWTString
        };
    }
}
exports.JWTAuth = JWTAuth;
