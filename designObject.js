const cordra = require('cordra');
const cordraUtil = require('cordraUtil');

let providerPublicKey = null;

exports.authenticate = authenticate;

function authenticate(authInfo, context) {
    cacheKeyIfNeeded();
    if (isTokenAuthentication(authInfo)) {
        return checkCredentials(authInfo);
    } else {
        return null;
    }
}

function isTokenAuthentication(authInfo) {
    if (authInfo.token) {
        if (isJwtFromProvider(authInfo.token)) {
            return true;
        }
    }
    return false;
}

function isJwtFromProvider(token) {
    try  {
        if (!token.includes(".")){
            return false
        }
        const claims = cordraUtil.extractJwtPayload(token);    
        if ("https://accounts.google.com" == claims.iss){
            return true
        }
    } catch (error) {
        return false;
    }
}

function checkCredentials(authInfo) {
    const token = authInfo.token;
    const payload = cordraUtil.extractJwtPayload(token);
    const isVerified = true;
    const claimsCheck = checkClaims(payload);
    const active = isVerified && claimsCheck;
    const result = {
        active: active
    };
    if (active) {
        result.userId = payload.sub;
        if (payload.username) {
            result.username = payload.username;
        }
        if (payload.groupIds) {
            result.groupIds = payload.groupIds;
        }
        if (payload.exp) {
            result.exp = payload.exp;
        }
        result.grantAuthenticatedAccess = true;
    }
    return result;
}

function isBasicAuth(authHeader) {
    return authHeader.startsWith("Basic ");
}

function isBearerTokenAuth(authHeader) {
    return authHeader.startsWith("Bearer ");
}

function getTokenFromAuthHeader(authHeader) {
    return authHeader.substring(authHeader.indexOf(" ") + 1);
}

function checkClaims(claims) {
    if (!claims.iss || !claims.exp || !claims.aud) {
        return false;
    }
    if ("https://accounts.google.com" !== claims.iss) {
        return false;
    }
    const nowInSeconds = Math.floor(Date.now() / 1000);
    if (nowInSeconds > claims.exp) {
        return false;
    }
    const aud = claims.aud;
    print(aud)
    if (!checkAudience(aud)) {
        return false;
    }
    return true;
}

function checkAudience(audElement) {
    let aud = [];
    if (typeof audElement === "string") {
        aud.push(audElement);
    } else if (Array.isArray(audElement)) {
        aud = audElement;
    } else {
        return false;
    }
    return true
}

function cacheKeyIfNeeded() {
    if (!providerPublicKey) {
        const configDir = getDataDir();
        const File = Java.type('java.io.File');
        const keyPath = configDir + File.separator + "publicKey.jwk";
        providerPublicKey =  cordraUtil.getCordraPublicKey()
        return true
    }
}

function getDataDir() {
    const System = Java.type('java.lang.System');
    const cordraDataDir = System.getProperty('cordra.data');
    return cordraDataDir;
}

function readFileToString(pathToFile) {
    const path = Java.type('java.nio.file.Paths').get(pathToFile);
    const string = Java.type('java.nio.file.Files').readString(path);
    return string;
}

function readFileToJsonAndParse(pathToFile) {
    const jsonString = readFileToString(pathToFile);
    const result = JSON.parse(jsonString);
    return result;
}