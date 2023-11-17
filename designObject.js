const cordra = require('cordra');
const cordraUtil = require('cordraUtil');

let providerPublicKey = null;

exports.authenticate = authenticate;

function authenticate(authInfo, context) {
    print("__authenticate__")
    print(Object.getOwnPropertyNames(authInfo))
    print(authInfo.username)
    print(authInfo.token)
    print(Object.getOwnPropertyNames(context))
    cacheKeyIfNeeded();
    if (isTokenAuthentication(authInfo)) {
        return checkCredentials(authInfo);
    } else {
        print("__return null__")
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
    print("__isJwtFromProvider__")
    try  {
        if (!token.includes(".")){
            print("token does not include .")
            print(token)
            return false
        }
        const claims = cordraUtil.extractJwtPayload(token);    
        print("verify claims")
        if ("https://accounts.google.com" == claims.iss){
            return true
        }
    } catch (error) {
        print(error)
        return false;
    }
}

function checkCredentials(authInfo) {
    print("__enter checkCredentials__")
    print("__Good till here___")
    print(Object.getOwnPropertyNames(authInfo))
    const token = authInfo.token;
    const payload = cordraUtil.extractJwtPayload(token);
    print(Object.getOwnPropertyNames(payload))
    const isVerified = true;
    print("isVerified:")
    print(isVerified)
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
    print("_______________")
    print(Object.getOwnPropertyNames(result))
    print(result.userId)
    print(result.active)
    print(result.exp)
    print(result.grantAuthenticatedAccess)
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
    print("__check Claims__")
    if (!claims.iss || !claims.exp || !claims.aud) {
        print("return in first")
        return false;
    }
    if ("https://accounts.google.com" !== claims.iss) {
        print("returen in second")
        return false;
    }
    const nowInSeconds = Math.floor(Date.now() / 1000);
    if (nowInSeconds > claims.exp) {
        print("return in third")
        return false;
    }
    const aud = claims.aud;
    print(aud)
    if (!checkAudience(aud)) {
        print("return in fourth")
        return false;
    }
    print("its ture baby")
    return true;
}

function checkAudience(audElement) {
    print("__check AUdience__")
    let aud = [];
    if (typeof audElement === "string") {
        aud.push(audElement);
    } else if (Array.isArray(audElement)) {
        aud = audElement;
    } else {
        print("__return in first")
        return false;
    }
    return true
    print(aud.includes(".apps.googleusercontent.com"))
    if (aud.includes("https://cordra.org/")) {
        return true;
    } else {
        return false;
    }
}

function cacheKeyIfNeeded() {
    if (!providerPublicKey) {
        const configDir = getDataDir();
        const File = Java.type('java.io.File');
        const keyPath = configDir + File.separator + "publicKey.jwk";
        providerPublicKey =  cordraUtil.getCordraPublicKey()
        return true
        providerPublicKey = readFileToJsonAndParse(keyPath);
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