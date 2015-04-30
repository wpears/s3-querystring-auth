'use strict';
var crypto = require('crypto');
var util = require('util');
var aws = require('aws-sdk');


function getUrl(bucket, resource, profile){
  var credentials;

  if(process.env.AWS_ACCESS_KEY_ID){
    credentials = new aws.EnvironmentCredentials('AWS');
  }else{
   credentials = new aws.SharedIniFileCredentials({profile: profile});
  }
  
  var isoCombined = (new Date()).toISOString().replace(/[:-]|\.\d{3}/g,'');
  var scope = getScope(isoCombined);

  var queryParams = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': util.format('%s/%s', credentials.accessKeyId, scope),
    'X-Amz-Date': isoCombined,
    'X-Amz-Expires': '86400',
    'X-Amz-SignedHeaders': 'host',
    'X-Amz-Signature': null
  }

  queryParams['X-Amz-Signature'] = calculateSignature(resource, credentials, scope, queryParams);

}


function getScope(isoCombined){
  return isoCombined.slice(0,8) + '/us-east-1/s3/aws4_request';
}


function calculateSignature(resource, credentials, scope, queryParams){
  var signingKey = getSigningKey(credentials.secretAccessKey, scope.split('/')[0]) 
  var stringToSign = getStringToSign(resource, scope, queryParams);

  return hmac(signingKey, stringToSign);
}


function getSigningKey(secretAccessKey, scope){
  var scopeArr = scope.split('/');
  var dateKey = hmac("AWS4" + secretAccessKey, scope[0]); 
  var dateRegionKey = hmac(dateKey, scope[1]);
  var dateRegionServiceKey = hmac(dateRegionKey, scope[2]);

  return hmac(dateRegionServiceKey, scope[3])
}


function getStringToSign(resource, scope, queryParams){
  var canonicalRequest = getCanonicalRequest(resource, queryParams);

  return util.format('%s\n%s\n%s\n%s',
    queryParams['X-Amz-Algorithm'],
    queryParams['X-Amz-Date'],
    scope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex')
  )
}


function getCanonicalRequest(resource, queryParams){

}


function hmac(key, data){
  var hmacObj = crypto.createHmac('sha256', key);
  hmacObj.update(data);
  return hmacObj.digest();
}

public static String uri-encode(CharSequence input, boolean encodeSlash) {
              if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '~' || ch == '.') {
                  result.append(ch);
              } else if (ch == '/') {
                  result.append(encodeSlash ? "%2F" : ch);
              } else {
                  result.append(toHexUTF8(ch));
              }
          }
          return result.toString();
      }

function encodeAwsUri(input, ignoreSlash){
  var result = '';
  var allowed = /[\w~\-.]/

  for(var i=0; i<input.length; i++){
    var curr = input[i];

    if(allowed.test(curr) || curr === '/' && ignoreSlash) {
      result += curr;  
    }else{ 
      result += escapeChar(curr);
    }
  }

  return result;
}

function escapeChar(character){
  return '%' + (new Buffer(character)).toString('hex').toUpperCase()
}
