'use strict';
var crypto = require('crypto');
var util = require('util');
var aws = require('aws-sdk');


function getUrl(bucket, resource, profile){
  if(resource[0] !== '/') resource = '/' + resource;

  var credentials;

  if(process.env.AWS_ACCESS_KEY_ID){
    credentials = new aws.EnvironmentCredentials('AWS');
  }else{
   credentials = new aws.SharedIniFileCredentials({profile: profile});
  }
  
  var isoCombined = (new Date('Fri, 24 May 2013 00:00:00 GMT')).toISOString().replace(/[:-]|\.\d{3}/g,'');
  var scope = getScope(isoCombined);

  var queryParams = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': util.format('%s/%s', credentials.accessKeyId, scope),
    'X-Amz-Date': isoCombined,
    'X-Amz-Expires': '86400',
    'X-Amz-SignedHeaders': 'host',
    'X-Amz-Signature': null
  }

  queryParams['X-Amz-Signature'] = calculateSignature(bucket, resource, credentials, scope, queryParams);
  
  return util.format('https://%s.s3.amazonaws.com%s?%s',
           bucket,
           resource,
           Object.keys(queryParams)
            .map(function(v){
              return v + '=' + encodeAwsUri(queryParams[v]);
            })
            .join('&')
         )
}


function getScope(isoCombined){
  return isoCombined.slice(0,8) + '/us-east-1/s3/aws4_request';
}


function calculateSignature(bucket, resource, credentials, scope, queryParams){
  var canonicalRequest = getCanonicalRequest(bucket, resource, queryParams);
  var signingKey = getSigningKey(credentials.secretAccessKey, scope) 
  var stringToSign = getStringToSign(canonicalRequest, scope, queryParams);
 
  return hmac(signingKey, stringToSign).toString('hex');
}


function getSigningKey(secretAccessKey, scope){
  var scopeArr = scope.split('/');
  var dateKey = hmac("AWS4" + secretAccessKey, scopeArr[0]); 
  var dateRegionKey = hmac(dateKey, scopeArr[1]);
  var dateRegionServiceKey = hmac(dateRegionKey, scopeArr[2]);

  return hmac(dateRegionServiceKey, scopeArr[3])
}


function getStringToSign(canonicalRequest, scope, queryParams){
  return util.format('%s\n%s\n%s\n%s',
    queryParams['X-Amz-Algorithm'],
    queryParams['X-Amz-Date'],
    scope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex')
  )
}


function getCanonicalRequest(bucket, resource, queryParams){

  var queryString = Object.keys(queryParams).sort().reduce(function(a, b){
    if(!queryParams[b]){
      return a;
    }
    return a + (a?'&':'') + encodeAwsUri(b) + '=' + encodeAwsUri(queryParams[b])
  }, '') 
   
  return util.format('%s\n%s\n%s\n%s\n\n%s\n%s',
          'GET',
           encodeAwsUri(resource, 1),
           queryString,
          'host:' + bucket.trim() + '.s3.amazonaws.com',
          'host',
          'UNSIGNED-PAYLOAD'
         )
}


function hmac(key, data){
  var hmacObj = crypto.createHmac('sha256', key);
  hmacObj.update(data);
  return hmacObj.digest();
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


module.exports = getUrl;
