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
  var isoDate = isoCombined.slice(0,8);

  var queryParams = [
    {param: 'X-Amz-Algorithm', value: 'AWS4-HMAC-SHA256'},
    {param: 'X-Amz-Credential', value: util.format('%s/%s/us-east-1/s3/aws4_request', credentials.accessKeyId, isoDate)},
    {param: 'X-Amz-Date', value: isoCombined},
    {param: 'X-Amz-Expires', value: '86400'},
    {param: 'X-Amz-SignedHeaders', value: 'host'},
    {param: 'X-Amz-Signature', value: calculateSignature()}
  ].sort(function(a,b){return a.param > b.param})
    console.log(queryParams);
}
getUrl();

function calculateSignature(credentials, isoCombined){
  return hmac(getSigningKey(credentials, isoCombined), getStringToSign());
}


function getSigningKey(credentials, isoDate){
  var dateKey = hmac("AWS4" + credentials.secretAccessKey, isoCombined.slice(0,8)); 
  var dateRegionKey = hmac(dateKey, 'us-east-1');
  var dateRegionServiceKey = hmac(dateRegionKey, 's3');
  return hmac(dateRegionServiceKey, 'aws4_request')
}


function getStringToSign(){

}


function getCanonicalRequest(){

}


function hmac(key, data){
  var hmacObj = crypto.createHmac('sha256', key);
  hmacObj.update(data);
  return hmacObj.digest();
}
