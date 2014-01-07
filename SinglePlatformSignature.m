//  SinglePlatformSignature.m
//
//Copyright (c) 2014 Ronak Jangir
//
//Permission is hereby granted, free of charge, to any person obtaining a copy of
//this software and associated documentation files (the "Software"), to deal in
//the Software without restriction, including without limitation the rights to
//use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
//the Software, and to permit persons to whom the Software is furnished to do so,
//subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
//FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
//COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
//IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
//CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#import "SinglePlatformSignature.h"
#import <CommonCrypto/CommonHMAC.h>
// Base64 Library for iOS 6 Support
#import "MF_Base64Additions.h"

@implementation SinglePlatformSignature

+ (NSString *) generateApiSingatureForPath:(NSString *)path
                                withParams:(NSDictionary *)parmas
                              withCliendId:(NSString *)clientId
                              andApiSecret:(NSString *)signingKey {
    path = [self mergeParamsToPath:path params:parmas];
    NSString *uri_path = [NSString stringWithFormat:@"%@client=%@",path,clientId];
    NSData *signature = [uri_path dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signxingKey =  [self decodeURLBase64String:signingKey];
    NSData *digest = [self hmacSha1:signature key:signxingKey];
    NSString *signatureBase64 = [self encodeURLBase64Data:digest];
    return [NSString stringWithFormat:@"%@&sig=%@", uri_path, signatureBase64];
}

+ (NSString *) mergeParamsToPath:(NSString *)path params:(NSDictionary *)params {
    __block NSString *paramsString = @"";
    [params enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        paramsString = [NSString stringWithFormat:@"%@=%@&",key,obj];
    }];
    return [NSString stringWithFormat:@"%@?%@",path,paramsString];
}

+ (NSData *) decodeURLBase64String:(NSString *)string {
    string = [string stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    string = [string stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    string = [NSString stringWithFormat:@"%@=",string];
    NSData *data = [self base64EncodedData:string];
    return data;
}

+ (NSData *) base64EncodedData:(NSString *)string {
    NSData *encodedData;
    if ([NSData resolveInstanceMethod:@selector(initWithBase64EncodedString:options:)]) {
        encodedData = [[NSData alloc] initWithBase64EncodedString:string options:0];
    } else {
        encodedData = [[NSData alloc] initWithBase64Encoding:string];
    }
    return encodedData;
}

+ (NSString *) encodeURLBase64Data:(NSData *)data {
    NSString *signatureBase64 = [self base64EncodedString:data];
    signatureBase64 = [signatureBase64 stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    signatureBase64 = [signatureBase64 stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    signatureBase64 = [signatureBase64 stringByReplacingOccurrencesOfString:@"=" withString:@""];
    return signatureBase64;
}

+ (NSString *) base64EncodedString:(NSData *)data {
    return [data respondsToSelector:@selector(base64EncodedStringWithOptions:)] ? [data base64EncodedStringWithOptions:0] : [data base64String];
}

+ (NSData *) hmacSha1:(NSData *)data key:(NSData *)key {
    NSMutableData *hmac = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
    CCHmac( kCCHmacAlgSHA1,
           key.bytes,  key.length,
           data.bytes, data.length,
           hmac.mutableBytes);
    return hmac;
}

@end
