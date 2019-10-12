//
//  TencentCloudAPI3.m
//
//  Created by xx on 2019/10/11.
//  Copyright © 2019 TencentCloud. All rights reserved.
//
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import "TencentCloudAPI3.h"
static TencentCloudAPI3 *tc3 = nil;
@implementation TencentCloudAPI3
+(instancetype)TC{
    if (tc3 == nil) {
        tc3 = [[TencentCloudAPI3 alloc]init];
    }
    return tc3;
}
// 设置
-(void)setConfig:(NSDictionary *)config{
    if (tc3 == nil) {
        tc3 = [[TencentCloudAPI3 alloc]init];
    }
    // 加个判断 todo
    tc3.SECRET_ID = config[@"SECRET_ID"];
    tc3.SECRET_KEY = config[@"SECRET_KEY"];
    tc3.VERSION = config[@"VERSION"];
    tc3.HOST = config[@"HOST"];
    tc3.SERVICE = config[@"SERVICE"];
}
// 获取结果
-(void)getResult:(NSDictionary *)params
         success:(void (^)(NSDictionary * obj))success
         failure:(void (^)(NSError *__nullable error))failure{
    NSDictionary *paramsDic = [tc3 sign: params];
    [self request:paramsDic[@"url"] parametersDict:params[@"data"] headers:paramsDic[@"header"] success:success failure:failure];
}
// 计算签名
-(NSDictionary *)sign:(NSDictionary *)params{
    // static Charset UTF8 = StandardCharsets.UTF_8;
    NSString *SECRET_ID = tc3.SECRET_ID;
    NSString *SECRET_KEY = tc3.SECRET_KEY;
    NSString *CT_JSON = @"application/json; charset=utf-8";
    NSString *service = tc3.SERVICE;
    NSString *host = tc3.HOST;
    NSString *hostn = [host stringByAppendingString:@"\n"];
    NSString *region = @"ap-guangzhou";
    NSString *action = params[@"action"];
    NSString *version = tc3.VERSION;
    NSString *algorithm = @"TC3-HMAC-SHA256";
    NSString *timestamp = [self currentTimestamp];
    NSString *date = [self utc0date];
    // ************* 步骤 1：拼接规范请求串 *************
    NSString *httpRequestMethod = @"POST";
    NSString *canonicalUri = @"/";
    NSString *canonicalQueryString = @"";
    NSString *canonicalHeaders = [@"content-type:application/json; charset=utf-8\nhost:" stringByAppendingString:hostn];
    NSString *signedHeaders = @"content-type;host";
    NSDictionary *payloadDic = params[@"data"];
    NSData *data1 = [NSJSONSerialization dataWithJSONObject:payloadDic options:0 error:nil];
    NSString *payloadJson = [[NSString alloc] initWithData:data1 encoding:NSUTF8StringEncoding];
    
    NSString *hashedRequestPayload = [self sha256HashFor:payloadJson];
//    NSString *canonicalRequest = httpRequestMethod + "\n" + canonicalUri + "\n" + canonicalQueryString + "\n"
//            + canonicalHeaders + "\n" + signedHeaders + "\n" + hashedRequestPayload;
    NSString *canonicalRequest= [[NSString alloc] initWithFormat:@"%@%@%@%@%@%@%@%@%@%@%@", httpRequestMethod,@"\n",canonicalUri,@"\n", canonicalQueryString,@"\n", canonicalHeaders,@"\n", signedHeaders,@"\n", hashedRequestPayload];
    NSLog(@"canonicalRequest:%@",canonicalRequest);
    // ************* 步骤 2：拼接待签名字符串 *************
    NSString *credentialScope = [[NSString alloc]initWithFormat: @"%@%@%@%@", date,@"/",service,@"/tc3_request"];
    NSString *hashedCanonicalRequest = [self sha256HashFor:canonicalRequest];
    NSString *stringToSign = [[NSString alloc] initWithFormat:@"%@%@%@%@%@%@%@", algorithm,@"\n",timestamp,@"\n",credentialScope,@"\n",hashedCanonicalRequest];
    NSLog(@"%@",stringToSign);
    
    // ************* 步骤 3：计算签名 *************
    
    NSString * key1 = [self hexStringFromString:[@"TC3" stringByAppendingString:SECRET_KEY]];
    NSString *secretDate = [self hmacForHexKey:key1 andStringData:date];
    NSLog(@"secretDate:%@", secretDate);
    
    NSString *secretService = [self hmacForHexKey:secretDate andStringData:service];
    NSLog(@"secretService:%@", secretService);
    
   
    NSString *secretSigning = [self hmacForHexKey:secretService andStringData:@"tc3_request"];
    NSLog(@"secretSigning:%@", secretSigning);
    
    NSString *signature = [self hmacForHexKey:secretSigning andStringData:stringToSign];
    
    NSLog(@"signature:%@", signature);
    
    // ************* 步骤 4：拼接 Authorization *************
    // NSString *authorization = algorithm + " " + "Credential=" + SECRET_ID + "/" + credentialScope + ", "
           // + "SignedHeaders=" + signedHeaders + ", " + "Signature=" + signature;
    NSString *authorization = [[NSString alloc] initWithFormat: @"%@ Credential=%@/%@, SignedHeaders=%@, Signature=%@",algorithm,SECRET_ID,credentialScope, signedHeaders, signature];
    NSLog(@"authorization:%@", authorization);
    
    NSDictionary *dic = @{
        @"header":@{
                @"authorization": authorization,
                @"version": version,
                @"host": host,
                @"action": action,
                @"timestamp": timestamp,
                @"region": region,
                @"contentType": CT_JSON,
                @"authorization": authorization,
        },
        @"url": [@"https://" stringByAppendingString:host]
    };
    return dic;
}
//SHA256加密
-(NSString*)sha256HashFor:(NSString*)input{
    const char* str = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(str, (CC_LONG)strlen(str), result);
    
    NSMutableString *ret = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for(int i = 0; i<CC_SHA256_DIGEST_LENGTH; i++)
    {
        [ret appendFormat:@"%02x",result[i]];
    }
    ret = (NSMutableString *)[ret uppercaseString];
    return [ret lowercaseString];
}
// hmac256加密
- (NSString *)hmacForHexKey:(NSString *)hexkey andStringData:(NSString *)data
{

    NSData *keyData = [self dataFromHexString:hexkey];

    const char *cKey  = [keyData bytes];
    const char *cData = [data cStringUsingEncoding:NSUTF8StringEncoding];

    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];

    CCHmac(kCCHmacAlgSHA256, cKey, keyData.length, cData, strlen(cData), cHMAC);

    return  [self convertDataToHexStr: [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)]];

}
// string 转data
- (NSData *)dataFromHexString:(NSString *)sHex {
    const char *chars = [sHex UTF8String];
    int i = 0;
    NSUInteger len = sHex.length;

    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;

    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    return data;
}
// 当前时间戳
-(NSString *)currentTimestamp {
    return [NSString stringWithFormat:@"%ld", (long)([[NSDate date] timeIntervalSince1970])];
    // return (long)([[NSDate date] timeIntervalSince1970]);
}
// 获取utc0时间
-(NSString *)utc0date{
    NSDate *currentDate = [NSDate date];
    //转为字符串
    NSDateFormatter *df = [[NSDateFormatter alloc]init];//实例化时间格式类
    NSTimeZone* timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0]; // 转换为utc0时间，详情见https://cloud.tencent.com/document/api/213/30654#1.-.E6.8B.BC.E6.8E.A5.E8.A7.84.E8.8C.83.E8.AF.B7.E6.B1.82.E4.B8.B2
    [df setTimeZone:timeZone];
    [df setDateFormat:@"yyyy-MM-dd"];
    return [df stringFromDate:currentDate];
}
// 普通转为16进制
- (NSString *)hexStringFromString:(NSString *)string{
    NSData *myD = [string dataUsingEncoding:NSUTF8StringEncoding];
    Byte *bytes = (Byte *)[myD bytes];
    //下面是Byte 转换为16进制。
    NSString *hexStr=@"";
    for(int i=0;i<[myD length];i++)
    {
        NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i]&0xff];///16进制数
        if([newHexStr length]==1)
            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
        else
            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
    }
    return hexStr;
}
- (NSString *)convertDataToHexStr:(NSData *)data{
    if (!data || [data length] == 0) {
        return @"";
    }
    NSMutableString *string = [[NSMutableString alloc] initWithCapacity:[data length]];
    
    [data enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
        unsigned char *dataBytes = (unsigned char*)bytes;
        for (NSInteger i = 0; i < byteRange.length; i++) {
            NSString *hexStr = [NSString stringWithFormat:@"%x", (dataBytes[i]) & 0xff];
            if ([hexStr length] == 2) {
                [string appendString:hexStr];
            } else {
                [string appendFormat:@"0%@", hexStr];
            }
        }
    }];
    
    return string;
}

-(void)request:(NSString *)URL
            parametersDict:(nullable NSDictionary *) parametersDict
            headers:(NSDictionary *)headers
            success:(void (^)(NSDictionary * obj))success
            failure:(void (^)(NSError *__nullable error))failure
{
    NSURL *url = [NSURL URLWithString:URL];
    // NSURLSession *session = [NSURLSession sharedSession];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setTimeoutInterval:10.0];
    // 设置请求方法
    [request setHTTPMethod:@"POST"];
    [request addValue:headers[@"authorization"] forHTTPHeaderField:@"Authorization"];
    [request addValue:headers[@"contentType"] forHTTPHeaderField:@"Content-Type"];
    [request addValue:headers[@"host"] forHTTPHeaderField:@"Host"];
    [request addValue:headers[@"action"] forHTTPHeaderField:@"X-TC-Action"];
    [request addValue:headers[@"timestamp"] forHTTPHeaderField:@"X-TC-Timestamp"];
    [request addValue:headers[@"version"] forHTTPHeaderField:@"X-TC-Version"];
    [request addValue:headers[@"region"] forHTTPHeaderField:@"X-TC-Region"];
    NSError *error;
    NSData *postData = [NSJSONSerialization dataWithJSONObject:parametersDict options:0 error:&error];
    NSString *jsonString;
    jsonString = [[NSString alloc] initWithData:postData encoding:NSUTF8StringEncoding];
    NSLog(@"%@", jsonString);
    [request setHTTPBody: postData];
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * data,NSURLResponse *response,NSError *error){
        if (error!=nil) {
            NSLog(@"错误");
            failure(error);
        }else{
            // 如果请求成功，则解析数据。
            id object = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableLeaves error:&error];
            if (error) {
                NSLog(@"post error :%@",error.localizedDescription);
                failure(error);
            }else {
                success(object);
                
                dispatch_async(dispatch_get_main_queue(), ^{
                    // 刷新界面...
                    // NSLog(@"刷新页面:");
                });
            }
        }
    }];
    [task resume];
}
@end
