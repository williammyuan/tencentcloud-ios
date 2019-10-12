//
//  TencentCloudAPI3.h
//
//  Created by xx on 2019/10/11.
//  Copyright © 2019 TencentCloud. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TencentCloudAPI3 : NSObject
@property(nonatomic, copy)NSString * SECRET_ID;
@property(nonatomic, copy)NSString * SECRET_KEY;
@property(nonatomic, copy)NSString * VERSION;
@property(nonatomic, copy)NSString * HOST;
@property(nonatomic, copy)NSString * SERVICE;
+(instancetype)TC;
-(void)setConfig:(NSDictionary *)config;
-(void)getResult:(NSDictionary *)params
         success:(void (^)(NSDictionary * obj))success
         failure:(void (^)(NSError *__nullable error))failure;
@end

NS_ASSUME_NONNULL_END
