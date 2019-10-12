# tencentcloud-ios
腾讯云api3.0签名v3 ios版本

使用方法：

直接将两个文件拖到项目，在需要使用的地方引入头文件，只需要setConfig一次。


示例如下:

```objective-c
#import "TencentCloudAPI3.h"
// 以下内容，需要从云api中获取
// 1、初始化，只需要初始化一次
NSString *SECRET_ID = @"<替换为你的id>";
NSString *SECRET_KEY = @"<替换为你的key>";
NSString *HOST = @"xx.tencentcloudapi.com";
NSString *SERVICE = @"xx";
NSString *VERSION = @"2018-04-08";
[[TencentCloudAPI3 TC] setConfig:@{
  @"SECRET_ID": SECRET_ID,
  @"SECRET_KEY": SECRET_KEY,
  @"HOST": HOST,
  @"SERVICE": SERVICE,
  @"VERSION": VERSION
}];
 // 2、构造数据
 NSDictionary *getTokenParams = @{
   @"action": @"xxxxx", // action是接口的Action
   @"data": @{ // data里面是真正的数据
     @"Bid": @1,
     @"Scene": @2
   }
 };
   
// 3、获取token示例
[[TencentCloudAPI3 TC] getResult:getTokenParams success:^(NSDictionary *responseObject){
  NSLog(@"responseObject");
  NSLog(@"%@", responseObject);
} failure:^(NSError *error){
  NSLog(@"error");
  NSLog(@"%@", error.localizedDescription);
}];
```

