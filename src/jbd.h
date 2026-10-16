/* --------------*----*-- name: jbd.h  --*----*-------------- */
/* --------------*----*-- mode: ObjC++ --*----*-------------- */

#pragma once
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

typedef NS_ENUM(NSInteger, JBThreatLevel) {
    JBThreatLevelClean = 0,
    JBThreatLevelSuspicious,
    JBThreatLevelJailbroken,
};

@interface JBFinding : NSObject
@property (nonatomic, copy) NSString *category;
@property (nonatomic, copy) NSString *detail;
@property (nonatomic, assign) NSInteger weight;
@end

@interface JailbreakDetector : NSObject
+ (instancetype)shared;
- (void)loadRules;
- (NSArray<JBFinding *> *)runAllChecks;
- (JBThreatLevel)levelForFindings:(NSArray<JBFinding *> *)findings;
@end
