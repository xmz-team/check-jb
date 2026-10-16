/* --------------*----*-- name: appd.mm --*----*-------------- */
/* --------------*----*-- mode: ObjC++  --*----*-------------- */

#import "jbd.h"
#include <libxmz/apple-ios-objc.hpp>
#include <libxmz/crash.hpp>
#include <libxmz/io.hpp>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace oc = xmz::ios::objc;

@interface ResultVC : UIViewController
@property (nonatomic, strong) UILabel *verdict;
@property (nonatomic, strong) UITextView *detail;
@end

@implementation ResultVC
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Jailbreak Check";
    self.view.backgroundColor = oc::color::system_background();

    self.verdict = oc::make::label(@"点击“开始检测”|Click `Start Testing`");
    self.verdict.font = oc::font::bold_system(24);

    self.detail = [[UITextView alloc] init];
    self.detail.editable = NO;
    self.detail.font = oc::font::monospaced(12);
    self.detail.translatesAutoresizingMaskIntoConstraints = NO;

    UIButton *btn = oc::make::button(@"开始检测|Start testing");
    [btn addTarget:self action:@selector(runCheck)
          forControlEvents:UIControlEventTouchUpInside];

    [self.view addSubview:self.verdict];
    [self.view addSubview:btn];
    [self.view addSubview:self.detail];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;

    [NSLayoutConstraint activateConstraints:@[
        [self.verdict.topAnchor constraintEqualToAnchor:safe.topAnchor constant:24],
        [self.verdict.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [self.verdict.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],
        [btn.topAnchor constraintEqualToAnchor:self.verdict.bottomAnchor constant:16],
        [btn.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.detail.topAnchor constraintEqualToAnchor:btn.bottomAnchor constant:16],
        [self.detail.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [self.detail.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],
        [self.detail.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-16],
    ]];
}

- (void)runCheck {
    JailbreakDetector *d = [JailbreakDetector shared];
    NSArray<JBFinding *> *findings = [d runAllChecks];
    JBThreatLevel level = [d levelForFindings:findings];

    switch (level) {
        case JBThreatLevelClean:
            self.verdict.text = @"未检测到越狱\nNo jailbreak detected";
            self.verdict.textColor = oc::color::system_green();
            break;
        case JBThreatLevelSuspicious:
            self.verdict.text = @"疑似越狱环境\nSuspected jailbreak environment";
            self.verdict.textColor = oc::color::yellow();
            break;
        case JBThreatLevelJailbroken:
            self.verdict.text = @"已越狱\nEscaped from prison";
            self.verdict.textColor = oc::color::system_red();
            break;
    }

    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"命中(Hit) %lu 项(item): \n\n", (unsigned long)findings.count];
    for (JBFinding *f in findings) {
        [s appendFormat:@"[%@] %@\n", f.category, f.detail];
    }
    self.detail.text = s;
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app
        didFinishLaunchingWithOptions:(NSDictionary *)opts {

    xmz::crash::init_crash_handler(
        [[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
          stringByAppendingPathComponent:@"crash.log"] UTF8String]);

    [[JailbreakDetector shared] loadRules];

    self.window = oc::make::window();
    self.window.rootViewController =
        oc::make::navctrl([[ResultVC alloc] init]);
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    seteuid(0);
    setuid(0);
    /* if (getuid() != 0) { abort(); } */
    return oc::ui::run(argc, argv, [AppDelegate class]);
}
