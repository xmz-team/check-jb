/* --------------*----*-- name: jbd.mm --*----*-------------- */
/* --------------*----*-- mode: ObjC++ --*----*-------------- */

#import "jbd.h"
#include "info.h"
#include <libxmz/aux.hpp>
#include <libxmz/fs.hpp>
#include <libxmz/log.hpp>
#include <libxmz/io.hpp>

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <glob.h>
#include <fnmatch.h>
#include <stdlib.h>

@interface JailbreakDetector ()
@property (nonatomic, strong) NSDictionary *rules;
@property (nonatomic, strong) NSMutableArray<NSString *> *mergedJBPaths;
@end

@implementation JBFinding @end

@implementation JailbreakDetector
+ (instancetype)shared {
    static JailbreakDetector *inst;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [JailbreakDetector new]; });
    return inst;
}

#pragma mark - load plist
- (void)loadRules {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir  = [docs stringByAppendingPathComponent:@"io.github.xmz-team.Check-JB"];
    NSString *path = [dir stringByAppendingPathComponent:@"jailbreak-rules.plist"];

    if (!xmz::aux::is_dir(dir.UTF8String)) {
        if (!xmz::fs::mkdir(dir.UTF8String)) {
            xmz::log::error("failed to create rules dir:", dir.UTF8String);
            return;
        }
        xmz::log::info("rules dir created:", dir.UTF8String);
    }

    if (!xmz::aux::is_file(path.UTF8String)) {
        if (!xmz::fs::writefile(std::string(jb_rules), path.UTF8String)) {
            xmz::log::error("failed to write default rules:", path.UTF8String);
            return;
        }
        xmz::log::info("default rules written:", path.UTF8String);
    }

    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) {
        xmz::log::error("rules file read failed:", path.UTF8String);
        return;
    }

    NSError *err = nil;
    id obj = [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:&err];
    if (![obj isKindOfClass:[NSDictionary class]]) {
        xmz::log::error("rules plist parse failed");
        return;
    }

    self.rules = obj;
    [self mergeJBPaths];
    xmz::log::info("jailbreak rules loaded from:", path.UTF8String);
}

#pragma mark - jb_path
- (NSArray<NSString *> *)mergePathsWithJBVariant:(NSArray<NSString *> *)raw {
    if (![raw isKindOfClass:[NSArray class]]) return @[];
    NSMutableArray<NSString *> *merged = [NSMutableArray arrayWithCapacity:raw.count * 4];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    /* /var/containers/Bundle/Application/.jbroot-*, the absolute path of roothide‘s directory on the file system */
    NSMutableArray<NSString *> *roothide_dir = [NSMutableArray array];
    NSString *bundleApp = @"/var/containers/Bundle/Application";
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray<NSString *> *entries = [fm contentsOfDirectoryAtPath:bundleApp error:nil];
    for (NSString *entry in entries) if ([entry hasPrefix:@".jbroot-"]) [roothide_dir addObject:[bundleApp stringByAppendingPathComponent:entry]];
    // /private/preboot/*/dopamine-*/procursus, the absolute path of rootless(dopamine) on the file system
    NSMutableArray<NSString *> *dopamine_dir = [NSMutableArray array];
    NSArray<NSString *> *prebootExpanded = GlobExpand(@"/private/preboot/*/dopamine-*/procursus");
    for (NSString *p in prebootExpanded) if (DirExists(p)) [dopamine_dir addObject:p];

    for (NSString *p in raw) {
        if (![p isKindOfClass:[NSString class]] || p.length == 0) continue;
        // rootful
        if (![seen containsObject:p]) {
            [merged addObject:p];
            [seen addObject:p];
        }
        // rootless
        if (![p hasPrefix:@"/var/jb"]) {
            NSString *v = [@"/var/jb" stringByAppendingString:p];
            if (![seen containsObject:v]) {
                [merged addObject:v];
                [seen addObject:v];
            }
        }
        // roothide
        for (NSString *root in roothide_dir) {
            NSString *v = [root stringByAppendingString:p];
            if (![seen containsObject:v]) {
                [merged addObject:v];
                [seen addObject:v];
            }
        }
        // rootless(dopamine), because Dopamine's hidden jailbreak only hides the /var/jb path, so it is queried through the absolute path
        for (NSString *root in dopamine_dir) {
            NSString *v = [root stringByAppendingString:p];
            if (![seen containsObject:v]) {
                [merged addObject:v];
                [seen addObject:v];
            }
        }
    }
    return merged;
}

- (void)mergeJBPaths {
    NSArray<NSString *> *raw = self.rules[@"jb_path"];
    self.mergedJBPaths = [[self mergePathsWithJBVariant:raw] mutableCopy];
    xmz::log::info("jb_path merged count:", (int)self.mergedJBPaths.count);
}

#pragma mark - tools
static inline BOOL HasGlob(NSString *p) {
    return [p rangeOfString:@"*"].location != NSNotFound ||
           [p rangeOfString:@"?"].location != NSNotFound ||
           [p rangeOfString:@"["].location != NSNotFound;
}

static NSArray<NSString *> *GlobExpand(NSString *pattern) {
    NSMutableArray<NSString *> *result = [NSMutableArray array];
    if (pattern.length == 0) return result;
    glob_t *g = (glob_t *)calloc(1, sizeof(glob_t));
    if (!g) return result;
    int r = glob(pattern.UTF8String, GLOB_TILDE | GLOB_BRACE, NULL, g);
    if (r == 0) {
        for (size_t i = 0; i < g->gl_pathc; i++) {
            const char *path = g->gl_pathv[i];
            if (path) {
                [result addObject:[NSString stringWithUTF8String:path]];
            }
        }
    }
    globfree(g);
    free(g);
    return result;
}

static BOOL PathExists(NSString *p) {
    if (p.length == 0) return NO;
    if (HasGlob(p)) {
        NSArray<NSString *> *expanded = GlobExpand(p);
        for (NSString *e in expanded) {
            if (xmz::aux::exist(e.UTF8String) || xmz::aux::is_file(e.UTF8String)) {
                return YES;
            }
        }
        return NO;
    }
    return xmz::aux::exist(p.UTF8String) || xmz::aux::is_file(p.UTF8String);
}

static BOOL DirExists(NSString *p) {
    if (p.length == 0 || [p isEqualToString:@"/"]) return NO;
    if (HasGlob(p)) {
        NSArray<NSString *> *expanded = GlobExpand(p);
        for (NSString *e in expanded) {
            if (xmz::aux::is_dir(e.UTF8String)) return YES;
        }
        return NO;
    }
    return xmz::aux::is_dir(p.UTF8String);
}

static BOOL SymlinkExists(NSString *p) {
    if (p.length == 0) return NO;
    if (HasGlob(p)) {
        NSArray<NSString *> *expanded = GlobExpand(p);
        for (NSString *e in expanded) {
            struct stat st;
            if (lstat(e.UTF8String, &st) == 0 && S_ISLNK(st.st_mode)) return YES;
        }
        return NO;
    }
    struct stat st;
    return lstat(p.UTF8String, &st) == 0 && S_ISLNK(st.st_mode);
}

#pragma mark - check
- (void)checkFiles:(NSArray<NSString *> *)list
          category:(NSString *)cat
             into:(NSMutableArray<JBFinding *> *)out {
    for (NSString *p in list) {
        if (![p isKindOfClass:[NSString class]] || p.length == 0) continue;
        if (PathExists(p)) {
            JBFinding *f = [JBFinding new];
            f.category = cat;
            f.detail   = p;
            f.weight   = 20;
            [out addObject:f];
        }
    }
}

- (void)checkDirs:(NSArray<NSString *> *)list
             into:(NSMutableArray<JBFinding *> *)out {
    for (NSString *p in list) {
        if (![p isKindOfClass:[NSString class]] || p.length == 0) continue;
        if (DirExists(p)) {
            JBFinding *f = [JBFinding new];
            f.category = @"accessible-dir";
            f.detail   = p;
            f.weight   = 25;
            [out addObject:f];
        }
    }
}

- (void)checkSymlinks:(NSArray<NSString *> *)list
                 into:(NSMutableArray<JBFinding *> *)out {
    for (NSString *p in list) {
        if (![p isKindOfClass:[NSString class]] || p.length == 0) continue;
        if (SymlinkExists(p)) {
            JBFinding *f = [JBFinding new];
            f.category = @"symlink";
            f.detail   = p;
            f.weight   = 15;
            [out addObject:f];
        }
    }
}

- (void)checkLoadedImages:(NSArray<NSString *> *)libs
                     into:(NSMutableArray<JBFinding *> *)out {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *img = _dyld_get_image_name(i);
        if (!img) continue;
        NSString *name = [NSString stringWithUTF8String:img];
        for (NSString *sus in libs) {
            if (![sus isKindOfClass:[NSString class]] || sus.length == 0) continue;
            if ([name rangeOfString:sus].location != NSNotFound) {
                JBFinding *f = [JBFinding new];
                f.category = @"loaded-dylib";
                f.detail   = name;
                f.weight   = 40;
                [out addObject:f];
            }
        }
    }
}

- (void)checkURLSchemes:(NSArray<NSDictionary *> *)schemes
                   into:(NSMutableArray<JBFinding *> *)out {
    for (NSDictionary *d in schemes) {
        if (![d isKindOfClass:[NSDictionary class]]) continue;
        NSString *scheme = d[@"scheme"];
        if (![scheme isKindOfClass:[NSString class]] || scheme.length == 0) continue;
        NSURL *url = [NSURL URLWithString:scheme];
        if (url && [[UIApplication sharedApplication] canOpenURL:url]) {
            JBFinding *f = [JBFinding new];
            f.category = @"url-scheme";
            f.detail   = [NSString stringWithFormat:@"%@ (%@)", d[@"description"], scheme];
            f.weight   = 30;
            [out addObject:f];
        }
    }
}

- (void)checkEnv:(NSArray<NSString *> *)vars
            into:(NSMutableArray<JBFinding *> *)out {
    for (NSString *v in vars) {
        if (![v isKindOfClass:[NSString class]] || v.length == 0) continue;
        const char *val = getenv(v.UTF8String);
        if (val != NULL) {
            JBFinding *f = [JBFinding new];
            f.category = @"env-var";
            f.detail   = [NSString stringWithFormat:@"%s=%s", v.UTF8String, val];
            f.weight   = 25;
            [out addObject:f];
        }
    }
}

- (void)checkPorts:(NSArray<NSDictionary *> *)ports
              into:(NSMutableArray<JBFinding *> *)out {
    for (NSDictionary *d in ports) {
        if (![d isKindOfClass:[NSDictionary class]]) continue;
        NSInteger port = [d[@"port"] integerValue];
        if (port <= 0) continue;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port   = htons((uint16_t)port);
        a.sin_addr.s_addr = inet_addr("127.0.0.1");
        fcntl(s, F_SETFL, O_NONBLOCK);
        int r = connect(s, (struct sockaddr *)&a, sizeof(a));
        close(s);
        if (r == 0 || errno == EISCONN) {
            JBFinding *f = [JBFinding new];
            f.category = @"open-port";
            f.detail   = [NSString stringWithFormat:@"%ld (%@)", (long)port, d[@"description"]];
            f.weight   = 40;
            [out addObject:f];
        }
    }
}

- (void)checkObjCClasses:(NSArray<NSDictionary *> *)classes
                    into:(NSMutableArray<JBFinding *> *)out {
    for (NSDictionary *d in classes) {
        if (![d isKindOfClass:[NSDictionary class]]) continue;
        NSString *cls = d[@"className"];
        if (![cls isKindOfClass:[NSString class]] || cls.length == 0) continue;
        Class c = objc_getClass(cls.UTF8String);
        if (c) {
            JBFinding *f = [JBFinding new];
            f.category = @"objc-class";
            f.detail   = cls;
            f.weight   = 30;
            [out addObject:f];
        }
    }
}

#pragma mark - main
- (NSArray<JBFinding *> *)runAllChecks {
    NSMutableArray<JBFinding *> *out = [NSMutableArray array];
    NSDictionary *r = self.rules ?: @{};

    NSArray *jbPath        = self.mergedJBPaths ?: @[];
    NSArray *other         = r[@"other"];
    NSArray *susLibrary    = r[@"suspicious_library"];
    NSArray *susMobileFile = [self mergePathsWithJBVariant:r[@"suspicious_mobile_file"]];
    NSArray *susRootFile   = [self mergePathsWithJBVariant:r[@"suspicious_root_file"]];
    NSArray *susObjCClass  = r[@"suspicious_objc_class"];
    NSArray *susPort       = r[@"suspicious_port"];
    NSArray *susURLScheme  = r[@"suspicious_url-scheme"];
    NSArray *unsafeEnv     = r[@"unsafe_env_value"];

    // jb_path
    [self checkFiles:jbPath category:@"jb_path" into:out];

    // other
    [self checkFiles:other category:@"other" into:out];

    // suspicious_mobile_file
    [self checkFiles:susMobileFile category:@"mobile-file" into:out];

    // suspicious_root_file
    [self checkFiles:susRootFile category:@"root-file" into:out];

    // suspicious_library
    [self checkFiles:susLibrary category:@"suspicious-library" into:out];
    [self checkLoadedImages:susLibrary into:out];

    // suspicious_objc_class
    [self checkObjCClasses:susObjCClass into:out];

    // suspicious_port
    [self checkPorts:susPort into:out];

    // suspicious_url-scheme
    [self checkURLSchemes:susURLScheme into:out];

    // unsafe_env_value
    [self checkEnv:unsafeEnv into:out];

    // Sandbox write detection
    NSString *probe = @"/private/var/xmz_jb_probe";
    if (xmz::fs::touch(probe.UTF8String)) {
        xmz::fs::rmfile(probe.UTF8String);
        JBFinding *f = [JBFinding new];
        f.category = @"sandbox";
        f.detail   = @"can write outside sandbox";
        f.weight   = 100;
        [out addObject:f];
    }

    // fork check
    pid_t pid = fork();
    if (pid >= 0) {
        if (pid == 0) _exit(0);
        JBFinding *f = [JBFinding new];
        f.category = @"fork";
        f.detail   = @"fork succeeded";
        f.weight   = 80;
        [out addObject:f];
    }
    return out;
}

- (JBThreatLevel)levelForFindings:(NSArray<JBFinding *> *)findings {
    NSInteger score = 0;
    for (JBFinding *f in findings) score += f.weight;
    if (score >= 100) return JBThreatLevelJailbroken;
    if (score >= 30)  return JBThreatLevelSuspicious;
    return JBThreatLevelClean;
}
@end
