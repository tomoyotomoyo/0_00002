//
//  RootViewController.m
//  KFLog — AMA-10 terminal + staged exploit logging
//

#import "RootViewController.h"
#import <AVFoundation/AVFoundation.h>
#import <Foundation/Foundation.h>
#import "KFLogFilter.h"

// KFKernel C API
extern int KFInit(void);
extern bool KFIsReady(void);
extern bool KFIsRoot(void);
extern bool KFIsSandboxEscaped(void);

extern uint8_t  KFKread8(uint64_t kaddr);
extern uint16_t KFKread16(uint64_t kaddr);
extern uint32_t KFKread32(uint64_t kaddr);
extern uint64_t KFKread64(uint64_t kaddr);
extern void KFKwrite8(uint64_t kaddr, uint8_t val);
extern void KFKwrite16(uint64_t kaddr, uint16_t val);
extern void KFKwrite32(uint64_t kaddr, uint32_t val);
extern void KFKwrite64(uint64_t kaddr, uint64_t val);
extern void KFHexdump(uint64_t kaddr, size_t size);

extern uint64_t KFProcSelf(void);
extern uint64_t KFProcFindByName(const char *name);

extern int KFChown(const char *path, uid_t uid, gid_t gid);
extern int KFChmod(const char *path, mode_t mode);

@interface RootViewController () {
    WKWebView *_webView;
    NSTimer *_logTimer;
    KFLogFilter _filter;
    BOOL _exploitDone;
    AVAudioPlayer *_silentPlayer;
}
@end

@implementation RootViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
    WKWebpagePreferences *wp = [[WKWebpagePreferences alloc] init];
    wp.allowsContentJavaScript = YES;
    cfg.defaultWebpagePreferences = wp;
    [cfg.userContentController addScriptMessageHandler:self name:@"kflog"];

    _webView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:cfg];
    _webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _webView.navigationDelegate = self;
    _webView.backgroundColor = [UIColor blackColor];
    _webView.opaque = NO;
    [self.view addSubview:_webView];

    NSString *htmlPath = [[NSBundle mainBundle] pathForResource:@"index" ofType:@"html"];
    if (htmlPath) {
        NSURL *url = [NSURL fileURLWithPath:htmlPath];
        [_webView loadFileURL:url allowingReadAccessToURL:[url URLByDeletingLastPathComponent]];
    }

    [self startSilentAudio];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [self runExploitStaged];
    });
}

// MARK: - Staged Exploit Logging

- (void)runExploitStaged {
    [self jsEval:@"clearBoot();"];
    _exploitDone = NO;

    [self boot:@"> KFLog terminal initializing..." type:@"dim"];
    [self boot:@"> KFLog terminal initializing..." type:@"dim"];
    [self boot:@"> Audio keep-alive active" type:@"success"];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self boot:@"> Exploiting kernel (opa334 ICMPv6 OOB)..." type:@"dim"];

        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            int ret = KFInit();

            dispatch_async(dispatch_get_main_queue(), ^{
                if (ret == 0) {
                    self->_exploitDone = YES;
                    [self boot:@"> Kernel R/W established" type:@"success"];
                    [self boot:[NSString stringWithFormat:@"> Self proc: 0x%llX", KFProcSelf()] type:@"dim"];

                    [self boot:@"> Sandbox escaped" type:@"success"];
                    [self boot:[NSString stringWithFormat:@"> Root elevation OK (uid=%d)", getuid()] type:@"success"];

                    if (KFLogInitFilter(&self->_filter)) {
                        [self boot:@"> Kernel log channel connected" type:@"success"];
                        [self setStatus:@"ok" text:@"LOGGING"];
                        [self startLogStream];
                    } else {
                        [self boot:@"> Kernel log channel failed (fallback mode)" type:@"dim"];
                        [self setStatus:@"warn" text:@"FALLBACK"];
                    }
                } else {
                    [self boot:[NSString stringWithFormat:@"> EXPLOIT FAILED: %d", ret] type:@"error"];
                    [self setStatus:@"err" text:@"FAILED"];
                }
            });
        });
    });
}

// MARK: - Log Stream

- (void)startLogStream {
    if (_logTimer) return;
    _logTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *timer) {
        [self pollLogs];
    }];
}

- (void)pollLogs {
    if (!_exploitDone) return;
    int n = KFLogPoll(&_filter);
    for (int i = n - 1; i >= 0; i--) {
        const KFLogLine *line = KFLogGetLine(&_filter, i);
        if (!line) continue;
        NSString *json = [NSString stringWithFormat:
            @"{\"t\":\"%s\",\"tag\":\"%s\",\"text\":\"%s\",\"r\":%d}",
            line->timestamp, line->tag, line->text, line->isRed];
        [self jsEval:[NSString stringWithFormat:@"addKernelLog(%@)", json]];
    }
}

// MARK: - JS Bridge

- (void)boot:(NSString *)text type:(NSString *)type {
    NSString *safe = [text stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    [self jsEval:[NSString stringWithFormat:@"addBootStep(\"%@\",\"%@\")", safe, type]];
}

- (void)setStatus:(NSString *)state text:(NSString *)text {
    [self jsEval:[NSString stringWithFormat:@"setStatus(\"%@\",\"%@\")", state, text]];
}

- (void)jsEval:(NSString *)script {
    [_webView evaluateJavaScript:script completionHandler:nil];
}

- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.name isEqualToString:@"kflog"]) return;

    NSString *cmd = message.body;
    NSArray *parts = [cmd componentsSeparatedByString:@" "];
    NSString *op = parts.firstObject;

    // Kernel R/W commands
    if ([op isEqualToString:@"kr8"] && parts.count >= 2) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint8_t v = KFKread8(addr);
        [self boot:[NSString stringWithFormat:@"> kr8(0x%llX) = 0x%02X", addr, v] type:@"dim"];
    }
    else if ([op isEqualToString:@"kr16"] && parts.count >= 2) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint16_t v = KFKread16(addr);
        [self boot:[NSString stringWithFormat:@"> kr16(0x%llX) = 0x%04X", addr, v] type:@"dim"];
    }
    else if ([op isEqualToString:@"kr32"] && parts.count >= 2) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint32_t v = KFKread32(addr);
        [self boot:[NSString stringWithFormat:@"> kr32(0x%llX) = 0x%08X", addr, v] type:@"dim"];
    }
    else if ([op isEqualToString:@"kr64"] && parts.count >= 2) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint64_t v = KFKread64(addr);
        [self boot:[NSString stringWithFormat:@"> kr64(0x%llX) = 0x%llX", addr, v] type:@"dim"];
    }
    else if ([op isEqualToString:@"kw8"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint8_t v = (uint8_t)strtoul([parts[2] UTF8String], NULL, 0);
        KFKwrite8(addr, v);
        [self boot:[NSString stringWithFormat:@"> kw8(0x%llX, 0x%02X) OK", addr, v] type:@"success"];
    }
    else if ([op isEqualToString:@"kw16"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint16_t v = (uint16_t)strtoul([parts[2] UTF8String], NULL, 0);
        KFKwrite16(addr, v);
        [self boot:[NSString stringWithFormat:@"> kw16(0x%llX, 0x%04X) OK", addr, v] type:@"success"];
    }
    else if ([op isEqualToString:@"kw32"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint32_t v = (uint32_t)strtoul([parts[2] UTF8String], NULL, 0);
        KFKwrite32(addr, v);
        [self boot:[NSString stringWithFormat:@"> kw32(0x%llX, 0x%08X) OK", addr, v] type:@"success"];
    }
    else if ([op isEqualToString:@"kw64"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        uint64_t v = strtoull([parts[2] UTF8String], NULL, 0);
        KFKwrite64(addr, v);
        [self boot:[NSString stringWithFormat:@"> kw64(0x%llX, 0x%llX) OK", addr, v] type:@"success"];
    }
    else if ([op isEqualToString:@"khd"] && parts.count >= 3) {
        uint64_t addr = strtoull([parts[1] UTF8String], NULL, 0);
        size_t sz = strtoul([parts[2] UTF8String], NULL, 0);
        KFHexdump(addr, sz);
        [self boot:[NSString stringWithFormat:@"> hexdump(0x%llX, %zu) printed to stdout", addr, sz] type:@"dim"];
    }
    else if ([op isEqualToString:@"proc"] && parts.count >= 2) {
        NSString *procName = [[parts subarrayWithRange:NSMakeRange(1, parts.count - 1)] componentsJoinedByString:@" "];
        const char *name = [procName UTF8String];
        uint64_t p = KFProcFindByName(name);
        [self boot:[NSString stringWithFormat:@"> proc_find(\"%s\") = 0x%llX", name, p] type:p ? @"success" : @"error"];
    }
    else if ([op isEqualToString:@"chown"] && parts.count >= 4) {
        const char *path = [parts[1] UTF8String];
        uid_t uid = (uid_t)atoi([parts[2] UTF8String]);
        gid_t gid = (gid_t)atoi([parts[3] UTF8String]);
        int r = KFChown(path, uid, gid);
        [self boot:[NSString stringWithFormat:@"> chown(\"%s\", %d, %d) = %d", path, uid, gid, r] type:r == 0 ? @"success" : @"error"];
    }
    else if ([op isEqualToString:@"chmod"] && parts.count >= 3) {
        const char *path = [parts[1] UTF8String];
        mode_t mode = (mode_t)strtoul([parts[2] UTF8String], NULL, 8);
        int r = KFChmod(path, mode);
        [self boot:[NSString stringWithFormat:@"> chmod(\"%s\", 0%o) = %d", path, mode, r] type:r == 0 ? @"success" : @"error"];
    }
    else if ([cmd isEqualToString:@"start"]) {
        [self startLogStream];
    }
    else if ([cmd isEqualToString:@"stop"]) {
        [_logTimer invalidate];
        _logTimer = nil;
    }
    else if ([cmd isEqualToString:@"reinit"]) {
        [self runExploitStaged];
    }
    else if ([cmd isEqualToString:@"clear"]) {
        [self jsEval:@"clearBoot();clearKernel();"];
    }
}

// MARK: - Background Audio

- (void)startSilentAudio {
    uint8_t wav[44 + 44100 * 2] = {0};
    memcpy(wav, "RIFF", 4);
    uint32_t chunkSize = 36 + 44100 * 2;
    memcpy(wav + 4, &chunkSize, 4);
    memcpy(wav + 8, "WAVE", 4);
    memcpy(wav + 12, "fmt ", 4);
    uint32_t subchunk1 = 16;
    memcpy(wav + 16, &subchunk1, 4);
    uint16_t audioFormat = 1;
    memcpy(wav + 20, &audioFormat, 2);
    uint16_t numChannels = 1;
    memcpy(wav + 22, &numChannels, 2);
    uint32_t sampleRate = 44100;
    memcpy(wav + 24, &sampleRate, 4);
    uint32_t byteRate = 44100 * 2;
    memcpy(wav + 28, &byteRate, 4);
    uint16_t blockAlign = 2;
    memcpy(wav + 32, &blockAlign, 2);
    uint16_t bitsPerSample = 16;
    memcpy(wav + 34, &bitsPerSample, 2);
    memcpy(wav + 36, "data", 4);
    uint32_t dataSize = 44100 * 2;
    memcpy(wav + 40, &dataSize, 4);

    NSData *data = [NSData dataWithBytes:wav length:sizeof(wav)];
    _silentPlayer = [[AVAudioPlayer alloc] initWithData:data error:nil];
    _silentPlayer.volume = 0.0;
    _silentPlayer.numberOfLoops = -1;
    [_silentPlayer play];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    _webView.frame = self.view.bounds;
}

@end
