#import <AppKit/NSColor.h>
#import <CoreGraphics/CoreGraphics.h>

@interface NSColor(NSAppKitPrivate)
-(CGColorRef)createCGColorRef;
@end
