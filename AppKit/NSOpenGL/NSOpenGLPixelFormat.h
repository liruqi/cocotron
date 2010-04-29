/* Copyright (c) 2006-2007 Christopher J. W. Lloyd

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */

#import <Foundation/NSObject.h>

typedef enum {
   NSOpenGLPFADoubleBuffer=5,
   NSOpenGLPFAStereo=6,
   NSOpenGLPFAAuxBuffers=7,
   NSOpenGLPFAColorSize=8,
   NSOpenGLPFAAlphaSize=11,
   NSOpenGLPFADepthSize=12,
   NSOpenGLPFAStencilSize=13,
   NSOpenGLPFAAccumSize=14,
   NSOpenGLPFAOffScreen=53,
   NSOpenGLPFAFullScreen=54,
   NSOpenGLPFARendererID=70,
   NSOpenGLPFAAccelerated=73,
   NSOpenGLPFAWindow=80,
   NSOpenGLPFAScreenMask=84,
} NSOpenGLPixelFormatAttribute;

@interface NSOpenGLPixelFormat : NSObject {
   NSOpenGLPixelFormatAttribute *_attributes;
}

-initWithAttributes:(NSOpenGLPixelFormatAttribute *)attributes;

-(void *)CGLPixelFormatObj;
-(int)numberOfVirtualScreens;

-(void)getValues:(long *)values forAttribute:(NSOpenGLPixelFormatAttribute)attribute forVirtualScreen:(int)screen;

@end
