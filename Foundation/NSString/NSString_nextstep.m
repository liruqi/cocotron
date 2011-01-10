/* Copyright (c) 2006-2007 Christopher J. W. Lloyd

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */

// Original - Christopher Lloyd <cjwl@objc.net>
#import <Foundation/NSString_nextstep.h>
#import <Foundation/NSRaise.h>
#import <Foundation/NSRaiseException.h>

static const unichar NEXTSTEPToUnicode[256]={
 0x0000,0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,
 0x0008,0x0009,0x000a,0x000b,0x000c,0x000d,0x000e,0x000f,
 0x0010,0x0011,0x0012,0x0013,0x0014,0x0015,0x0016,0x0017,
 0x0018,0x0019,0x001a,0x001b,0x001c,0x001d,0x001e,0x001f,
 0x0020,0x0021,0x0022,0x0023,0x0024,0x0025,0x0026,0x0027,
 0x0028,0x0029,0x002a,0x002b,0x002c,0x002d,0x002e,0x002f,
 0x0030,0x0031,0x0032,0x0033,0x0034,0x0035,0x0036,0x0037,
 0x0038,0x0039,0x003a,0x003b,0x003c,0x003d,0x003e,0x003f,
 0x0040,0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,
 0x0048,0x0049,0x004a,0x004b,0x004c,0x004d,0x004e,0x004f,
 0x0050,0x0051,0x0052,0x0053,0x0054,0x0055,0x0056,0x0057,
 0x0058,0x0059,0x005a,0x005b,0x005c,0x005d,0x005e,0x005f,
 0x0060,0x0061,0x0062,0x0063,0x0064,0x0065,0x0066,0x0067,
 0x0068,0x0069,0x006a,0x006b,0x006c,0x006d,0x006e,0x006f,
 0x0070,0x0071,0x0072,0x0073,0x0074,0x0075,0x0076,0x0077,
 0x0078,0x0079,0x007a,0x007b,0x007c,0x007d,0x007e,0x007f,

 0x00a0,0x00c0,0x00c1,0x00c2,0x00c3,0x00c4,0x00c5,0x00c7,
 0x00c8,0x00c9,0x00ca,0x00cb,0x00cc,0x00cd,0x00ce,0x00cf,
 0x00d0,0x00d1,0x00d2,0x00d3,0x00d4,0x00d5,0x00d6,0x00d9,
 0x00da,0x00db,0x00dc,0x00dd,0x00de,0x00b5,0x00d7,0x00f7,
 0x00a9,0x00a1,0x00a2,0x00a3,0x2044,0x00a5,0x0192,0x00a7,
 0x00a4,0x2019,0x201c,0x00ab,0x2039,0x203a,0xfb01,0xfb02,
 0x00ae,0x2013,0x2020,0x2021,0x00b7,0x00a6,0x00b6,0x2022,
 0x201a,0x201e,0x201d,0x00bb,0x2026,0x2030,0x00ac,0x00bf,
 0x00b9,0x02cb,0x00b4,0x02c6,0x02dc,0x00af,0x02d8,0x02d9,
 0x00a8,0x00b2,0x02da,0x00b8,0x00b3,0x02dd,0x02db,0x02c7,
 0x2014,0x00b1,0x00bc,0x00bd,0x00be,0x00e0,0x00e1,0x00e2,
 0x00e3,0x00e4,0x00e5,0x00e7,0x00e8,0x00e9,0x00ea,0x00eb,
 0x00ec,0x00c6,0x00ed,0x00aa,0x00ee,0x00ef,0x00f0,0x00f1,
 0x0141,0x00d8,0x0152,0x00ba,0x00f2,0x00f3,0x00f4,0x00f5,
 0x00f6,0x00e6,0x00f9,0x00fa,0x00fb,0x0131,0x00fc,0x00fd,
 0x0142,0x00f8,0x0153,0x00df,0x00fe,0x00ff,0xfffd,0xfffd
};

unichar *NSNEXTSTEPToUnicode(const char *cString,NSUInteger length,
  NSUInteger *resultLength,NSZone *zone) {
   unichar *characters=NSZoneMalloc(zone,sizeof(unichar)*length);
   int      i;

   for(i=0;i<length;i++)
    characters[i]=NEXTSTEPToUnicode[((unsigned char *)cString)[i]];

   *resultLength=i;
   return characters;
}

char *NSUnicodeToNEXTSTEP(const unichar *characters,NSUInteger length,
  BOOL lossy,NSUInteger *resultLength,NSZone *zone, BOOL zeroTerminate) {
    char *nextstep=NSZoneMalloc(zone,sizeof(char)*(length + (zeroTerminate == YES ? 1 : 0)));
    int   i,j;
    
    for(i=0;i<length;i++){
        
        if(characters[i]<128)
            nextstep[i]=characters[i];
        else{
            
            for(j=128;j<256;j++)
                if(characters[i]==NEXTSTEPToUnicode[j])
                    break;
            
            if(j<256)
                nextstep[i]=j;
            else if(lossy)
                nextstep[i]='\0';
            else {
                NSZoneFree(zone,nextstep);
                return NULL;
            }
        }
    }
    if(zeroTerminate == YES)
    {
        nextstep[i++]='\0';
    }
    *resultLength=i;
    
    return nextstep;
}

NSUInteger NSGetNEXTSTEPCStringWithMaxLength(const unichar *characters,NSUInteger length,NSUInteger *location,char *cString,NSUInteger maxLength,BOOL lossy) {
   NSUInteger i,result=0;

    if(length+1 > maxLength) {
        cString[0]='\0';
        return NSNotFound;
    }
   for(i=0;i<length && result<=maxLength;i++){
    unichar code=characters[i];

    if(code<128)
     cString[result++]=code;
    else {
     int j;

     for(j=128;j<256;j++)
      if(code==NEXTSTEPToUnicode[j])
       break;

     if(j<256)
      cString[result++]=j;
     else if(lossy)
      cString[result++]='\0';
     else {
      return NSNotFound;
     }
    }
   }

   cString[result]='\0';

   *location=i;

   return result;
}

@implementation NSString_nextstep

NSString *NSNEXTSTEPStringNewWithBytes(NSZone *zone,
 const char *bytes,NSUInteger length) {
   NSString_nextstep *string;
   NSInteger               i;

   string=NSAllocateObject([NSString_nextstep class],length*sizeof(char),zone);

   string->_length=length;
   for(i=0;i<length;i++)
    string->_bytes[i]=bytes[i];
   string->_bytes[i]='\0';

   return string;
}

-(NSUInteger)length {
   return _length;
}

-(unichar)characterAtIndex:(NSUInteger)location {
   if(location>=_length){
    NSRaiseException(NSRangeException,self,_cmd,@"index %d beyond length %d",
     location,[self length]);
   }

   return NEXTSTEPToUnicode[((unsigned char *)_bytes)[location]];
}

-(void)getCharacters:(unichar *)buffer {
   int i;

   for(i=0;i<_length;i++)
    buffer[i]=NEXTSTEPToUnicode[((unsigned char *)_bytes)[i]];
}

-(void)getCharacters:(unichar *)buffer range:(NSRange)range {
   NSInteger i,loc=range.location,len=range.length;

   if(NSMaxRange(range)>_length){
    NSRaiseException(NSRangeException,self,_cmd,@"range %@ beyond length %d",
     NSStringFromRange(range),[self length]);
   }

   for(i=0;i<len;i++)
    buffer[i]=NEXTSTEPToUnicode[((unsigned char *)_bytes)[loc+i]];
}

@end
