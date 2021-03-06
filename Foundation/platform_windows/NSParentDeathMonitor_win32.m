/* Copyright (c) 2006-2007 Christopher J. W. Lloyd

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */

// Original - Christopher Lloyd <cjwl@objc.net>
#import <Foundation/NSParentDeathMonitor_win32.h>
#import <Foundation/NSHandleMonitor_win32.h>
#import <Foundation/NSUserDefaults.h>
#import <Foundation/NSString.h>

@implementation NSParentDeathMonitor_win32

-init {
   _parentHandle=NULL;
   _monitor=nil;
   return self;
}

-(void)handleMonitorIndicatesSignaled:(NSHandleMonitor_win32 *)monitor {
   DWORD exitCode;

   GetExitCodeProcess(_parentHandle,&exitCode);

   if(exitCode!=STILL_ACTIVE)
    exit(0);
}

-(NSHandleMonitor_win32 *)handleMonitor {
   if(_monitor==nil){
    int processId=[[NSUserDefaults standardUserDefaults] integerForKey:@"ParentProcessId"];

    if(processId==0 || (_parentHandle=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_INFORMATION,NO,processId))==NULL){
     [self dealloc];
     return nil;
    }

    _monitor=[[NSHandleMonitor_win32 allocWithZone:NULL] initWithHandle:_parentHandle];
    [_monitor setDelegate:self];
   }
   return _monitor;
}

@end
