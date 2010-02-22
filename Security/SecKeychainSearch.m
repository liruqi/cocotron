//
//  SecKeychainSearch.m
//  Security
//
//  Created by Christopher Lloyd on 2/12/10.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#import "SecKeychainSearch.h"
#import "SecKeychain.h"

@implementation SecKeychainSearch


-initWithKeychainOrArray:(CFTypeRef)keychainOrArray itemClass:(SecItemClass)itemClass attributeList:(const SecKeychainAttributeList *)attributeList {
NSLog(@"%s %d",__FUNCTION__,__LINE__);
   if(keychainOrArray==NULL)
    keychainOrArray=[SecKeychain defaultUserKeychain];
NSLog(@"%s %d",__FUNCTION__,__LINE__);
    
   if(![keychainOrArray isKindOfClass:[NSArray class]])
    keychainOrArray=[NSArray arrayWithObject:keychainOrArray];
NSLog(@"%s %d",__FUNCTION__,__LINE__);
   
   _array=CFRetain(keychainOrArray);
NSLog(@"%s %d",__FUNCTION__,__LINE__);
   _itemClass=itemClass;
NSLog(@"%s %d",__FUNCTION__,__LINE__);
   _attributeList=SecCopyAttributeList(attributeList);
NSLog(@"%s %d",__FUNCTION__,__LINE__);

   _arrayCursor=0;
   _keychainCursor=nil;
NSLog(@"%s %d",__FUNCTION__,__LINE__);
   return self;
}

-(void)dealloc {
   CFRelease(_array);
   SecFreeAttributeList(_attributeList);   
   [_keychainCursor release];
   [super dealloc];
}

-(SecKeychainItemRef)copyNextItem {
   NSCLog("%s %d",__FUNCTION__,__LINE__);
  
  while(_arrayCursor<CFArrayGetCount(_array)){
   SecKeychainRef keychain=CFArrayGetValueAtIndex(_array,_arrayCursor);
   NSCLog("%s %d",__FUNCTION__,__LINE__);
   
   if(_keychainCursor==nil)
    _keychainCursor=[keychain createCursorForItemClass:_itemClass];
   NSCLog("%s %d",__FUNCTION__,__LINE__);
    
   SecKeychainItemRef check=nil;
    
   if(_keychainCursor!=nil)
    check=[keychain createNextItemAtCursor:_keychainCursor attributeList:_attributeList];
    
   if(check!=nil)
    return check;
    
   _arrayCursor++;
   [_keychainCursor release];
   _keychainCursor=nil;
  }
   NSCLog("%s %d",__FUNCTION__,__LINE__);
   return nil;
}

@end
