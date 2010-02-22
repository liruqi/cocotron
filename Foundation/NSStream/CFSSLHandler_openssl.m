#import "CFSSLHandler_openssl.h"
#import <Foundation/NSSocket.h>
#import <Foundation/NSData.h>
#import <pthread.h>

#ifdef OPENSSL_ENABLED
#import <openssl/err.h>

@implementation CFSSLHandler(openssl)

+allocWithZone:(NSZone *)zone {
   return NSAllocateObject([CFSSLHandler_openssl class],0,zone);
}

@end

#endif

@implementation CFSSLHandler_openssl

#ifdef OPENSSL_ENABLED


static pthread_mutex_t  initLock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t *lockTable;

static void locking_function(int mode,int idx,const char *file,int line){
   if(mode&CRYPTO_LOCK){
    pthread_mutex_lock(&(lockTable[idx]));
   }
   else {
    pthread_mutex_unlock(&(lockTable[idx]));
   }
}

#if 0
// We don't need this on Windows but it should be implemented generally
static threadid_func(CRYPTO_THREADID *id){
}
#endif

+(void)initialize {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   pthread_mutex_lock(&initLock);
   SSL_library_init();
   SSL_load_error_strings();
   
   int i,numberOfLocks=CRYPTO_num_locks();
   lockTable=OPENSSL_malloc(numberOfLocks*sizeof(pthread_mutex_t));
   for(i=0;i<numberOfLocks;i++)
    pthread_mutex_init(&(lockTable[i]),NULL);
    
   CRYPTO_set_locking_callback(locking_function);
   pthread_mutex_unlock(&initLock);
}

-initWithProperties:(CFDictionaryRef )properties {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   _properties=CFRetain(properties);
   
   CFStringRef level=CFDictionaryGetValue(_properties,kCFStreamSSLLevel);
   
   if(level==NULL)
     _method=SSLv23_client_method();
   else if(CFStringCompare(level,kCFStreamSocketSecurityLevelSSLv3,0)==kCFCompareEqualTo)
     _method=SSLv3_client_method();
   else if(CFStringCompare(level,kCFStreamSocketSecurityLevelSSLv2,0)==kCFCompareEqualTo)
     _method=SSLv2_client_method();
   else if(CFStringCompare(level,kCFStreamSocketSecurityLevelTLSv1,0)==kCFCompareEqualTo)
     _method=TLSv1_client_method();
   else
     _method=SSLv23_client_method();
   
   CFNumberRef validatesCertChain=CFDictionaryGetValue(_properties,kCFStreamSSLValidatesCertificateChain);
   
   if(validatesCertChain!=NULL){
   }
NSCLog("%s %d",__FUNCTION__,__LINE__);
   
   _context=SSL_CTX_new(_method);
   _connection=SSL_new(_context);
   _incoming=BIO_new(BIO_s_mem());
   _outgoing=BIO_new(BIO_s_mem());

#if 0
   BIO_set_mem_eof_return(_incoming,0);
   BIO_set_mem_eof_return(_outgoing,0);
#endif

   SSL_set_bio(_connection,_incoming,_outgoing);
   
   SSL_set_connect_state(_connection);
   
   /* The SSL_read doc.s say that when SSL_read returns Wants More you should use the same arguments
      the next call. It is a little ambiguous whether the same exact pointer should be used, so we don't
      chance it and just maintain a 1k buffer for this purpose. */
      
   _stableBufferCapacity=1024;
   _stableBuffer=NSZoneMalloc(NULL,_stableBufferCapacity);
   _readBuffer=[[NSMutableData alloc] init];
   
NSCLog("%s %d",__FUNCTION__,__LINE__);
   return self;
}

-(void)dealloc {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   CFRelease(_properties);
   SSL_free(_connection);
   NSZoneFree(NULL,_stableBuffer);
   [super dealloc];
}

-(void)close {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   SSL_shutdown(_connection);
}

-(BOOL)isHandshaking {
NSCLog("%s %d state=%s",__FUNCTION__,__LINE__,SSL_state_string_long(_connection));
   return SSL_in_init(_connection)?YES:NO;
}

-(NSInteger)writePlaintext:(const uint8_t *)buffer maxLength:(NSUInteger)length {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   int result=SSL_write(_connection,buffer,length);
   
   if(result<0){
NSCLog("%s %d %d",__FUNCTION__,__LINE__,result);
    int error=SSL_get_error(_connection,result);

    switch(error) {
     case SSL_ERROR_ZERO_RETURN:
      NSCLog("SSL_write(%d) returned SSL_ERROR_ZERO_RETURN",length);
      break;
      
     case SSL_ERROR_NONE: 
      NSCLog("SSL_write(%d) returned SSL_ERROR_NONE",length);
      break;
      
     case SSL_ERROR_WANT_READ:
      NSCLog("SSL_write(%d) returned SSL_ERROR_WANT_READ",length);
      break;

     default :;
      char errorCString[256];

       while (error != 0){
        ERR_error_string_n(error, errorCString, sizeof(errorCString));

        NSCLog("SSL_write(%d) returned error %d - %s",length,error,errorCString);

         error = ERR_get_error();
       }
       break;
    }
   }
   
   return result;
}

-(NSInteger)writeBytesAvailable {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   return BIO_ctrl_pending(_outgoing);
}

-(BOOL)wantsMoreIncoming {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   return SSL_want_read(_connection);
}

-(NSInteger)readEncrypted:(uint8_t *)buffer maxLength:(NSUInteger)length {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   int check=BIO_read(_outgoing,buffer,length);

   if(check<=0){
    // This shouldn't happen unless we read when not ready
    NSCLog("BIO_read(_outgoing,buffer,%d) returned %d ",length,check);
   }
   
   return check;
}

-(NSInteger)writeEncrypted:(const uint8_t *)buffer maxLength:(NSUInteger)length {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   size_t check=BIO_write(_incoming,buffer,length);
   
   if(check<=0){
    // This shouldn't happen unless we are out of memory?
    NSCLog("BIO_write(_incoming,buffer,%d) returned %d ",length,check);
   }
   
   return check;
}

-(NSInteger)_readPostSSL:(uint8_t *)buffer maxLength:(NSUInteger)length {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   int check=SSL_read(_connection,buffer,length);
   
   if(check<=0){
    int error = SSL_get_error(_connection, check);

    switch(error){
     case SSL_ERROR_ZERO_RETURN:
      NSCLog("SSL_read(%d) returned SSL_ERROR_ZERO_RETURN",length);
      return 0;
      
     case SSL_ERROR_NONE: 
      NSCLog("SSL_read(%d) returned SSL_ERROR_NONE",length);
      return 0;
      
     case SSL_ERROR_WANT_READ:
      NSCLog("SSL_read(%d) returned SSL_ERROR_WANT_READ",length);
      return 0;

     default :;
      char errorCString[256];

       while (error != 0){
        ERR_error_string_n(error, errorCString, sizeof(errorCString));

        NSCLog("SSL_read(%d) returned error %d - %s",length,error,errorCString);

        error = ERR_get_error();
       }
       break;
    }
   }
   
   return check;
}

-(NSInteger)readBytesAvailable {
/* SSL_pending() is useless here because it doesn't actually process anything, it will return 0 when there are bytes
   available post-processing.
 */
NSCLog("%s %d",__FUNCTION__,__LINE__);
   if([_readBuffer length]>0)
    return [_readBuffer length];
   else {
    NSInteger result=[self _readPostSSL:_stableBuffer maxLength:_stableBufferCapacity];
   
    if(result<=0)
     return 0;

    [_readBuffer appendBytes:_stableBuffer length:result];
    return result;
   }
}

-(NSInteger)readPlaintext:(uint8_t *)buffer maxLength:(NSUInteger)length {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   if([_readBuffer length]>0){
    NSInteger qty=MIN([_readBuffer length],length);
    
    [_readBuffer getBytes:buffer length:qty];
    [_readBuffer replaceBytesInRange:NSMakeRange(0,qty) withBytes:NULL length:0];
    return qty;
   }
   
   return [self _readPostSSL:buffer maxLength:length];
}

-(NSInteger)transferOneBufferFromSSLToSocket:(NSSocket *)socket {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   NSInteger available=[self readEncrypted:_stableBuffer maxLength:_stableBufferCapacity];
   
   if(available<=0)
    return available;
   else {
    NSInteger check=[socket write:_stableBuffer maxLength:available];
    
    if(check!=available)
     NSCLog("FAILURE socket write:%d=%d",available,check);
   
    return check;
   }
}

-(NSInteger)transferOneBufferFromSocketToSSL:(NSSocket *)socket {
NSCLog("%s %d",__FUNCTION__,__LINE__);
   NSInteger result=[socket read:_stableBuffer maxLength:_stableBufferCapacity];
NSCLog("%s %d result=%d",__FUNCTION__,__LINE__,result);
     
   if(result<=0)
    return result;
     
   NSInteger check;
     
   if((check=[self writeEncrypted:_stableBuffer maxLength:result])!=result){
    NSCLog("[sslHandler writeEncrypted:socketBuffer maxLength:%d] failed %d",result,check);
   }
      
   return result;
}

-(void)runHandshakeIfNeeded:(NSSocket *)socket {
   while([self isHandshaking]){
     NSCLog("SSL_do_handshake");
     
    int check=SSL_do_handshake(_connection);
    
    if(check==1){
     NSCLog("successful handshake");
     break;
    }
    
    if(check==0){
     NSCLog("failed handshake");
     break;
    }
    
     if([self writeBytesAvailable]){
      if((check=[self transferOneBufferFromSSLToSocket:socket])<=0)
        break;
     }
     
     if([self wantsMoreIncoming]){
      if((check=[self transferOneBufferFromSocketToSSL:socket])<=0)
       break;
     }
   }
}

-(void)runWithSocket:(NSSocket *)socket {
NSCLog("%s %d",__FUNCTION__,__LINE__);
    while([self writeBytesAvailable] || [self wantsMoreIncoming]){
     NSInteger check;

NSCLog("%s %d isHandshaking=%s",__FUNCTION__,__LINE__,[self isHandshaking]?"YES":"NO");
     
     if([self writeBytesAvailable]){
      if((check=[self transferOneBufferFromSSLToSocket:socket])<=0)
        break;
     }
NSCLog("%s %d isHandshaking=%s",__FUNCTION__,__LINE__,[self isHandshaking]?"YES":"NO");
    
     if([self wantsMoreIncoming]){
      if((check=[self transferOneBufferFromSocketToSSL:socket])<=0)
       break;
     }
    }
NSCLog("%s %d",__FUNCTION__,__LINE__);
}

#endif

@end
