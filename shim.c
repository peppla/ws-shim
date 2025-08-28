/*
 * shim.c - A dynamic library shim to capture TLS keys for Wireshark
 *
 * This library intercepts SSL_CTX_new and SSL_CTX_new_ex calls to install a
 * keylog callback that writes TLS session keys to a file specified by the
 * SSLKEYLOGFILE environment variable. This allows tools like Wireshark to
 * decrypt TLS traffic for analysis.
 *
 * Usage:
 *   1. Compile this file into a shared library:
 *        gcc -shared -fPIC -o shim.so shim.c -ldl -lpthread -lssl
 *   2. Set the SSLKEYLOGFILE environment variable to the desired log file path:
 *        export SSLKEYLOGFILE=/path/to/your/keylogfile.log
 *   3. Preload the shim library when running your application:
 *        LD_PRELOAD=/path/to/shim.so your_application
 *
 * Note: This code is intended for debugging and analysis purposes only.
 *       It should not be used in production environments due to potential
 *       security and performance implications.
 * 
 * shim.c © 2025 by Pep Pla and "friends" is licensed under Creative Commons 
 * Attribution-ShareAlike 4.0 International. To view a copy of this license,
 * visit https://creativecommons.org/licenses/by-sa/4.0/
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>

static FILE *keylog_fp = NULL; /* pointer to the keylog file */

/* multithreaded safety */
static pthread_once_t keylog_once = PTHREAD_ONCE_INIT; /* to ensure that keylog_init_once is called only once */ 
static pthread_mutex_t keylog_mutex = PTHREAD_MUTEX_INITIALIZER; /* to prevent concurrent writes to the keylog file */

/* keylog initialization */
static void keylog_init_once(void) {
    const char *path = getenv("SSLKEYLOGFILE");

    // if path is not set or empty, do nothing
    if (!path || !*path) return;

    // open the file in append mode, create it if it doesn't exist, with permissions 0600
    int fd = open(path, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0600);
    
    // if we can't open the file, do nothing
    if (fd < 0) return;

    // convert the file descriptor to a FILE pointer and set it to line buffered
    FILE *fp = fdopen(fd, "a");

    // again, if we can't convert it, close the fd and do nothing
    if (!fp) { close(fd); return; }

    // we set line buffering, this could be a problem if we're going to write a lot of keys very fast
    // but this code is meant for debugging, NOT FOR PRODUCTION USE
    // Did you read that? NOT FOR PRODUCTION USE!
    setvbuf(fp, NULL, _IOLBF, 0);      /* line buffered */
    keylog_fp = fp;
}

/* cleanup function to close the keylog file at exit */
static void keylog_cleanup(void) {

    // not sure if this is needed at all
    // we make sure that keylog_init_once has been called at least once
    pthread_once(&keylog_once, keylog_init_once);

    // if the file is open, close it, but do it safely without interrupting any write in progress
    pthread_mutex_lock(&keylog_mutex);
    if (keylog_fp) { fclose(keylog_fp); keylog_fp = NULL; }
    pthread_mutex_unlock(&keylog_mutex);
}

/* As we need to call the real SSL functions, we need to resolve their symbols using dlsym
   This is done to avoid ABI skew. And what is ABI skew? It is a mismatch between the
   library we use to compile the program and the library we use to run the program.

   It is a bit complex... and the explanation is:
   (a) Beyond the scope of this comment
   (b) I don't fully understand it myself
   Feel free to chose the option(s) that you like the most.
*/

// First we define these types that say something like:
// "p_SSL_CTX_new is a pointer to a function that takes a SSL_METHOD and returns a SSL_CTX"
// (and similar for the other functions we need to intercept)
typedef SSL_CTX *(*p_SSL_CTX_new)(const SSL_METHOD *);
typedef SSL_CTX *(*p_SSL_CTX_new_ex)(OSSL_LIB_CTX *, const char *, const SSL_METHOD *);
typedef void (*p_SSL_CTX_set_keylog_callback)(SSL_CTX *, SSL_CTX_keylog_cb_func);
typedef SSL_CTX_keylog_cb_func (*p_SSL_CTX_get_keylog_callback)(const SSL_CTX *);

// Now we define some static variables to hold the real function pointers
static p_SSL_CTX_new real_SSL_CTX_new;
static p_SSL_CTX_new_ex real_SSL_CTX_new_ex;
static p_SSL_CTX_set_keylog_callback real_set_klog;
static p_SSL_CTX_get_keylog_callback real_get_klog;

// Real men only resolve symbols once
static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;
// Fun fact: once is a false friend in Spanish. It means eleven, not once.

// Function to resolve the real symbols using dlsym
// What does dlsym do? it looks up the address of a symbol (function or variable) in a
// shared library
// But which shared library? In theory, we call dlsym with a handle to the specific library
// but this means that we need to know which library we are using and open it using dlopen.
// Instead of doing this, we can use a special handler that tells dlsym to search for the
// symbol using the default search order. This handler is RTLD_DEFAULT.
// But the problem with RTLD_DEFAULT is that we will preload the shim library with the
// symbols we want to intercept... and that sound pretty much like an infinite loop.
// Luckily, there is another special handler, RTLD_NEXT, that tells dlsym to search
// for the symbol in the next library after the current one.

// Fun fact: 1 Infinite Loop used to be the address of the Apple headquarters in Cupertino

static void resolve_syms(void) {
    real_SSL_CTX_new    = (p_SSL_CTX_new)    dlsym(RTLD_NEXT, "SSL_CTX_new");
    real_SSL_CTX_new_ex = (p_SSL_CTX_new_ex) dlsym(RTLD_NEXT, "SSL_CTX_new_ex"); /* may be NULL on <3.0 */
    real_set_klog = (p_SSL_CTX_set_keylog_callback)dlsym(RTLD_NEXT, "SSL_CTX_set_keylog_callback");
    real_get_klog = (p_SSL_CTX_get_keylog_callback)dlsym(RTLD_NEXT, "SSL_CTX_get_keylog_callback");
}

// Now a bit of explanation about SSL_CTX_new and SSL_CTX_new_ex
// These functions create a ssl context (SSL_CTX) that holds configuration
// and state information for SSL/TLS connections.
// SSL_CTX_new is the older function available, while SSL_CTX_new_ex is newer (3.0+)
// I guess calling it SSL_CTX__new_new would have been too much

// And SSL_CTX_set_keylog_callback is a function that sets a callback function
// that will be called whenever a new TLS session key is generated.
// While SSL_CTX_get_keylog_callback returns the currently set callback function.
// We will use get to check if there is already a callback installed and not
// overwrite it if there is one. We are so polite.

/* The callback function itself */
// Once we install the callback, this function will be called every time a new TLS session
// key is generated.
static void keylog_cb(const SSL *ssl, const char *line) {

    (void)ssl; // Avoid unused parameter warning

    if (!line || !*line) return; // if line is NULL or empty, do nothing

    // We make sure that keylog_init_once has been called at least once
    pthread_once(&keylog_once, keylog_init_once);

    // if the file is not open, do nothing
    if (!keylog_fp) return;

    // We write and flush the line to the file, but do it safely without interrupting any write in progress
    pthread_mutex_lock(&keylog_mutex);
    fputs(line, keylog_fp);
    fputc('\n', keylog_fp);
    fflush(keylog_fp);
    pthread_mutex_unlock(&keylog_mutex);
}

/* We have a callback function, but it needs to be installed */
static inline void maybe_install_cb(SSL_CTX *ctx) {

    // If we don't have a ssl context, we can't do anything
    if (!ctx) return;

    // We make sure the symbols are resolved, but only once
    pthread_once(&resolve_once, resolve_syms);

    // If we have the real functions, and there is no callback installed yet, install ours
    // We only install the callback if there is no callback installed yet
    if (real_get_klog && real_set_klog && !real_get_klog(ctx)) {
      // install our callback
      real_set_klog(ctx, keylog_cb);
    }

    // This code will be executed only once (or twice... but who cares)
    // once is by default initialized to 0 and not 0 is 1 or true
    // but we are post incrementing it, so the first time it is not 0 (AKA true)
    // but the following times it is not (1 or greater than 1),(AKA false)
    // atexit registers a function to be called at program termination
    static int once;
    if (!once++) atexit(keylog_cleanup);
}

/* This function, as we explained before is the ssl context creator.*/
// We intercept this function to install our callback, we don't do anything else
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth) {

  // We make sure the symbols are resolved, but only once
  pthread_once(&resolve_once, resolve_syms);

  // If we don't have the real function, we can't do anything
  if (!real_SSL_CTX_new) return NULL;
  
  // Call the real function to create the ssl context
  SSL_CTX *ctx = real_SSL_CTX_new(meth);

  // install our callback if needed
  maybe_install_cb(ctx);

  // We return the context as the original function does
  // Keep moving, nothing to see here!
  return ctx;
}

SSL_CTX *SSL_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq, const SSL_METHOD *meth) {

  // I guess you know what this does by now
  pthread_once(&resolve_once, resolve_syms);

  // We're so polite that if we don't have the real function, we just fallback to
  // SSL_CTX_new
  if (real_SSL_CTX_new_ex) {
    // If I bothered to count the lines, why don't you bother to read my comments?
    // You just have to scroll up 20 lines!
    SSL_CTX *ctx = real_SSL_CTX_new_ex(libctx, propq, meth);

    // Guess what? The comment you are looking for is also 20 lines up!
    maybe_install_cb(ctx);

    // (Almost) nothing to see here, move along!
    return ctx;
  }

  // Read the comment 14 lines up
  return SSL_CTX_new(meth);  /* fallback for OpenSSL <3.0 */
}
