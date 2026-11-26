#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// The shared login uses a legacy macOS keychain item, including its ACL.
// Keep credential bytes in-process and use the same service and account as agy.
static const char service[] = "gemini";
static const char account[] = "antigravity";

OSStatus agy_macos_keychain_read(UInt32 *length, void **bytes) {
    return SecKeychainFindGenericPassword(NULL, sizeof(service) - 1, service,
                                          sizeof(account) - 1, account,
                                          length, bytes, NULL);
}

void agy_macos_keychain_free(void *bytes) {
    SecKeychainItemFreeContent(NULL, bytes);
}

static OSStatus trusted_switch_apps(const char *peer, CFArrayRef *apps) {
    SecTrustedApplicationRef current = NULL;
    SecTrustedApplicationRef companion = NULL;
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &current);
    if (status == errSecSuccess && peer != NULL) {
        status = SecTrustedApplicationCreateFromPath(peer, &companion);
    }
    if (status == errSecSuccess) {
        const void *values[] = {current, companion};
        *apps = CFArrayCreate(NULL, values, companion == NULL ? 1 : 2, &kCFTypeArrayCallBacks);
        if (*apps == NULL) status = errSecAllocate;
    }
    if (companion != NULL) CFRelease(companion);
    if (current != NULL) CFRelease(current);
    return status;
}

static OSStatus restrict_open_access(SecKeychainItemRef item, CFArrayRef trusted) {
    SecAccessRef access = NULL;
    OSStatus status = SecKeychainItemCopyAccess(item, &access);
    if (status != errSecSuccess) return status;
    CFArrayRef entries = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
    if (entries == NULL) {
        CFRelease(access);
        return errSecInvalidItemRef;
    }
    bool changed = false;
    for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount(entries); i++) {
        SecACLRef entry = (SecACLRef)CFArrayGetValueAtIndex(entries, i);
        CFArrayRef apps = NULL;
        CFStringRef label = NULL;
        SecKeychainPromptSelector prompt = 0;
        status = SecACLCopyContents(entry, &apps, &label, &prompt);
        // A NULL list grants every application access. Preserve existing
        // restricted entries, including permissions previously approved by the user.
        if (status == errSecSuccess && apps == NULL) {
            status = SecACLSetContents(entry, trusted, label == NULL ? CFSTR("Antigravity") : label, prompt);
            changed = true;
        }
        if (apps != NULL) CFRelease(apps);
        if (label != NULL) CFRelease(label);
    }
    if (status == errSecSuccess && changed) status = SecKeychainItemSetAccess(item, access);
    CFRelease(entries);
    CFRelease(access);
    return status;
}

static OSStatus create_item(const char *name, UInt32 name_length,
                            const char *user, UInt32 user_length,
                            const void *bytes, UInt32 length, CFStringRef label,
                            CFArrayRef trusted) {
    SecAccessRef access = NULL;
    OSStatus status = SecAccessCreate(label, trusted, &access);
    if (status == errSecSuccess) {
        SecKeychainAttribute attributes[] = {
            {kSecServiceItemAttr, name_length, (void *)name},
            {kSecAccountItemAttr, user_length, (void *)user},
        };
        SecKeychainAttributeList list = {2, attributes};
        status = SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass, &list,
                                                  length, bytes, NULL, access, NULL);
        CFRelease(access);
    }
    return status;
}

OSStatus agy_macos_keychain_write(const void *bytes, UInt32 length, const char *peer) {
    CFArrayRef trusted = NULL;
    OSStatus status = trusted_switch_apps(peer, &trusted);
    if (status != errSecSuccess) return status;

    SecKeychainItemRef item = NULL;
    status = SecKeychainFindGenericPassword(NULL, sizeof(service) - 1, service,
                                            sizeof(account) - 1, account,
                                            NULL, NULL, &item);
    if (status == errSecSuccess) {
        status = restrict_open_access(item, trusted);
        if (status == errSecSuccess) {
            status = SecKeychainItemModifyAttributesAndData(item, NULL, length, bytes);
        }
        CFRelease(item);
    } else if (status == errSecItemNotFound) {
        status = create_item(service, sizeof(service) - 1, account, sizeof(account) - 1,
                             bytes, length, CFSTR("Antigravity"), trusted);
    }
    CFRelease(trusted);
    return status;
}


// Store the managed account database key separately from the shared Antigravity login.
OSStatus agy_macos_account_key(const void *candidate, void *key, UInt32 length, const char *peer) {
    static const char name[] = "com.lbjlaq.antigravity-tools-lite.account-vault";
    static const char user[] = "account-encryption";
    UInt32 found_length = 0;
    void *found = NULL;
    OSStatus status = SecKeychainFindGenericPassword(NULL, sizeof(name) - 1, name,
                                                    sizeof(user) - 1, user,
                                                    &found_length, &found, NULL);
    if (status == errSecItemNotFound && candidate != NULL) {
        CFArrayRef trusted = NULL;
        status = trusted_switch_apps(peer, &trusted);
        if (status != errSecSuccess) return status;
        status = create_item(name, sizeof(name) - 1, user, sizeof(user) - 1,
                             candidate, length, CFSTR("AntiGravity Switch account key"), trusted);
        CFRelease(trusted);
        if (status == errSecSuccess) {
            memcpy(key, candidate, length);
            return errSecSuccess;
        }
        if (status == errSecDuplicateItem) {
            return agy_macos_account_key(NULL, key, length, peer);
        }
    }
    if (status == errSecSuccess) {
        if (found != NULL && found_length == length) {
            memcpy(key, found, length);
        } else {
            status = errSecDecode;
        }
    }
    if (found != NULL) {
        memset_s(found, found_length, 0, found_length);
        SecKeychainItemFreeContent(NULL, found);
    }
    return status;
}
