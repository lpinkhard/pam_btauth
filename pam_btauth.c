#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <security/pam_modules.h>
#include <openssl/md5.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

/**
 * Reads a stored hash from /etc/btauth
 */
int _bt_read_hash(const char *username, unsigned char *hash) {
        int dirlen, usrlen, result;
        char *path = NULL;
        FILE *file = NULL;
        const char directory[] = "/etc/btauth/";

        dirlen = strlen(directory);
        usrlen = strlen(username);

        // Build the path to the file
        path = malloc(dirlen + usrlen);
        memcpy(path, directory, dirlen);
        memcpy(path + dirlen, username, usrlen + 1);

        // Open the file
        file = fopen(path, "r");
        if (!file) {
                free(path);
                return PAM_AUTHINFO_UNAVAIL;        // Cannot access file
        }

        // Read the hash
        result = fread(hash, MD5_DIGEST_LENGTH * 2, 1, file);

        // Close the file
        fclose(file);
        free(path);

        if (result != 1) {
                return PAM_AUTHINFO_UNAVAIL;        // Stored hash is corrupt
        }

        return PAM_SUCCESS;
}

/**
 * Checks whether a device is in range based on hash of MAC address
 */
int _bt_find_hash(const unsigned char *hash) {
        int i, j, device, results;
        inquiry_info *ii = NULL;
        unsigned char bt_addr[19] = { 0 };
        unsigned char hash_result[MD5_DIGEST_LENGTH];
        unsigned char hash_str[MD5_DIGEST_LENGTH * 2];

        device = hci_get_route(NULL);   // Find the Bluetooth adapter

        if (device < 0) {
                return PAM_AUTHINFO_UNAVAIL;    // No Bluetooth access
        }

        // Allocate memory for scan results
        ii = (inquiry_info *) malloc(sizeof(inquiry_info) * 255);

        // Find devices
        results = hci_inquiry(device, 10, 255, NULL, &ii, IREQ_CACHE_FLUSH);

        if (results < 0) {
                free(ii);
                return PAM_AUTHINFO_UNAVAIL;    // Scan problem
        }

        // Iterate devices
        for (i = 0; i < results; i++) {
                ba2str(&(ii + i)->bdaddr, bt_addr);

                // Compute hash
                MD5((unsigned char *) bt_addr, 17, hash_result);
                for (j = 0; j < MD5_DIGEST_LENGTH; j++) {
                        sprintf(&hash_str[j * 2], "%02x",
                                (unsigned int) hash_result[j]);
                }

                // Compare
                if (strncmp(hash_str, hash, MD5_DIGEST_LENGTH * 2) == 0) {
                        free(ii);
                        return PAM_SUCCESS;     // Found the device
                }
        }

        // No match, authentication failed
        free(ii);
        return PAM_AUTH_ERR;
}

/**
 * Authenticates a user's device
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, 
                                   const char **argv) {
        const char *username;
        unsigned char device[19] = { 0 };
        unsigned char hash[MD5_DIGEST_LENGTH * 2];
        int retval;

        // Retrieve the username
        if ((retval = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) {
                return retval;
        }       

        // Retrieve the hash
        if ((retval = _bt_read_hash(username, hash)) != PAM_SUCCESS) {
                return retval;
        }
 
        return _bt_find_hash(hash);
}

/**
 * Set credentials after login, does nothing
 */
PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh, int flags, int argc,
			       const char **argv) {
        // Nothing to do here
        return PAM_SUCCESS;
}
