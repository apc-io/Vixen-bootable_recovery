/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rsa/rsa.h"
#include "rsa/x509.h"

#include "common.h"
#include "install.h"
#include "mincrypt/rsa.h"
#include "minui/minui.h"
#include "minzip/SysUtil.h"
#include "minzip/Zip.h"
#include "mtdutils/mounts.h"
#include "mtdutils/mtdutils.h"
#include "roots.h"
#include "verifier.h"
#include "ui.h"

extern RecoveryUI* ui;

#define ASSUMED_UPDATE_BINARY_NAME  "META-INF/com/google/android/update-binary"
#define PUBLIC_KEYS_FILE "/res/keys"

#define PUBLIC_KEY_ENV_NAME "wmt.rsa.pem"
#define PUBLIC_KEY_TMEPORARY "/tmp/rsa.public.key"



// Default allocation of progress bar segments to operations
static const int VERIFICATION_PROGRESS_TIME = 60;
static const float VERIFICATION_PROGRESS_FRACTION = 0.25;
static const float DEFAULT_FILES_PROGRESS_FRACTION = 0.4;
static const float DEFAULT_IMAGE_PROGRESS_FRACTION = 0.1;

// If the package contains an update binary, extract it and run it.
static int
try_update_binary(const char *path, ZipArchive *zip, int* wipe_cache) {
    const ZipEntry* binary_entry =
            mzFindZipEntry(zip, ASSUMED_UPDATE_BINARY_NAME);
    if (binary_entry == NULL) {
        mzCloseZipArchive(zip);
        return INSTALL_CORRUPT;
    }

    const char* binary = "/tmp/update_binary";
    unlink(binary);
    int fd = creat(binary, 0755);
    if (fd < 0) {
        mzCloseZipArchive(zip);
        LOGE("Can't make %s\n", binary);
        return INSTALL_ERROR;
    }
    bool ok = mzExtractZipEntryToFile(zip, binary_entry, fd);
    close(fd);
    mzCloseZipArchive(zip);

    if (!ok) {
        LOGE("Can't copy %s\n", ASSUMED_UPDATE_BINARY_NAME);
        return INSTALL_ERROR;
    }

    int pipefd[2];
    pipe(pipefd);

    // When executing the update binary contained in the package, the
    // arguments passed are:
    //
    //   - the version number for this interface
    //
    //   - an fd to which the program can write in order to update the
    //     progress bar.  The program can write single-line commands:
    //
    //        progress <frac> <secs>
    //            fill up the next <frac> part of of the progress bar
    //            over <secs> seconds.  If <secs> is zero, use
    //            set_progress commands to manually control the
    //            progress of this segment of the bar
    //
    //        set_progress <frac>
    //            <frac> should be between 0.0 and 1.0; sets the
    //            progress bar within the segment defined by the most
    //            recent progress command.
    //
    //        firmware <"hboot"|"radio"> <filename>
    //            arrange to install the contents of <filename> in the
    //            given partition on reboot.
    //
    //            (API v2: <filename> may start with "PACKAGE:" to
    //            indicate taking a file from the OTA package.)
    //
    //            (API v3: this command no longer exists.)
    //
    //        ui_print <string>
    //            display <string> on the screen.
    //
    //   - the name of the package zip file.
    //

    const char** args = (const char**)malloc(sizeof(char*) * 5);
    args[0] = binary;
    args[1] = EXPAND(RECOVERY_API_VERSION);   // defined in Android.mk
    char* temp = (char*)malloc(10);
    sprintf(temp, "%d", pipefd[1]);
    args[2] = temp;
    args[3] = (char*)path;
    args[4] = NULL;

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        execv(binary, (char* const*)args);
        fprintf(stdout, "E:Can't run %s (%s)\n", binary, strerror(errno));
        _exit(-1);
    }
    close(pipefd[1]);

    *wipe_cache = 0;

    char buffer[1024];
    FILE* from_child = fdopen(pipefd[0], "r");
    while (fgets(buffer, sizeof(buffer), from_child) != NULL) {
        char* command = strtok(buffer, " \n");
        if (command == NULL) {
            continue;
        } else if (strcmp(command, "progress") == 0) {
            char* fraction_s = strtok(NULL, " \n");
            char* seconds_s = strtok(NULL, " \n");

            float fraction = strtof(fraction_s, NULL);
            int seconds = strtol(seconds_s, NULL, 10);

            ui->ShowProgress(fraction * (1-VERIFICATION_PROGRESS_FRACTION), seconds);
        } else if (strcmp(command, "set_progress") == 0) {
            char* fraction_s = strtok(NULL, " \n");
            float fraction = strtof(fraction_s, NULL);
            ui->SetProgress(fraction);
        } else if (strcmp(command, "ui_print") == 0) {
            char* str = strtok(NULL, "\n");
            if (str) {
                ui->Print("%s", str);
            } else {
                ui->Print("\n");
            }
        } else if (strcmp(command, "wipe_cache") == 0) {
            *wipe_cache = 1;
        } else if (strcmp(command, "clear_display") == 0) {
            ui->SetBackground(RecoveryUI::NONE);
        } else {
            LOGE("unknown command [%s]\n", command);
        }
    }
    fclose(from_child);

    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        LOGE("Error in %s\n(Status %d)\n", path, WEXITSTATUS(status));
        return INSTALL_ERROR;
    }

    return INSTALL_SUCCESS;
}

// Reads a file containing one or more public keys as produced by
// DumpPublicKey:  this is an RSAPublicKey struct as it would appear
// as a C source literal, eg:
//
//  "{64,0xc926ad21,{1795090719,...,-695002876},{-857949815,...,1175080310}}"
//
// For key versions newer than the original 2048-bit e=3 keys
// supported by Android, the string is preceded by a version
// identifier, eg:
//
//  "v2 {64,0xc926ad21,{1795090719,...,-695002876},{-857949815,...,1175080310}}"
//
// (Note that the braces and commas in this example are actual
// characters the parser expects to find in the file; the ellipses
// indicate more numbers omitted from this example.)
//
// The file may contain multiple keys in this format, separated by
// commas.  The last key must not be followed by a comma.
//
// Returns NULL if the file failed to parse, or if it contain zero keys.
static RSAPublicKey*
load_keys(const char* filename, int* numKeys) {
    RSAPublicKey* out = NULL;
    *numKeys = 0;

    FILE* f = fopen(filename, "r");
    if (f == NULL) {
        LOGE("opening %s: %s\n", filename, strerror(errno));
        goto exit;
    }

    {
        int i;
        bool done = false;
        while (!done) {
            ++*numKeys;
            out = (RSAPublicKey*)realloc(out, *numKeys * sizeof(RSAPublicKey));
            RSAPublicKey* key = out + (*numKeys - 1);

            char start_char;
            if (fscanf(f, " %c", &start_char) != 1) goto exit;
            if (start_char == '{') {
                // a version 1 key has no version specifier.
                key->exponent = 3;
            } else if (start_char == 'v') {
                int version;
                if (fscanf(f, "%d {", &version) != 1) goto exit;
                if (version == 2) {
                    key->exponent = 65537;
                } else {
                    goto exit;
                }
            }

            if (fscanf(f, " %i , 0x%x , { %u",
                       &(key->len), &(key->n0inv), &(key->n[0])) != 3) {
                goto exit;
            }
            if (key->len != RSANUMWORDS) {
                LOGE("key length (%d) does not match expected size\n", key->len);
                goto exit;
            }
            for (i = 1; i < key->len; ++i) {
                if (fscanf(f, " , %u", &(key->n[i])) != 1) goto exit;
            }
            if (fscanf(f, " } , { %u", &(key->rr[0])) != 1) goto exit;
            for (i = 1; i < key->len; ++i) {
                if (fscanf(f, " , %u", &(key->rr[i])) != 1) goto exit;
            }
            fscanf(f, " } } ");

            // if the line ends in a comma, this file has more keys.
            switch (fgetc(f)) {
            case ',':
                // more keys to come.
                break;

            case EOF:
                done = true;
                break;

            default:
                LOGE("unexpected character between keys\n");
                goto exit;
            }

            LOGI("read key e=%d\n", key->exponent);
        }
    }

    fclose(f);
    return out;

exit:
    if (f) fclose(f);
    free(out);
    *numKeys = 0;
    return NULL;
}

extern "C" int wmt_getsyspara(const char	*varname,	char *varval,	int	*varlen);


//32 bit limb
uint32_t mpi_get_word(mpi * x){
    // 4 bytes
	if (mpi_size(x) > 4)
		return 0xffffffff;
	else
        return x->p[0];
	//return 0;   
}


/* Convert OpenSSL RSA public key to android pre-computed RSAPublicKey format */

int RSA_to_RSAPublicKey(rsa_context *rsa, RSAPublicKey *pkey)
{
    int ret = 1;
    unsigned int i;
    mpi r32;
    mpi rr;
    mpi r;
    mpi rem;
    mpi n;
    mpi n0inv;
    mpi divid;

    mpi_init(&r32);
    mpi_init(&rr);
    mpi_init(&r);
    mpi_init(&rem);
    mpi_init(&n);
    mpi_init(&n0inv);
    mpi_init(&divid);

    
    if(rsa->len != RSANUMBYTES){
       ret = 0;
       goto out;
    }

    mpi_set_bit(&r32, 32, 1);
    mpi_copy(&n, &rsa->N);
    mpi_set_bit(&r, RSANUMWORDS * 32, 1);

    mpi_lset(&rr, 1 );
    mpi_shift_l(&rr, rsa->N.n * 2 * 32);
    mpi_mod_mpi(&rr, &rr, &rsa->N);
    
    mpi_div_mpi(NULL, &rem ,&n, &r32);
    mpi_inv_mod(&n0inv, &rem, &r32);

    pkey->len = RSANUMWORDS;
    pkey->n0inv = 0 - mpi_get_word(&n0inv);

    for (i = 0; i < RSANUMWORDS; i++) {
        mpi_div_mpi(&divid, &rem, &rr, &r32);
        pkey->rr[i] = mpi_get_word(&rem);
        mpi_copy(&rr, &divid);
        mpi_div_mpi(&divid, &rem, &n, &r32);
        pkey->n[i] = mpi_get_word(&rem);
        mpi_copy(&n, &divid);
    }
    pkey->exponent = mpi_get_word(&rsa->E);
        
out:
    mpi_free(&r32);
    mpi_free(&rr);
    mpi_free(&r);
    mpi_free(&rem);
    mpi_free(&n);
    mpi_free(&n0inv);
    mpi_free(&divid);
    
    return ret;
}

static void dumpKey(const char *dumpFile, RSAPublicKey *pkey){
   FILE * file = fopen(dumpFile, "w+");
   if(file != NULL){
       int version=1;
       if(pkey->exponent == 3){
           version = 1;
       }else if(pkey->exponent == 65537){
           version = 2;
       }else{
          LOGE("unknown public key exponent\n");
          goto END;     
       }

       if(pkey->len != RSANUMWORDS){
          LOGE("unknown key length\n");
          goto END;
       }

       if(version > 1){
           fprintf(file, "v%d", pkey->exponent);
       }

       fprintf(file, "{%d,", RSANUMWORDS);
       fprintf(file, "0x%x,{", pkey->n0inv);

       for(int i = 0; i < RSANUMWORDS; i++){
           fprintf(file, "%u", pkey->n[i]);
           if(i < RSANUMWORDS - 1)
             fprintf(file, ",");
       }

       fprintf(file, "},{");

       for(int i = 0; i < RSANUMWORDS; i++){
           fprintf(file, "%u", pkey->rr[i]);
           if(i < RSANUMWORDS - 1)
             fprintf(file, ",");           
       }

       fprintf(file, "}}\n");
END:       
       fclose(file);
   }
}

static RSAPublicKey* load_key_from_env(int *numKeys){

     char envval[512]={0};
     int  envvallen=sizeof(envval);
     RSAPublicKey *pubkey = NULL;
     rsa_context rsa;

     *numKeys = 0;
     if(wmt_getsyspara(PUBLIC_KEY_ENV_NAME, envval, &envvallen)){
         //fail to get public key env
         LOGE("fail to load public key!\n");
         return NULL;
     }
    
     rsa_init(&rsa, RSA_PKCS_V15, 0);
     if(x509parse_public_key(&rsa, (unsigned char*)envval, envvallen) != 0){
        rsa_free(&rsa);
        return NULL;
     }

     pubkey = (RSAPublicKey *)malloc(sizeof(RSAPublicKey));

     RSA_to_RSAPublicKey(&rsa, pubkey);

     //for debug
     dumpKey(PUBLIC_KEY_TMEPORARY, pubkey);
     
     rsa_free(&rsa);
     *numKeys = 1;
end:

     return pubkey;

}

static int
really_install_package(const char *path, int* wipe_cache)
{
    ui->SetBackground(RecoveryUI::INSTALLING_UPDATE);
    ui->Print("Finding update package...\n");
    ui->SetProgressType(RecoveryUI::INDETERMINATE);
    LOGI("Update location: %s\n", path);

    if (ensure_path_mounted(path) != 0) {
        LOGE("Can't mount %s\n", path);
        return INSTALL_CORRUPT;
    }

    ui->Print("Opening update package...\n");

    int numKeys;
    LOGI("trying to load keys\n");
    RSAPublicKey* loadedKeys = load_key_from_env(&numKeys);
    if(loadedKeys == NULL){
       loadedKeys = load_keys(PUBLIC_KEYS_FILE, &numKeys);
        if (loadedKeys == NULL) {
            LOGE("Failed to load keys\n");
            return INSTALL_CORRUPT;
        }
        LOGI("%d key(s) loaded from %s\n", numKeys, PUBLIC_KEYS_FILE);
    }else{
        LOGI("1 key loaded form env\n");
    }

    // Give verification half the progress bar...
    ui->Print("Verifying update package...\n");
    ui->SetProgressType(RecoveryUI::DETERMINATE);
    ui->ShowProgress(VERIFICATION_PROGRESS_FRACTION, VERIFICATION_PROGRESS_TIME);

    int err;
    err = verify_file(path, loadedKeys, numKeys);
    free(loadedKeys);
    LOGI("verify_file returned %d\n", err);
    if (err != VERIFY_SUCCESS) {
        LOGE("signature verification failed\n");
        return INSTALL_CORRUPT;
    }

    /* Try to open the package.
     */
    ZipArchive zip;
    err = mzOpenZipArchive(path, &zip);
    if (err != 0) {
        LOGE("Can't open %s\n(%s)\n", path, err != -1 ? strerror(err) : "bad");
        return INSTALL_CORRUPT;
    }

    /* Verify and install the contents of the package.
     */
    ui->Print("Installing update...\n");
    return try_update_binary(path, &zip, wipe_cache);
}

int
install_package(const char* path, int* wipe_cache, const char* install_file)
{
    FILE* install_log = fopen_path(install_file, "w");
    if (install_log) {
        fputs(path, install_log);
        fputc('\n', install_log);
    } else {
        LOGE("failed to open last_install: %s\n", strerror(errno));
    }
    int result = really_install_package(path, wipe_cache);
    if (install_log) {
        fputc(result == INSTALL_SUCCESS ? '1' : '0', install_log);
        fputc('\n', install_log);
        fclose(install_log);
    }
    return result;
}
